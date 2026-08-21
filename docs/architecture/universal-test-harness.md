# Universal test harness

DevCoordinator provides one server-wide asynchronous test service for current
repository work. Test data is disposable; repository source, project databases,
credentials, routes, users, grants, and repository registrations are not.

## Boundaries

- The public edge and Console authenticate remote users.
- The root authority owns host mutation and immutable repository identity.
- `devcoordinator-testd` owns current test scheduling and its private SQLite
  store.
- The snapshot/runtime helper validates source and launches exact transient
  non-root systemd units.
- Repository code never runs as root or inside the Console, edge, or authority
  processes.
- Unix identity is attribution and execution routing on this single-developer
  host, not a local authorization boundary.

Credentials use the separate root-owned credential registry and transient
systemd `LoadCredential=` files. Manifests and ordinary launch descriptors
contain only opaque binding names, never secret values or secret paths.

## Disposable state

The Test Store contains only data needed to execute and follow current work:
repository setup snapshots, plans internal to a run, active runs and attempts,
bounded failures, artifact metadata, and the mutation records required for
idempotent current operations.

It has no authority-side mirror, fleet rollups, daily/hourly statistics,
case-detail history, evidence attestations, evidence consumption, cross-run
reuse decision, retry chain, or completed-run public history. A testd
replacement stops exact transient runtimes, cancels every unfinished run,
discards its private result spool, and starts cleanly. It never recovers an
attempt lease or replays result chunks from a prior daemon.

Software-owned delivery may replace the Test Store with an empty current-schema
store while testd is stopped. No test rows are backed up, exported, imported, or
migrated.

## Run lifecycle

A run performs these internal steps:

1. Resolve the exact configured repository and selected original or temporary
   source.
2. Validate the repository manifest without executing repository content.
3. Select current targets and dependency order, clamp execution and launch
   deadlines, and register the plan inside testd.
4. Return a run ID after idempotent submission.
5. Launch each ready target as the recorded non-root execution user in a
   transient unit with private scratch space, explicit TTL, clean environment,
   cgroup accounting, and `kill_after_run=true`.
6. Ingest bounded structured results, failures, and copied artifact metadata.
7. Expose current status until the disposable state is reset.

Scheduling uses a fixed conservative memory estimate. Historical memory
learning and history-derived sharding are absent. CPU and memory measurements
remain observational evidence for the current attempt.

Cancellation, timeout, test failure, infrastructure failure, incomplete
reporting, and success stay distinct. A manual retry is a new run.

## Public agent API

The stable agent and MCP surface has four actions:

- `run`: validate, plan internally, submit, and return the run handle;
- `follow`: read bounded current status and terminal summary;
- `cancel`: request cancellation for the exact repository/run identity;
- `artifact`: resolve one exact bounded artifact.

Planning, submission, queue inspection, statistics, fleet projections, retry,
policy/evidence consumption, raw cases, and event history are not public agent
actions. Every mutation uses a canonical operation UUID, and every continuation
carries the repository identity returned by `run`.

A direct repository-native test remains eligible only when its selector is
proved before launch to collect at most 20 cases, a runner deadline bounds it to
at most 10 seconds, and it touches no shared runtime. Larger or unknown work
uses the asynchronous service.

## Repository manifest

The current manifest parser remains strict and fail closed. It validates typed
no-shell argv, contained working directories, dependencies, timeouts, network
policy, fixtures, opaque credential bindings, artifacts, and bounded literal
environment. It rejects shell executables, path escapes, undeclared fixtures or
credentials, unsafe secret-like environment names, graph cycles, and unknown
fields.

The intent, input-selection, shard, retry, and evidence-policy fields are still
present in schema 3 as execution/provenance controls. Removing those controls is
a separate security-posture decision; they are not used to retain completed test
history. Evidence reuse and retry operations have already been removed from the
store and public API.

## Console

The Tests destination lists current configured repositories first. Selecting a
repository opens the Run tests dialog in the current viewport. The Console has
no fleet heatmap, historical statistics, trends, retained test cache, or
repository-history detail tabs.

After submission it opens a current-runs sheet. That sheet can follow status,
cancel active work, and disclose bounded failures and artifact metadata. An
ordinary scheduler wait stays inside the current run; it never becomes a global
Console banner.

## Release and readiness

Production runs from one root-owned content-addressed release. The
repository-owned delivery workflow performs source checks, packaging, current
release activation, health verification, rollback to the immediately preceding
current-format release, and installed browser/client acceptance. The installed
DevCoordinator test or installation clients are never used to validate this
repository itself.

Activation and authority-readiness checks remain fail closed. They verify exact
release identity, service topology, sockets, authority generation, Test Store
schema, credential preflight, public/API health, and rollback evidence. Process
liveness alone is not readiness.

## Verification

Completion requires:

- manifest and launch-boundary negative tests;
- dependency, timeout, cancellation, restart-cleanup, and artifact tests;
- stable run/follow/cancel/artifact contract tests;
- current repository and run journeys at wide and narrow viewports;
- source validation across every repository partition;
- immutable package verification;
- current-format activation, health, and rollback checks;
- installed Console/browser and agent-client acceptance.

Raw logs stay in delivery artifacts. The project completion ledger contains only
active unresolved work.
