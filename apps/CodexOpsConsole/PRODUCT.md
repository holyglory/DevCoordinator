# Codex Ops Console Product And Journey Contract

## Confirmation Status

The user approved the implementation plan containing the journeys and safety
constraints below on 2026-07-10, then explicitly approved the ImageGen design
review board on the same date. Consequential SwiftUI changes must follow that
confirmed hierarchy and safety-flow direction.

## App Idea

- Product promise: give a local developer/operator one truthful place to
  inspect and control coordinator-managed development servers, Docker
  resources, port leases, and PostgreSQL protection across Codex, Claude, and
  Parall runtime homes.
- Primary users: local developers and technical operators who understand the
  projects they run but should not need to reason about coordinator state-file
  locations or raw command payloads during normal work.
- Primary value: identify what needs attention, act through the owning
  coordinator, and see the real result without invented status or hidden
  cross-home assumptions.
- Non-goals: remote infrastructure management, production fleet orchestration,
  synthetic monitoring data, or replacement of Docker/PostgreSQL administration
  tools outside coordinator-owned local workflows.
- Main context: macOS desktop and menu bar, keyboard and pointer input, with
  mistakes capable of stopping local work or damaging local database data.

## User Contexts

| User | Expertise | Frequency | Environment | Urgency | Mistake cost |
| --- | --- | --- | --- | --- | --- |
| Local developer | Technical | Frequent | Several local projects and agent runtimes | Normal to high during failures | Lost work time or wrong service action |
| Local operator | Advanced | Occasional | Docker and PostgreSQL development stacks | High during recovery | Data loss or prolonged outage |

## Journey Inventory

| Journey | Status | Frequency | Importance | Risk if broken | Entry | Success |
| --- | --- | --- | --- | --- | --- | --- |
| Survey all sources | confirmed | Frequent | High | An unhealthy or missing source is overlooked | Main window/menu bar | User knows whether state is complete and what needs attention |
| Act on one resource | confirmed | Frequent | High | Wrong coordinator or resource is changed | Resource row/detail | Correct owning coordinator completes the requested action |
| Inspect logs and command results | confirmed | Frequent during failures | High | User cannot diagnose failure or trusts a silent action | Row/detail action | Real output, source, time, and failure state remain visible |
| Lease and use a port | confirmed | Occasional | High | Wrong or hidden port causes collision or failed startup | Lease action | Actual leased port and expiry are visible and usable |
| Protect or restore a database | confirmed | Occasional | Critical | Wrong target or weak verification causes data loss | Database surface | Exact database is backed up, verified, and safely restored |
| Stop selected running resources | confirmed | Rare/destructive | Critical | Unintended services are stopped | Explicit bulk action | Only confirmed selections are stopped with per-item results |

## Journey Decision Model

### Survey All Sources

- Primary user goal: understand whether the combined local runtime state can be
  trusted and what needs attention.
- Primary decision: is the combined inventory complete and healthy, and which
  source or resource needs attention?
- Required facts: configured source identity, source freshness/completeness,
  explicit unhealthy/degraded resources, running/stopped state, current action
  progress, and measured load warnings.
- Warning conditions: unreachable or stale source, partial inventory, unhealthy
  process/container, failed action, unavailable Docker, and failed backup
  verification.
- Frequent actions: refresh, open a resource, inspect the affected source.
- Secondary details: exact coordinator/state paths and raw diagnostics.
- Unresolved assumptions: none in the approved primary hierarchy; native
  breakpoint behavior still requires Build macOS Apps verification.
- Success: the same health reducer drives main-window and menu-bar summaries.

### Act On One Resource

- Primary user goal: safely control or inspect one exact resource.
- Primary decision: start, stop, restart, or inspect this exact resource.
- Required facts: resource type, project, source label, current state, action
  availability, and any in-progress operation.
- Warning conditions: stale ownership, ambiguous project, duplicate operation,
  incompatible state, or partial source failure.
- Frequent actions: row activation and one resource-scoped action.
- Secondary details: structured command, environment provenance, operation id.
- Unresolved assumptions: none in the action ownership model.
- Success: command runs through the resource's owning coordinator and returns a
  typed result.

### Inspect Logs And Command Results

- Primary user goal: understand the real outcome of an operation or failure.
- Primary decision: did the operation succeed, and what evidence explains a
  failure?
- Required facts: resource/source, command type, start/end time, exit state,
  stdout/stderr or log tail, timeout/cancellation, and retained error.
- Warning conditions: truncated output, unreadable log, stale output, or output
  from another source.
- Frequent actions: refresh and copy output.
- Secondary details: sanitized command/environment and coordinator operation id.
- Unresolved assumptions: none in the retained-result composition.
- Success: inventory refresh cannot erase the result being inspected.

### Lease And Use A Port

- Primary user goal: obtain and use a collision-free port for the selected project.
- Primary decision: use the assigned port or cancel/release it.
- Required facts: actual port, project, source, lease id, expiry, and conflict
  state.
- Warning conditions: expired lease, project/source ambiguity, or failure to
  bind/start.
- Frequent actions: copy port and start a server using that lease.
- Unresolved assumptions: none in the returned-value contract.
- Success: UI reports the returned port, never a derived id fragment.

### Protect Or Restore A Database

- Primary user goal: protect or recover one exact local PostgreSQL database without damaging another target.
- Primary decision: which exact database needs protection, and is the selected
  backup strong and compatible enough to restore?
- Required facts: coordinator origin, container identity, database name, real
  size when available, destination, backup creation time, checksum state,
  restore-test state, compatibility, and safety-backup result.
- Warning conditions: no backup, checksum failure, no strong restore test,
  mismatched source/target, stale/unavailable discovery, cleanup failure, or
  unsafe cluster topology.
- Frequent actions: create and verify backup.
- Destructive action: restore, requiring exact target confirmation and verified
  pre-restore protection.
- Unresolved assumptions: none in the protection/evidence hierarchy; backend
  safety remains fixed by contract.
- Success: data verification passes and rollback evidence remains available.

### Stop Selected Running Resources

- Primary user goal: stop a deliberate set of local resources and understand every result.
- Primary decision: which running resources should stop now?
- Required facts: explicit selection, source, project, resource type/state,
  selected count, and consequence.
- Warning conditions: stale state, dependency impact, already-running action,
  or mixed-source selection.
- Destructive action: confirmation after selection; opening the sheet has no
  side effect.
- Unresolved assumptions: none in the explicit selection/confirmation layout.
- Success: only checked resources stop and every result remains visible.

## Information Relevance Inventory

| Information/control | Relevance | Default access | Rationale |
| --- | --- | --- | --- |
| Combined health and incomplete-source warning | critical-always | Inline summary | Determines whether the inventory can be trusted |
| Resource state, name, project, and compact source label | primary-frequent | Row/table | Supports normal selection and action |
| Resource-scoped start/stop/restart/log action | primary-frequent | Affected row/detail | Keeps action ownership explicit |
| Actual log/command result | conditional-critical | Result sheet/detail | Needed after failure or explicit inspection |
| Actual leased port and expiry | conditional-critical | Lease result | Required to use the lease |
| Backup verification strength and exact target | conditional-critical | Database row/detail | Prevents false protection claims |
| Exact coordinator home/state path | secondary-occasional | Sources/details surface | Useful for repair, noisy in normal rows |
| Raw command/environment and operation journal | debug/expert-only | Explicit diagnostics disclosure | Needed for diagnosis, not routine decisions |
| Bulk stop | rare/destructive | Explicit secondary action | Must not dominate or share implicit row selection |
| Source configuration and refresh policy | rare/configuration | Settings/Sources surface | Changed infrequently |

## Interaction And Metadata Model

| Surface | Element | Interaction target | Feedback/detail access | Lifecycle/accessibility |
| --- | --- | --- | --- | --- |
| Resource table/tree | Resource activation | Non-action row region or native selection | Focus/hover/selected state opens details | Keyboard arrows/Return and accessible selected value |
| Resource table/tree | Start/stop/restart/log | Control on the affected resource only | Disabled/progress/result states | Separate from row activation; accessible action name |
| Health summary | Status signal | Compact summary control when details exist | Opens source/resource breakdown | Not color-only; consistent main/menu result |
| Log/result viewer | Copy/refresh | Explicit buttons | Copy confirmation and retained output | Escape/outside close where applicable; focus remains reachable |
| Lease result | Port | Selectable value plus Copy Port | Start Using Port is explicit | Persists until dismissed or lease is released/expired |
| Backup status | Verification label | Row/detail signal | Opens manifest and verification evidence | Labels distinguish checksum from restore test |
| Bulk stop | Selection checkboxes | Checkbox only for destructive selection | Selected count and confirmation | Cancel/Escape safe; no implicit selection |
| Sources/settings | Source row | Native row/button | Shows freshness, error, and exact path details | Secondary surface; closes normally and preserves changes |

Passive timestamps, source labels, routing metadata, and operation ids are not
selectable message content unless copying them is a documented action. Status
summaries show one truthful primary state; error counts, durations, and raw
execution detail move to the result/detail surface.

## Required States

- Initial loading and per-source loading.
- Complete empty inventory.
- Partial inventory with retained successful sources.
- Stale/unreachable source.
- Running, intentionally stopped, starting, unhealthy, and unknown resource.
- Action queued/running/succeeded/failed/timed out/cancelled.
- Empty logs, retained logs, stderr-only failure, and unavailable log.
- Lease created, expired, released, and failed.
- Database discovery unavailable, no backup, checksum verified, restore tested,
  verification failed, restore running, restore succeeded, and rollback needed.
- Bulk selection empty, selected, confirmation, partial success, and complete
  success.

## Feature Inventory

- Multi-home coordinator inventory with partial-source truth.
- Resource-scoped start, stop, restart, logs, and project actions.
- Port leasing with returned-value use and release.
- Docker inventory, lifecycle, logs, and measured telemetry.
- PostgreSQL database discovery, backup, checksum verification, strong restore
  testing, safe restore, and rollback evidence.
- Explicit bulk selection and bounded per-item execution.
- Menu-bar status and actions consistent with the main window.
- Coordinator source configuration and diagnostics.

## UI Element Inventory

- Source-aware navigation tree and resource tables.
- Compact health summary and partial-source warning.
- Resource action controls and typed result/log viewer.
- Lease form and persistent lease result.
- Database protection status, backup detail, and restore confirmation.
- Bulk selection sheet with checkboxes, selected count, confirmation, progress,
  and per-item results.
- Secondary Coordinator Sources/Settings surface.
- Loading, empty, stale, unavailable, error, and recovery states.

## Implementation Expectations

- Every visible action maps to a coordinator or PostgreSQL handler with
  validated input, source provenance, bounded execution, retained output, and
  explicit failure state.
- Models preserve source identity through aggregation, selection, commands,
  persistence/configuration, and result presentation.
- Configuration persists typed source and refresh settings; raw serialized
  payloads are never exposed as editable UI.
- Permission, missing dependency, unavailable integration, and stale-state
  failures remain truthful and recoverable.

## UI Handoff Constraints

- The primary survey and resource decision must fit at the supported minimum
  window without unintended clipping, overlap, or hidden controls.
- Source provenance stays compact near the owned object; private paths and raw
  diagnostics require explicit detail access.
- Logs, backup evidence, and destructive confirmation use progressive
  disclosure rather than displacing the primary inventory.
- Exact visual grouping follows the user-approved design review board: compact
  source health in the header, primary inventory dominant, retained results in
  the inspector, and lease/database/bulk safety flows as focused disclosures.
- Native screenshot and geometry evidence must cover wide, minimum-window,
  menu-bar, partial-source, failure, lease, backup, restore-confirmation, and
  bulk-selection states.

## Test Expectations

- Two isolated coordinator homes with colliding resource names remain distinct
  and route actions correctly.
- Real coordinator, Docker, and disposable PostgreSQL journeys verify action
  results end to end.
- XCTest covers source-aware identity, aggregation, health, parsing, backup
  matching, and bulk selection.
- XCUI covers keyboard navigation, result viewers, source failure, leases,
  database protection, destructive confirmation, and menu-bar parity.
- VoiceOver exposes role, name, state/value, and action without depending on
  tooltip text or color.
- Test-only fixtures are isolated from runtime inventory and are never presented
  as product data.
