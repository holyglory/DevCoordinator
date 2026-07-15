# Repository catalog and coordinator state-store architecture

Status: Owner-approved on 2026-07-14; implementation complete, release
acceptance evidence pending

This document records both the bounded Board repair implemented for the
2026-07-13 repository-duplication incident and the owner-approved target model
for DevCoordinator storage. On 2026-07-14 the owner approved the SQLite store, same-UID
importer, broker for shared cross-user resources, v2 inventory graph, single
host-resource observer, and reversible repository-decommission semantics after
receiving the alternatives, costs, risks, and recommendation recorded in
`DecisionHistory.md`. The implementation now exists; the acceptance matrix in
this document remains the release gate and results must not be overstated until
the final normal/optimized, native, cross-UID, packaging, and launch runs pass.

## Decision

The product invariant is:

> One canonical local Git worktree root is one repository and therefore one
> project in the Board.

Coordinator source homes, Codex application instances, server records, Docker
observations, display names, and derived name keys are not project identities.
They may contribute resources or observations to a repository, but they must
never create another project for the same canonical worktree root.

The source of truth is one private, normalized SQLite database
in WAL mode per effective POSIX account. The coordinator owns repository
identity, resource membership, observation, aggregation, and control routing.
The Board consumes one account-store projection and no longer polls imported
legacy homes as independent authorities. Its production Swift models decode
the normalized v2 graph directly. A bounded v1 compatibility projection is
generated from the same v2 query only for older external clients; it cannot
create identities, observe the host, or mutate state independently.

## Confirmed current design

### Persisted state

The coordinator resolves the effective POSIX account home and opens
`coordinator.sqlite3` through `AccountStore`. SQLite WAL, foreign keys, private
ownership/mode checks, schema versioning, distinct state/observation revisions,
and invariant queries are authoritative. Canonical repositories, installations,
definitions, source records, host resources, memberships, control bindings,
observations, policies, leases, assignments, operations, events, telemetry,
backup/import evidence, conflicts, and unassigned resources have separate
tables and lifecycles.

Legacy `state.json` homes are migration inputs only. The first normalized
bootstrap captures private checksummed evidence, imports same-UID homes in one
transaction, and leaves the source files untouched. Exact duplicates collapse;
contradictory immutable Docker claims become one conflicting physical resource
with no active membership or arbitrary controller. A later source write is a
reported conflict, not a competing live authority. The JSON backend remains
only under the explicit `legacy-json-test-only` name for deterministic fixtures.

The old callback-shaped dictionary mutation adapter is not a production
backend. Historical deterministic fixtures may opt into the explicitly named
`legacy-json-test-only` backend, but the default CLI and API lifecycle paths
commit through typed normalized services. A default-runtime guard makes an
accidental `locked_state` call fail instead of materializing and rewriting a
legacy projection.

### Reproduced pre-repair Board source and merge model (historical)

`FileSystemCoordinatorOriginDiscovery` in
[`Models.swift`](../../apps/DevOpsBoard/Sources/DevOpsBoard/Models.swift)
automatically discovers the account Codex and Claude homes and every Parall
application's `.codex/agent-coordinator` directory. The Board invokes inventory
for each discovered home.

Before this repair, `OpsStore.mergeInventories` deduplicated observed Docker containers by physical
container ID, but `mergeProjectUsage` groups rows by
`(coordinator origin, usage_key)`. `makeProjectGroups` and `projectGroupID` in
[`Views.swift`](../../apps/DevOpsBoard/Sources/DevOpsBoard/Views.swift) retain
that source in the project identity. Consequently:

- one repository reported by three homes becomes three project nodes;
- one physical Docker container is retained once, so only one of those nodes
  receives it and the others can become empty shells;
- host-global Docker usage is shown once per source contribution; and
- a `name:*` row with no repository path is rendered as a project.

The pre-repair `assertMultiSourceProjectMembership` fixture in
[`SplitSizingTest.swift`](../../apps/DevOpsBoard/Tools/SplitSizingTest.swift)
protects this incorrect UI invariant by expecting two project groups for the
same worktree path merely because two sources reuse the same native server ID.
Native-ID collision safety is necessary, but it belongs in resource identity,
not project identity.

This implementation contradicts the 2026-07-07 decision recorded in
[`DecisionHistory.md`](../../DecisionHistory.md), which says multi-home
inventories are bucketed by `usage_key` and their membership is unioned.

### Implemented Board repository catalog

`RepositoryCatalog.swift` now builds one in-memory aggregate per canonical
worktree path from the original source inventories before their presentation
rows are flattened. Repository identity excludes coordinator origin; server
and Docker resource identities retain origin and native identity for control
routing. Physical Docker observations are reconciled by immutable container ID
before repository assignment, and process metrics are reconciled by PID.

`OpsStore` publishes the catalog and its `ProjectGroup` projection coherently.
Path-backed repositories appear once in the sidebar and Project Load. Name-only
or unresolved evidence appears in one non-actionable **Unassigned Resources**
group. A whole-repository action is enabled only when one source proves control
coverage for every logical server and attributed Docker resource. Conflicting
active endpoints or cross-repository ownership claims remain visible, mark
health non-nominal, and block mutation. The launch-readiness marker compares
canonical repository count with rendered repository-group count so the
production-shaped one-repository/three-row regression fails the delivery gate.

The catalog originated as a compatibility repair over independent snapshots.
After the normalized cutover, it receives one account-store projection and acts
as a defensive presentation layer. Imported legacy homes are not Board sources;
host-global observation is coalesced before inventory is queried.

## Reproduced production-shaped evidence

The following evidence was read from the three current private stores and from
their real coordinator inventory on 2026-07-13. Full private paths are replaced
by a visible leaf plus the first ten characters of a SHA-256 path digest.
Volatile CPU samples are intentionally omitted.

### Inventory contributions

| Source | Presented servers | Docker containers | PostgreSQL projections | `project_usage` rows |
| --- | ---: | ---: | ---: | ---: |
| Account source | 16 | 15 | 7 | 11 |
| Legacy Codex TT source | 3 | 15 | 7 | 9 |
| Legacy ChatGPT TT source | 0 | 15 | 7 | 9 |

The three sources therefore return 29 project-usage rows for only 13 distinct
usage keys. Ten keys are path-backed. Nine of those paths currently exist as
Git worktree roots; one historical `wt-before#39d28becd1` path no longer
exists. The remaining three keys are name-backed, unassigned resources rather
than repositories.

All three sources returned the same `Nevod#71c009fd17` path-backed row with the
same two physical containers and approximately 3.73 GB of Docker memory. The
Board therefore showed Nevod three times in Project Load. All three also
returned `name:aicursegmailcheck` with `project=null`; the Board showed three
project nodes even though no repository identity exists for that resource.

### Persisted state and amplification

| Source | State bytes | Revision | Raw server records | Assignments | Docker history series | Docker samples |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Account source | 8,211,325 | 50,615 | 21 | 13 | 120 | 9,001 |
| Legacy Codex TT source | 1,550,427 | 50,530 | 4 | 8 | 46 | 1,350 |
| Legacy ChatGPT TT source | 496,675 | 51,779 | 0 | 0 | 8 | 548 |

The empty legacy ChatGPT TT server store still contains telemetry and has a
higher revision than either populated store. The Board's inventory polling is
itself keeping obsolete state homes active.

`locked_state` rewrites and fsyncs the complete pretty-printed JSON whenever
the lock is used. One inventory reserves observation generations and later
commits observations, causing two complete state writes. For an all-projects
Board refresh, `loadOriginInventory` also issues a second no-Docker inventory
to scan backup directories. At the captured sizes, the three sources therefore
rewrite approximately 39.13 MiB of JSON payload per Board refresh:

```text
4 writes per source x (8,211,325 + 1,550,427 + 496,675 bytes)
  = 41,033,708 bytes
  = approximately 39.13 MiB
```

That estimate excludes temporary-file overhead, filesystem metadata, fsync
cost, serialized command output, and reads. Docker `ps`, `stats`, and `inspect`
also run once per source even though all three sources observe the same engine.

Telemetry retention is bounded per history series but not across retired
series. `merge_docker_stats_history` never deletes a series when a container is
removed or recreated. The account store therefore retains 120 series for 15
current containers.

### Existing identity conflicts

The raw stores contain evidence that winner selection is masking schema
violations:

- the account store has five stopped records for one XFoilFOAM `api` server and
  two for one XFoilFOAM `web` server;
- the legacy Codex TT store has two stopped records for one Nevod `web` server;
- five benzovozka assignments are duplicated exactly across account and legacy
  Codex TT stores; and
- stale durable assignments in different stores claim ports 3000, 3002, and
  3003 for different repositories.

All observed server records were stopped at capture time, so this evidence does
not establish a current listener collision. It does prove that a migration
cannot concatenate stores or silently pick a winner.

## Implemented domain model

Identity, observation, aggregation, and control authority must be separate.

### RepositoryIdentity

`RepositoryIdentity` answers only: “which local Git worktree is this?”

```text
RepositoryIdentity = (host_id, repo_id, canonical_worktree_root)
UNIQUE(host_id, canonical_worktree_root)
```

- `repo_id` is a durable database-generated identifier used by foreign keys.
- `canonical_worktree_root` is a strict real path whose root contains a `.git`
  directory or worktree `.git` file.
- A nested working directory and a symlink alias resolve to the same root.
- Separate Git worktrees have separate roots and are separate repositories.
- Two clones with the same basename or remote at different paths are separate
  repositories.
- A relocation transaction may preserve `repo_id` while atomically replacing
  its unique root and recording the old path as an alias.
- A missing or deleted path becomes a `missing` repository tombstone. It does
  not remain in the active project list, but its assignments and history remain
  inspectable and recoverable.
- A path with no Git marker is not an active repository. It may be rejected at
  registration or retained as an unassigned workspace diagnostic, but it must
  not create a project.

The catalog adds repositories only through a real coordinator registration,
an explicit operator action, a validated server working directory, or explicit
Docker Compose/sidecar provenance. It does not scan the user's home and invent
projects from arbitrary directories.

### SourceResourceIdentity

`SourceResourceIdentity` preserves namespace and control provenance:

```text
SourceResourceIdentity = (source_id, resource_kind, native_id)
```

It distinguishes two sources that both call a server `web` or reuse the same
UUID. It is the lookup key for imported legacy records and source-specific
commands. It never participates in `RepositoryIdentity`.

### HostResourceIdentity

`HostResourceIdentity` identifies the physical object being observed:

| Resource | Host identity |
| --- | --- |
| Docker container | `(docker_engine_id, immutable_full_container_id)` |
| Process | `(host_id, pid, process_start_time)` |
| Listener | `(host_id, protocol, normalized address, port, owning process identity)` |
| Database | `(container host identity, database name)` |

This is the deduplication boundary for host-global facts. A physical container
observed through three coordinator sources is one host resource with several
provenance or control bindings.

### Observation

An observation is timestamped evidence about one host or source resource. It
does not redefine ownership or repository identity.

Examples include server health, listener ownership, process CPU/RSS, Docker
status, Docker telemetry, and repository-path availability. Current state and
time-series samples use separate tables and retention policies.

### ProjectAggregate

`ProjectAggregate` is a read model, not a persisted identity shortcut. It is
derived after physical-resource deduplication:

```text
ProjectAggregate {
  repository
  source_resource_refs[]
  host_resource_refs[]
  servers[]
  containers[]
  databases[]
  current_usage
  control_state
}
```

Processes are deduplicated by process identity, containers by host resource
identity, and metrics are summed only after deduplication. A source contribution
must not duplicate CPU, memory, or resource counts.

### ControlBinding

`ControlBinding` answers: “which authority may act on this resource?” It maps a
repository or resource to one coordinator source and records provenance,
capability, priority, and conflict state.

Repository display is independent of control binding. A repository may be
visible while an ambiguous legacy binding blocks mutation. The UI must show
the conflict rather than split one repository into several projects.

## Unassigned resources

Resources without a validated repository path belong to one explicit
Unassigned Resources surface. They are not projects and do not receive
whole-project actions.

Each unassigned row retains:

- its `HostResourceIdentity` when observable;
- all `SourceResourceIdentity` contributions;
- its real name, status, ports, and health;
- why attribution is unavailable or conflicting;
- explicit evidence such as Compose labels or coordinator sidecars; and
- an authorized Attach to Repository action when the operator chooses a real
  repository.

Name resemblance may power a suggestion, but it must never silently establish
membership. `name:aicursegmailcheck` and `name:kosttracking` are examples of
unassigned grouping hints, not repository identities.

## One observer per host resource domain

The observation planner groups work by physical observer domain before any
subprocess is launched:

1. Resolve a stable local `host_id`.
2. Resolve Docker engine identity from the configured context/socket and a
   verified daemon identity.
3. Coalesce concurrent refresh requests with a single-flight key per engine.
4. Run Docker `ps`, one bounded `stats --no-stream`, and batched `inspect` once.
5. Bind returned containers to repositories from explicit Compose labels or
   validated sidecar metadata.
6. Persist changed current observations and new telemetry once.
7. Build all project aggregates from the deduplicated observation.

The database-backed single-flight key includes whether Docker is present and a
digest of the canonical backup-directory set. A no-Docker readiness probe or a
different backup scan therefore cannot satisfy/join a full Board or removal
observation. Automatic Board refresh waits its configured interval after the
prior refresh completes and retains the last presentation while work runs.
This is coalesced interval observation, not an event stream. PostgreSQL catalog
discovery still performs bounded container queries during a full observation;
that measurable residual must not be described as eliminated polling.

Source homes may contribute sidecar metadata or server definitions, but they
must not independently resample the same Docker engine. Conflicting sidecar
claims are stored as conflicts; Compose working-directory evidence remains
explicit and inspectable.

Backup discovery should likewise run once per distinct active repository, not
once per source snapshot. It produces immutable backup evidence or a bounded
cache entry, separate from project identity.

## Implemented private SQLite WAL schema

The database remains private to the effective UID: its directory is mode
`0700`, files are mode `0600`, symlink components are refused, and ownership is
validated before open. WAL and sidecar files receive the same protection.

The schema is created and migrated atomically by `devcoordinator/schema.py`.
Field names may evolve through a versioned migration, but the following entity
boundaries and uniqueness rules are current requirements.

| Table | Purpose and required constraints |
| --- | --- |
| `schema_metadata` | Schema version, database generation, created/updated timestamps, migration state. |
| `hosts` | Stable host identity and observation capability metadata. No user credentials. |
| `coordinator_sources` | Canonical source identity, home or endpoint, effective UID, enabled/imported/retired state. |
| `repositories` | `repo_id`, `host_id`, canonical root, display name, active/missing/relocated state. `UNIQUE(host_id, canonical_root)`. |
| `repository_aliases` | Historical roots and relocation evidence. An alias cannot point at two repositories on one host. |
| `repository_installations` | Installed/disabling/disabled state, durable start fence, generation, actor/reason, and removal/reinstall operation. One row per repository. |
| `repository_memberships` | Exact one-repository ownership of server/container/supervisor host resources. A physical resource cannot be active in two repositories. |
| `server_definitions` | Durable server name, argv/template, cwd, environment references, health template, and log path. `UNIQUE(repo_id, name)`. |
| `source_resources` | `SourceResourceIdentity`, original legacy/native payload identity, and source provenance. |
| `control_bindings` | Resource/repository to authoritative source routing, capability, provenance, and conflict state. |
| `server_observations` | Latest health, PID identity, listener identity, lifecycle classification, and sample time. Separate from definitions. |
| `port_assignments` | Durable scheduling policy. `UNIQUE(repo_id, server_name)` and `UNIQUE(host_id, port)` for an unbrokered host namespace. |
| `leases` | Active/released/stale reservations with repository, owner, optional server, process identity, and expiry. |
| `operations` | Durable lifecycle transaction journal, generation, owner process identity, phase, status, and structured result/error. |
| `operation_targets` and parameter/dependency tables | Exact immutable multi-target plan, phase, per-target result/error, and execution ordering. |
| `events` | Append-only operator-relevant events referencing normalized entities rather than embedding authoritative copies. |
| `startup_policies` and `startup_policy_restore_states` | Current disable value plus exact pre-decommission Docker/supervisor/Compose/coordinator policy capture, restore state, and immutable binding evidence. |
| `resource_retirements` | Standalone resource disabling/retired fence and operation evidence. |
| `docker_engines` | Physical observation domain: host, context/socket identity, daemon identity, and capability state. |
| `docker_resources` | Immutable container identity, current name/image, and engine. `UNIQUE(engine_id, full_container_id)`. |
| `docker_observations` | Latest status, ports, labels digest, health, and sample time for one container. |
| `docker_ownership_claims` | Compose and sidecar repository claims with source, provenance, priority, and conflict state. |
| `database_bindings` | Logical database identity associated with a physical container and repository. |
| `telemetry_samples` | Bounded process/Docker samples keyed to host resource identity and time. |
| `backup_evidence` | Immutable backup/manifests/checksum/verification evidence; not repository configuration. |
| `legacy_imports` | Source path digest, source revision/hash, backup manifest, phase, and committed/rolled-back state. |
| `migration_conflicts` | Exact duplicate, identity conflict, port conflict, ownership conflict, or pending-operation disposition requiring review. |
| `unassigned_resources` | One physical resource, exact reason, suggested root, and active/attached/retired disposition without synthetic project identity. |
| `broker_lease_links`, `broker_assignment_links`, and reconciliation queue | Client-store link to the service-owned broker reservation/assignment, exact authority generation, rollback state, and unresolved cleanup evidence. |

SQLite foreign keys must be enabled. Mutations use `BEGIN IMMEDIATE` only for
the bounded reservation/commit phases that require exclusion. Slow process,
Docker, HTTP, Git, backup, and filesystem observation remains outside write
transactions and commits with optimistic fingerprints.

A service-owned broker database adds peer principals, per-resource ACLs, port
policies, durable assignment/lease ownership, idempotent authenticated request
records, and service-owned Compose definitions/files/services. Clients never
receive that database path or submit SQL, commands, repository paths, Compose
paths, or argv through the socket. A root-owned enrollment profile exposes only
the expected socket identity, service database generation, authenticated UID's
account ID, canonical repository root, and opaque normalized IDs.

## Read-only inventory contract

`inventory` and `GET /v1/inventory` are pure reads of one consistent SQLite
snapshot. They must not:

- increment an observation generation;
- rewrite the database or a state file;
- sample Docker or processes;
- scan backup directories;
- reconcile or prune records; or
- change an operation, lease, server, or telemetry record.

Observation is an explicit, coalesced command or coordinator service job.
The Board can request refresh and then read a completed snapshot, or read the
last completed snapshot with its age and an in-progress indicator. Multiple
Board/Codex clients share the same in-flight observation rather than spawning
parallel work.

State revision changes only for control-state mutations. Observation revision
changes only when an observation transaction commits a material difference or
a retained telemetry sample. A pure inventory read leaves logical database
content, counters, revisions, and the canonical database and maintenance-lock
identities and bytes unchanged. The read path may create private same-account
`-wal`/`-shm` coordination files when opening a WAL database whose sidecars are
absent. An unexposed existing-only `mode=rw` bootstrap makes `query_only` its
first SQL statement, lets SQLite create sidecars under its own locks, and stays
open until the real `mode=ro` reader attaches. Only the VFS-enforced read-only
connection reaches inventory and schema/data reads, so closing inventory cannot
checkpoint or truncate an orphaned committed WAL. The files are validated
again after first WAL access and before schema data is trusted, and the
stabilized set is reused on repeated reads. A non-WAL store is rejected without
a stray WAL artifact. If journal access and that security check both fail, the
top-level error retains both causes, including any cleanup failures.

## Telemetry retention

Retention must be bounded globally and per resource:

- cap samples per resource and by wall-clock age;
- retain short high-resolution and optional longer downsampled windows;
- expire telemetry for retired resources after a documented grace period;
- delete orphan series transactionally when no current resource or retained
  incident references them;
- enforce a total database-size or sample-count budget; and
- expose pruning counts and oldest/newest sample time as diagnostics.

Current status and immutable incident/backup evidence are not silently deleted
with telemetry. Tests must distinguish these lifecycles.

## Action routing

### Resource action

A server or Docker action starts with the selected resource identity. The
control binding resolves exactly one authorized source and exact native target.
Host-resource identity is reverified before mutation. A stale, missing, or
conflicting binding blocks before an operation or signal is written.

### Repository action

A whole-repository action starts with `repo_id`, never a source-specific
project group. The planner resolves all definitions and host resources, then
creates a concrete action plan:

- same-UID state imported into the account store has one canonical source;
- server operations target their exact source/native identities;
- a physical Docker resource is acted on once per engine, even if several
  sources contributed metadata;
- duplicate definitions or port conflicts block the affected target and remain
  visible; and
- multi-target outcomes retain per-target success/failure and truthful partial
  completion.

During legacy migration, a repository with unresolved multi-source ownership
is visible but its whole-project mutation is disabled. The system must not
choose an arbitrary source and must not fan the same Docker action out to every
legacy home.

## Same-UID legacy import transaction

Automatic Parall-home discovery becomes migration discovery, not permanent
inventory aggregation. New clients use the POSIX-account store by default.

### Preflight and preservation

1. Resolve and validate the account-owned canonical destination.
2. Discover same-UID legacy homes without following unsafe symlinks.
3. Acquire source locks in deterministic canonical-path order.
4. Record each source revision, byte size, SHA-256, ownership, and mode.
5. Create a new private, checksummed backup transaction outside Git.
6. Copy every state, lock-independent log reference, and required sidecar
   metadata before import.
7. Abort if a source revision/hash changes between capture and commit.

The importer never resets, rebases, deletes, or rewrites legacy state to make
the import convenient.

### Import rules

- Canonicalize every project path. An existing strict Git root becomes one
  repository; an absent root becomes a missing tombstone; a non-Git path is
  unassigned/conflicted.
- Merge exact duplicate server definitions into one active definition and
  retain every original source record as provenance. If definitions differ,
  live listener/process identity determines current evidence, but conflicting
  configuration remains explicit rather than being discarded.
- Collapse exact duplicate port assignments. Different ports for one
  `(repository, server)` or one host port claimed by different repositories
  become blocking migration conflicts.
- Verify any active lease against immutable process/listener ownership. Never
  import a caller-supplied PID as active merely because it is alive.
- Key Docker metadata by immutable full container ID when available. Retain
  Compose and sidecar provenance separately and surface conflicting claims.
- Namespace imported operation/event IDs by source when collision is possible.
  Reconcile pending operations; never turn an abandoned pending operation into
  success.
- Deduplicate telemetry by host resource and sample identity, then apply the
  target retention policy.

### Commit and retirement

The importer writes all normalized rows and conflicts in one database
transaction, runs invariant queries, checkpoints the WAL, and writes a durable
import marker containing all source hashes/revisions and the destination
generation. Only then may the Board stop polling imported homes.

Legacy files remain private and untouched for the compatibility window. A
later change to a retired source is detected as a legacy-writer conflict and
requires another bounded import; it is not silently ignored.

## Linux cross-user boundary

The default database is per effective UID. Different users must not share a
writable directory or SQLite database. Private ownership and mode checks remain
mandatory.

Two supported host-wide policies are possible:

1. **Isolated user coordinators:** each UID has its own database and an enforced
   non-overlapping port range. Docker visibility follows that user's actual
   socket permissions. This is the default deployable model.
2. **Authorized host broker:** a system service owns a root/service-owned
   database and Unix socket, authenticates clients with peer credentials,
   enforces per-UID repository/resource ACLs, and arbitrates host-global ports
   and Docker resources. Clients never receive shared filesystem write access.

The authorized broker is implemented as a peer-authenticated local Unix-socket
service. It is an explicit deployment boundary, not an implicit daemon: a root
operator must create the service-owned database, enroll each UID/repository,
publish the root-owned client profile, place clients in the socket access
group, and supervise `broker serve`. Without that installation, isolated user
coordinators still require disjoint ranges. Lack of cross-user visibility is
never proof that a port or container is unowned.

## Compatibility

The CLI and API expose an explicit inventory schema version and a v2 graph with
`repositories`, `resources`, `unassigned_resources`, `observations`, and
`control_bindings`.

A bounded v1 compatibility projection may continue returning `servers`,
`leases`, `docker`, and `project_usage`, but:

- each path-backed repository appears once;
- `project_usage` is generated from deduplicated host resources;
- name-only resources appear under an explicit unassigned key, not as an
  actionable project; and
- source/native identities remain available on resource rows for safe action
  routing.

The Board consumes v2 directly. The remaining v1 compatibility code must stay a
bounded projection of that graph and never become a second identity or
observation implementation.

## Delivery phases

Current status: phases 1 through 8 are implemented. Release acceptance remains
pending until the final normal/optimized, native, packaged-app, remote Linux
cross-UID, rollback, boundary, and freshness gates in this document pass.

1. **Contract and guardrails:** add the domain types, schema contract, realistic
   must-catch fixtures, read-only inventory write detector, and migration
   conflict fixtures before changing live storage.
2. **Canonical read model:** build one repository graph from existing snapshots
   while retaining source-resource identities. Move name-only rows to
   Unassigned Resources. Keep unsafe repository actions blocked.
3. **SQLite store and importer:** implement the private schema, JSON importer,
   invariant queries, telemetry retention, and dry-run conflict report.
4. **Shadow comparison:** populate a disposable/shadow database from copied
   real-shaped state and compare v1 inventory, resource counts, identities, and
   action plans without changing production state.
5. **Transactional same-UID import:** preserve backups, import legacy stores,
   resolve or explicitly retain conflicts, and verify the destination.
6. **Coordinator cutover:** make SQLite authoritative for mutations and pure
   inventory reads. Coalesce observation work once per host/engine.
7. **Board cutover:** consume the v2 graph, verify one repository node per root,
   and stop polling verified imported homes.
8. **Legacy retirement:** retain rollback artifacts for the declared window,
   detect late legacy writers, then archive rather than silently delete state.

No phase may report release acceptance before its original surface, migration,
action, and rollback checks pass.

## Rollback

Before authoritative cutover, rollback removes only the disposable/shadow
database and leaves legacy files unchanged. The import transaction keeps its
checksummed source backups and conflict report.

At authoritative cutover, record a durable phase marker and destination
generation. If no SQLite-only mutation has committed, rollback may switch the
read pointer back to the unchanged source generation. Once a SQLite-only
mutation commits, rollback must export a verified compatibility snapshot from
the database or replay the transaction journal; pointing clients at stale JSON
would lose state and is forbidden.

Routine normalized-store backup/restore is an explicit administrative CLI
surface. Binary restore is restricted to a strongly verified artifact from the
same database generation, logical import is restricted to a verified export,
and both require a readable current authority plus a newly verified safety
backup. Neither path guesses through SQLite corruption. Offline corrupt-store
recovery instead requires every writer stopped, captures and checksums the
exact current database/WAL/shared-memory files for forensics, accepts only a
strongly verified binary artifact of the same store role, validates the
replacement, and restores the exact captured bytes if publication fails.

Rollback verification must compare repositories, server definitions, active
leases, assignments, pending operations, control bindings, and source hashes.
Telemetry may be compared under its documented retention policy, but control
state may not be dropped to make counts match.

## Required tests and acceptance evidence

### Repository identity

- Same canonical worktree path from three sources produces one repository.
- Two sources reusing one native server ID produce two
  `SourceResourceIdentity` values inside one repository, not two projects.
- Nested cwd and symlink aliases collapse to one root.
- Two same-basename clones at different paths remain separate.
- Two Git worktrees with a shared object database remain separate.
- A non-Git path and a `name:*` container never enter the active project list.
- A deleted repository becomes a missing tombstone, not an active project or a
  silently deleted history record.
- Relocation preserves `repo_id`, assignments, and evidence without aliasing
  another existing repository.

### Real failure-shaped Board presentation

- Three snapshots each containing the same two Nevod containers render one
  Nevod project and count each physical container once.
- Three `name:aicursegmailcheck` rows render one unassigned resource group and
  no aicursegmailcheck project.
- One source owns the deduplicated Docker row while other sources contribute
  usage; no empty benzovozka project shells appear.
- Same project display names at distinct roots remain distinguishable.
- Project Load contains one row per repository and metrics are independent of
  source count.
- The supplied narrow/restored-window failure shape is rendered through the
  production SwiftUI hierarchy; the center panel starts below the toolbar and
  no top content, toolbar control, filter, table header, or footer is clipped.
  A wider-window control guards against overcorrecting the layout.

### Observation and performance

- Three same-host sources sharing one Docker engine cause exactly one bounded
  `ps`/`stats`/batched-`inspect` observation per refresh.
- Concurrent Board/Codex refreshes join one single-flight observation.
- Pure inventory reads leave database pages, revisions, observation tickets,
  and file timestamps unchanged.
- A second backup-discovery request does not resample Docker or rewrite control
  state.
- Retired-container telemetry is removed after the configured grace period;
  active telemetry and retained incident evidence are false-positive controls.
- Sustained polling proves bounded database size and no accumulation of retired
  series.

### Storage, concurrency, and migration

- Two same-UID processes mutate different repositories concurrently and
  serialize conflicting reservations correctly under WAL.
- Crash injection at every import phase leaves either the old authoritative
  state or the complete new transaction, never a partial mix.
- Real-shaped imports include duplicate stopped server UUIDs, exact duplicated
  assignments, cross-project port conflicts, retired telemetry, pending
  operations, and one missing repository path.
- Exact duplicates merge; materially different conflicts remain visible and
  block only unsafe actions.
- Source revision drift between capture and commit aborts without changing the
  destination authority.
- Rollback before and after the first SQLite-only mutation follows the two
  distinct safe paths described above.
- v1 compatibility output and v2 graph agree on physical resources and active
  repository membership.

### Action safety

- A repository action plans by `repo_id` and never runs the same physical
  Docker action once per source.
- Source-native server-ID collisions route each resource to its exact source.
- Ambiguous control binding, unknown listener ownership, missing repository,
  and migration conflict all fail before an operation, signal, lease, Docker
  action, or sidecar write.
- Partial multi-target results retain every failure and completed target.

### Linux user boundary

- Same-UID clients with different runtime `HOME` values resolve one account
  database and lock domain.
- Different UIDs cannot open or modify each other's database, WAL, shared-memory
  file, token, logs, or backups.
- Isolated-user mode enforces disjoint port ranges with a realistic overlapping
  configuration must-catch and a non-overlapping false-positive control.
- Broker mode authenticates real peer credentials and enforces
  repository/resource ACLs before host-global mutation.

Every detector added for this migration must prove recall against these
realistic failure classes and include intentional-pattern false-positive
controls. Passing implementation-shaped fixtures alone is not acceptance.

## Non-goals

- This implementation is not a remote orchestrator, general identity provider,
  or replacement for OS account and service supervision policy.
- It does not create synthetic repositories or infer ownership from names.
- It does not merge separate local worktrees because they share a Git remote.
- It does not weaken source-resource provenance or listener-identity safety to
  obtain a cleaner UI.
- It does not make a cross-user writable state directory acceptable.
