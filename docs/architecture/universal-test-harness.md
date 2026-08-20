# Universal test harness and control-plane isolation

This document is the production contract for the server-wide DevCoordinator
test harness. It describes one final architecture; schema versions are
fail-closed discriminators, not product compatibility modes.

All on-host communication follows the
[single-developer local trust model](single-developer-local-trust.md): Unix
identity is attribution, not authorization. Dedicated accounts and cgroups
remain for attribution, accounting, cancellation, and crash cleanup rather
than per-account or per-worker quotas.

## Availability boundary

`devcoordinator-edge` is the only owner of ports 80 and 443. It authenticates
Google identities, authorizes public domains, terminates TLS, selects upstream
protocols, serves content-addressed Console assets, and proxies from an
atomically published last-known-good route snapshot. A project, observer,
Console backend, broker, or test-plane failure must not remove the edge from a
project request path.

The control plane is split into independently supervised services:

- the root-owned authority and broker keep repository identity, grants,
  admission, and generation fences;
- socket-owned API and Console listeners survive compatible process
  replacement;
- blue/green Console slots are started and verified before the stable listener
  switches, then the old slot drains;
- the observer publishes bounded retained inventory without owning project
  lifecycle;
- `devcoordinator-testd` owns scheduling, test history, result ingestion, and
  rollups through a private Unix socket;
- the root snapshot helper performs only generation-bound, UID-attributed
  source preparation and attempt launch;
- project and test processes run outside the control slice. Ordinary test
  attempts use attributed, accounting-only leaves below
  `devcoordinator-tests.slice`; they do not inherit the background daemon's
  CPU, memory, or process ceilings.

Production runs from a root-owned, content-addressed, non-writable release.
The mutable Git checkout remains the canonical source for skill links but is
never a production executable root.

## Authority and stores

High-volume test results never enter an authority transaction. The deployment
has four explicit state classes:

1. authority: immutable repository identity, generations, grants, broker
   admission, protected capabilities, and mutation journals;
2. inventory/telemetry: retained, bounded observations and projections;
3. tests: snapshots, plans, runs, attempts, cases, failures, artifacts, events,
   evidence attestations, and hourly/daily rollups;
4. Console access: Google grants, invite requests, and other Console-owned user
   state. Telegram configuration remains in this logical state class but has a
   separately owned file and dedicated background worker; Console never polls
   Telegram or dispatches notifications in its control-plane process.

Startup performs read-only schema/profile checks and never migrates. The
production test read authority is explicitly `testd`; a missing protected
profile or test plane fails closed. No prior test-table read contract is
available in production or account mode.

Only a reviewed authority schema or pointer transaction activates global
maintenance. During that transaction, edge routes, the Console shell, Board,
and existing project traffic remain available; fenced mutations receive the
fixed typed maintenance response.

## Test lifecycle

Planning attributes the request to its actual non-root local caller and records
that UID as the repository execution identity. A protected non-executing reader
may inspect source metadata, after which the root boundary revalidates and
clamps the launch descriptor. Repository content is never executed while
parsing a manifest, and filesystem stat ownership never selects execution.

Testd and the disposable Test Store are the sole semantic authority for plan
inputs, dependency readiness, runs, attempts, deadlines, leases, result order,
and conclusions. The privileged snapshot/runtime boundary returns exact host
facts and performs idempotent prepare/start/observe/stop/collect actions; it
does not retain a second run state machine. Framework invocation, dependency,
and reporter selection is routed through explicit driver registries before the
normalized attempt/result crosses the store or scheduler.

1. `test plan` validates the manifest, computes changed inputs, expands target
   dependencies and reverse dependencies, and registers a durable plan.
2. `test submit` is idempotent and returns a run ID immediately.
3. Testd admits dependency waves and history-backed shards with fair ordering
   across repositories. It starts work when current Linux `MemAvailable`, less
   the protected control-plane reserve, covers the learned peak memory for the
   selected target. A target without history uses the conservative software
   default. CPU availability, declared CPU, account identity, repository
   identity, PID counts, and fixed job counts never reject or delay a test.
4. Testd and the broker exchange an exact generation-fenced launch descriptor
   over a kernel-attributed local Unix socket. Peer credentials provide
   attribution and routing, not local-account authorization. No bearer token,
   signature, or cryptographic ticket is created for on-host communication. Network or
   fixture access still requires a declared policy capability. An operational
   credential additionally requires both its exact administrator-sealed
   binding and a separately sealed named capability.
5. The root helper launches the attempt as the durably recorded actual non-root
   caller in a transient systemd unit with a clean environment, hidden unrelated homes, a private
   scratch area, explicit TTL, control-group cancellation, and
   `kill_after_run=true`. The unit enables CPU, memory, I/O, and task accounting
   but has no `CPUQuota`, `MemoryHigh`, `MemoryMax`, or `TasksMax`. Operational
   credential bytes cross the UID boundary only through transient systemd
   `LoadCredential=` files. Standard ignored dependency installations are
   derived by the Coordinator, never supplied as manifest mount paths. An
   immutable attempt receives only the applicable snapshot-lock-matched Python,
   Node, or package-cache root at its normal materialized path, read-only; an
   absolute interpreter link may additionally expose only its narrow external
   package-manager toolchain. Whole homes stay hidden.
6. The runner produces bounded captures and structured reporter output. It
   records actual peak memory from cgroup `memory.peak` and actual CPU time from
   `cpu.stat usage_usec`; both feed later scheduling and fleet telemetry. CPU is
   observational only. The runner exposes only opaque artifact IDs and digests;
   the protected collector copies and revalidates execution-private files before
   testd stores public handles.
7. Chunked result and exit evidence is durably spooled. Exact attempt,
   repository-generation, attempt-generation, chunk, and operation IDs make
   replay idempotent and prevent an abandoned attempt from completing a retry.
8. Terminalization requires a complete, internally consistent chunk set.
   Testd commits that conclusion first, then requests exact privileged runtime
   collection; rollups update without joining high-volume reads to raw cases.

Lease expiry, missed heartbeat, crash, timeout, cancellation, incomplete
reporting, abandonment, test failure, infrastructure failure, and superseded
live work are distinct outcomes.

The ordinary heartbeat lease remains short so a real testd crash is detected
promptly. A replacement daemon may cross an expired ordinary lease only for an
exact still-active attempt reconstructed from its private durable spool. It
validates the retained generation, lease owner, repository/runtime binding and
launch identity, grants one bounded recovery lease, then returns to normal
observation and heartbeat. Missing, contradictory, reaped or terminal
identities are never reconstructed, and recovery never creates a second launch.

## Source modes and reuse

Agent-local tests are a narrow feedback path, not an alternate suite runner.
One direct invocation is eligible only when its selector is proven before
launch to collect at most 20 cases, its runner enforces at most 10 seconds of
execution, it needs no host-visible or shared state, and it is not one fragment
of a suite split across repeated local commands. Unknown or larger scope and
durable evidence use one governed plan and asynchronous run. The same limit
applies to advisory tests after a reported harness failure; static checks remain
local and outside the test-case limit.

`change` and `checkpoint` runs are advisory live-worktree runs. They do not
lock editing. Selection is recomputed immediately before launch; a source
change during execution makes the result `superseded` while retaining it as
non-attestable diagnostic evidence.

`handoff`, `release`, and Console/manual verification use immutable private
materializations. Their source includes tracked, staged, unstaged, and bounded
non-ignored untracked files together with manifest, dependency-lock, and
toolchain identities. The materializer prefers Linux `FICLONE` copy-on-write,
falls back to a byte copy only for known unsupported-capability errors, verifies
the complete destination either way, and records `reflink`, `copy`, or `mixed`
in sealed provenance. Incomplete source capture blocks the plan.

Ignored generated dependency trees are deliberately not copied into immutable
source. Immediately before native launch, the Coordinator derives only standard
dependency roots implied by the selected target: a declared repository Python
environment, the target working directory's Node installation, or an applicable
package cache. Every mapping is repository- and destination-contained,
read-only, and admitted only while the original and materialized dependency
locks equal the selected snapshot provenance. A missing, changed, escaped, or
substituted dependency root is an infrastructure/bootstrap failure before
project code runs; the runner never silently falls back to a different system
environment.

Only identical active immutable jobs may deduplicate. Live runs and release
evidence never reuse completed results. Other immutable evidence may be reused
only when a named project policy explicitly permits an exact provenance match.

## Manifest contract

Repositories declare `.codex/tests.json` with:

- schema discriminator, defaults, global inputs, intents, targets, sealed
  fixture references, opaque operational-credential binding references, and
  named evidence policies;
- a typed driver/reporter and no-shell argv for every target;
- repository-relative working directory and input rules;
- intent membership, dependencies, timeout, network capability, exclusive
  resources, shard policy, artifacts, and bounded non-secret literal
  environment. Repositories never declare CPU, memory, PID, or worker quotas;
  testd learns actual target memory from completed attempts.

Manifest schema 3 requires every target to declare an explicit `retry` object
with both `max_attempts` and `retry_on`. `max_attempts` is 1–4; one attempt
requires `retry_on: []`, while multiple attempts require
`retry_on: ["lease_expired_before_launch"]` exactly. No assertion, test failure,
timeout, post-launch heartbeat loss, or other infrastructure outcome is retried
by this policy. Schema 3 is the only accepted manifest schema; every earlier or
unknown schema is rejected rather than normalized or upgraded during planning.

Network defaults to none. Private `loopback` is ordinary isolated test
reachability on this confirmed single-developer host and needs no separate
repository-generation grant. Host loopback and external access remain separate
protected capabilities. `host-loopback` is admitted only for an exact
manual-only target with no fixtures; named operational credentials remain
optional. Its generation-bound `network.host-loopback` grant runs in the host
network namespace without `PrivateNetwork` or `NetworkNamespacePath`, while
systemd `IPAddressDeny=any`, `IPAddressAllow=localhost`, and
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` permit host `127.0.0.1`/`::1`
only. Ordinary loopback remains a private network namespace and cannot reach
host loopback. Fixture names resolve only to administrator-sealed broker
templates; manifests cannot provide images, mounts, privileges, secrets, or
Docker flags. A credential declaration contains only a repository-local
logical name and an opaque administrator-created binding alias. It cannot
contain a value, source path, dotenv key, destination filename, provider
identifier, or grant. Credential-bearing targets must be manual-only.

For example:

```json
{
  "credentials": {
    "health-sweep-admin": {
      "binding": "skydive-health-sweep-admin-v1"
    }
  },
  "targets": {
    "health-sweep-post-deploy": {
      "intents": ["manual"],
      "credentials": ["health-sweep-admin"]
    }
  }
}
```

This fragment is illustrative; each target still requires the ordinary full
target contract. The binding alias is not a secret and does not select the
runtime filename. The administrator binding fixes that filename independently.

Selection fails toward more testing. Manifest, lockfile, build-system, CI,
global-input, unmapped, renamed, deleted, and unexpected untracked changes
select the complete required intent. Invalid globs, unknown fixtures, graph
cycles, path escapes, incomplete snapshots, or missing capability coverage
block planning.

`test manifest init`, `validate`, and `doctor` report each enrolled repository
as `ready`, `missing`, or `invalid`. Doctor validates the repository contract
and protected capability policy; it deliberately does not probe executables or
dependency paths as the calling Unix account. Protected immutable planning and
runner launch own lock-bound dependency and executable validation and return a
typed, journal-correlated failure when it is not usable. Raw framework commands remain available
for debugging, but do not produce Coordinator evidence or statistics.
The fleet catalog must cover every authority repository exactly once, but a
missing or invalid project remains locally fenced rather than blocking a
control-plane release. Only `ready` repositories can be planned or executed.

Fleet cataloging and optional manifest publication use a protected,
non-executing reader. The private plan binds every proposed document to an exact
repository ID, generation, current content digest, actual non-root caller UID,
and explicit administrator-supplied final manifest. UID/GID, filesystem owner,
mode, ACL, group, and link-count observations never authorize adoption, select
the execution identity, or determine readiness. Each atomic write preserves
existing valid documents; prior invalid bytes remain non-executable rollback
evidence. Authority or content drift blocks before the first write, and a
partial failure restores prior document bytes from the same sealed plan. No
adoption path scans repositories, repairs filesystem permissions, or infers
commands.

Typed .NET attempts use a runner-owned writable CLI home with first-use,
telemetry, logo, and workload-update notification behavior disabled. Before the
project process starts, the runner resolves the target project/solution's
nearest contained `global.json` context and performs a bounded SDK readiness
probe under the same clean environment. An unavailable pinned SDK or workload
bootstrap failure yields linked bounded infrastructure evidence. Only an
executed project process or structured TRX evidence may produce a project test
failure.

The immutable `devcoordinator-test-manifest-adoption` binary consumes the
authority repository export sealed during cutover. `catalog` revalidates every
exported repository ID, generation, and canonical root against the read-only
authority before parsing the manifest through the protected non-executing
reader. It reports only `ready`, `missing`, or `invalid`: readiness depends on
document bytes, schema, graph, policy, path containment, and complete source
input, never local permission metadata. Its public result contains no
repository paths, tracked names, or invalid bytes. `prepare-request` retains an
existing valid document exactly and requires a separately authored explicit
manifest for every missing or invalid repository. That explicit manifest set
is bound to the authority-export SHA-256. The complete request is written once
before the usual `plan`, `apply`, and exact result-digest `rollback` steps. Test
commands are therefore reviewed input, not a guess made by the adoption
executor.

The manifest-set input is deliberately smaller than the final request:

```json
{
  "schema_version": 1,
  "authority_export_sha256": "<sealed export digest>",
  "operation_id": "<UUID>",
  "manifests": [
    {"repository_id": "<missing-or-invalid ID>", "manifest": {}}
  ]
}
```

Every `manifest` above is the complete reviewed final contract, not a patch.
Rows are unique and sorted by repository ID. Ready repositories must not appear
because their validated current document is retained without a write.

There is no repository permission-repair adoption transaction. Local UID/GID,
owner, mode, ACL, group, and link-count differences remain bounded diagnostics
and cannot make a repository `repairable`, `blocked`, authorized, or
unauthorized. A missing caller routing/execution record is provisioned
atomically by the valid first-use flow for the actual non-root caller. Explicit
disabled action, repository, enrollment, and lifecycle state remains disabled.

First availability does not publish manifests across the fleet. It records one
read-only, authority-complete catalog, requires the DevCoordinator dogfood
repository to be `ready`, and activates the control plane with zero repository
mutations. Other ready repositories are runnable immediately. Missing or
invalid repositories remain visible as project-local Setup work and do not
block Console, Coordinator, or test-plane availability. The administrator may
later run the explicit manifest plan/apply transaction for selected
repositories; its document rollback contract remains unchanged.

The first-availability fleet journal records that catalog and the exact
runnable and Setup repository IDs. Replay revalidates the sealed authority
export and catalog; rollback is a no-op because no repository bytes or metadata
were changed. A pre-existing incomplete manifest-publication journal must be
rolled back and replaced with a fresh request rather than being silently
reinterpreted as the catalog-only gate.

## Operational credentials

Operational credentials are a separate broker-owned data class, not a fixture,
manifest literal, provider profile, or ordinary environment variable. The
root administrator imports a named value from one canonical regular dotenv
file owned by root or by the exact recorded repository execution UID. The source must
be mode 0400 or 0600, have one link, contain the named key exactly once, and
remain the same inode and size for the entire descriptor-based read. Symlinks,
hard links, owner or mode mismatches, duplicate keys, concurrent replacement,
and malformed values fail closed.

Registration binds the opaque alias to all of:

- exact repository ID and repository generation;
- exact target, manual intent, and recorded execution UID;
- fixed non-secret systemd credential filename;
- maximum attempt TTL and credential rotation generation.

The root registry at
`/etc/devcoordinator/test-execution-credentials.json` is mode 0600 and stores
only binding metadata, opaque material identity, value and source digests,
source descriptor identity, hashed source path, and rotation state. It never
stores the source path or credential bytes. Root-only material lives beneath
`/var/lib/devcoordinator/test-execution-credentials/` in mode-0400,
single-link files. Per-attempt copies live beneath
`/run/devcoordinator/test-execution-credential-leases/` and are removed during
terminal cleanup. Crash recovery retains only enough root-private lease
metadata to retry exact cleanup.

The administrator workflow is compare-and-swap guarded:

```text
devcoordinator-test-credential register \
  --alias skydive-health-sweep-admin-v1 \
  --repository-id <exact-repository-id> \
  --repository-generation <exact-generation> \
  --target health-sweep-post-deploy \
  --execution-uid <exact-recorded-caller-uid> \
  --credential-name health-sweep-bearer \
  --max-ttl-seconds 1800 \
  --source-env-file <canonical-ignored-dotenv-path> \
  --source-key ADMIN_TOKEN

devcoordinator-test-credential rotate \
  --alias skydive-health-sweep-admin-v1 \
  --expected-rotation-generation 1 \
  --source-env-file <canonical-ignored-dotenv-path> \
  --source-key ADMIN_TOKEN

devcoordinator-test-credential revoke \
  --alias skydive-health-sweep-admin-v1 \
  --expected-rotation-generation 2

devcoordinator-test-credential list
```

These commands print path-, digest-, and secret-free metadata. The credential
value is never accepted on the command line. The named source file may be an
ignored application `.env`; importing it does not add that path or its bytes
to the repository manifest.

At admission, `credential.<binding-alias>` must exist in the exact
repository-generation capability policy. At provisioning and immediately
before launch, the broker rechecks repository, generation, target, intent,
owner, TTL, active status, and rotation generation while holding the registry
read lock. Reusing one runtime identity with a different descriptor or
rotation is rejected. The transient unit receives only:

```text
LoadCredential=health-sweep-bearer:<root-private-opaque-runtime-path>
```

The runner rebuilds the child environment from a fixed allowlist, strips
inherited variables, and exposes only systemd's `CREDENTIALS_DIRECTORY`.
Credential bytes, their common encodings, root-private paths, and internal
lease state are excluded from tickets, SQLite, manifests, argv, logs,
artifacts, results, and public evidence. If exact credential material reaches
captured output or an artifact, the runner redacts it and marks the attempt
incomplete.

Rotation and revocation prevent new provisioning and any lease that has not
yet crossed the final guarded systemd launch. They cannot erase a kernel-owned
credential copy already delivered to a running process. To recall an active
credential immediately, revoke or rotate the binding and cancel the exact
active attempt; normal TTL and `kill_after_run=true` remain the backstop.

## Public surfaces

Agents use the canonical Python CLI:

```text
test manifest init|validate|doctor
test plan
test submit --repository-id REPOSITORY --plan-id PLAN --operation-id UUID
test status --repository-id REPOSITORY --run-id RUN
test summary --repository-id REPOSITORY --run-id RUN
test failures --repository-id REPOSITORY --run-id RUN [--after CURSOR] [--limit N]
test artifact --repository-id REPOSITORY --run-id RUN --artifact-id ARTIFACT
test cancel --repository-id REPOSITORY --run-id RUN --reason TEXT --operation-id UUID
test retry --repository-id REPOSITORY --run-id RUN --failed-only --operation-id UUID
test policy check
test catalog|stats
test wait --repository-id REPOSITORY --run-id RUN --timeout-seconds N
```

Manifest and plan commands derive repository identity from the explicit root
and temporary-repository context. Every later operation over an opaque plan,
run, or artifact identity also carries the immutable repository ID
returned by planning. The broker resolves and verifies that repository binding
before reading, mutating, or submitting; opaque continuation IDs never infer
or override project scope.

Plans persist and fingerprint two caller-selected semantic deadlines:
`execution_seconds` optionally overrides every selected target's manifest
deadline, while `launch_seconds` bounds definitive runner startup and
lost-reply reconciliation (300 seconds by default). Transport retries are
software-owned slices inside the launch deadline. `test wait` remains an
independent client-side blocking limit and never changes run state.

Default agent summaries are deterministic and at most 8 KiB. They contain the
conclusion, source identity, selection reasons, progress/timing, counts, at
most three actionable failures, artifact handles, and one drill-down command.

The broker exposes project-scoped manifest, plan, run, evidence, artifact,
rollup, and cursor-event operations. Every mutation has an operation UUID.
Internal lease, heartbeat, launch acknowledgement, chunk import,
terminalization, and reaping operations use the fixed supervisor-published
testd route plus the exact attempt and generation IDs. Unix-socket
`SO_PEERCRED` is recorded for attribution and diagnostics, not local-account
authorization. They do not use tokens, HMACs, or signed tickets. Content hashes remain
only for immutable snapshot/artifact identity, deduplication, and migration or
replay consistency. The `test.health` operation performs a
lightweight protected-store generation/schema read; offline startup continues
to use the stronger integrity verification rather than putting `quick_check`
on the serving health path.

Google grants use immutable repository IDs with `tests:read`, `tests:run`, and
`tests:operate`. Project users can run approved intents and cancel their own
runs; operators may act on another user’s run; Console owners retain release
intent and cross-project policy authority. Local agent calls are attributed and
routed by OS peer identity and broker records; those values are not
local-account authorization gates.

The current broker wire field for explicit test attribution is exactly
`actor`; there are no alternate actor field names. Agent-facing local clients
derive and emit canonical `codex:<thread-or-task-id>` attribution, falling back
to `codex:uid:<effective-uid>` when neither identity exists. Canonical
normalized `google:<email>` values are public identities and may be delegated
only by the protected Console API account. Every governed submit, cancel, and
retry mutation must carry this field; omission is invalid rather than a second
implicit attribution contract.

A host profile can contain several local routing records for the same canonical
repository. Routing selects an enabled entry by repository generation and the
actual non-root caller UID. If that caller has no record, a valid typed
first-use mutation provisions it atomically rather than selecting the
filesystem stat owner, root, a control-plane account, a lower UID, or the
profile default. Each repository call uses the account ID stored for that exact
caller record. Actor text and profile routing never replace exact repository
identity, generation, operation identity, explicit action/lifecycle state, or
Console authorization checks.

## Console information architecture

The default Tests view is fleet situational awareness, not individual-test
progress. It shows cross-repository coverage, freshness, efficiency, aggregate
test time, queue/capacity, failures, flakes, regressions, and trends. Selecting
a repository opens the detailed statistics, runs, and setup view. Individual
attempt evidence is loaded only on demand.

Retained content renders immediately and stays mounted during refresh. Project
failures stay inside their project view. Loading progress, healthy run volume,
and zero counts never create global banners or navigation badges. The badge is
reserved for conditions that may require a decision.

Charts expose exact values to pointer, keyboard, and touch users and include a
disclosed data table. Mobile replaces the fleet matrix with repository cards
and does not create document-level horizontal scrolling.

### Setup input-coverage evidence

The repository-UID Setup reader compares the validated `global_inputs` and
every target's `inputs` against the repository's bounded Git-visible path set:
the `HEAD` baseline, current index, and non-ignored untracked paths. The union
keeps staged deletions and both sides of a rename visible as planning inputs.
It does not claim behavioral or line coverage. A reported
`unmapped_repository_path` means only that a change to that exact relative
path cannot select a narrower target set and therefore triggers the planner's
complete required-intent fallback. Global-input matches count as mapped
because they deliberately select all eligible targets.

The projection returns concrete relative paths in sorted order, capped at 128,
followed by one fixed omission marker when more exist. If Git identity or path
enumeration cannot be completed, Setup returns the fixed
`input_coverage_inspection_incomplete` gap instead of an empty list. Repository
errors and path-discovery detail remain inside the repository-UID boundary.
Missing or invalid manifests have no input-coverage claims; their existing
sanitized manifest issue is the sole Setup blocker.

## Test Store cutover and activation

Test history is disposable. An incompatible deployment keeps testd offline,
recreates only its
private store at the current schema, publishes schema-readiness evidence, and
starts testd. It does not capture, drain, export, import, or seal prior test
rows, and it never opens the authority, profile, inventory, or Console stores:

```bash
sudo -n -H -u devcoordinator-testd \
  /opt/devcoordinator/releases/<digest>/bin/devcoordinator-test-store \
  initialize-fresh \
  --test-database /var/lib/devcoordinator-testd/tests.sqlite3 \
  --operation-id <canonical-operation-uuid> \
  --attestation-output \
    /var/lib/devcoordinator-testd/schema-readiness-<canonical-operation-uuid>.json \
  --expected-test-uid <devcoordinator-testd-uid> \
  --confirm-discard-test-history discard-test-history
```

The database parent must be testd-owned mode `0700`; the database and SQLite
sidecars, when present, must be testd-owned private regular files. A completed
operation replays through its unique attestation without deleting newly
recorded data. There is no authority-history importer or admission-drain
protocol.
The availability cutover `init` consumes the exact attestation with
`--discard-test-history discard-test-history`,
`--fresh-test-store-attestation`, and its sealed SHA-256; it enters `sealed`
without producing prior-history evidence.

Activation is evidence-gated. It requires:

- immutable release verification and rendered topology validation;
- root-owned protected profiles reconstructed from current authority evidence;
- a generation-bound capability policy covering every enrolled repository;
- sealed credential and filesystem preflight;
- a current Test Store schema-readiness attestation;
- verified candidate health and socket-listener continuity;
- an executable rollback to the exact prior publication and service graph.

Rollback is failed-deployment recovery only: it atomically restores the exact
prior publication after an unsuccessful activation. It never makes the prior
and current manifest, MCP, or caller contracts concurrently callable or
negotiable.

The live host gate is produced only by the candidate release's immutable
`bin/devcoordinator-test-preflight` wrapper. Activation invokes that wrapper;
it does not accept an operator-authored JSON substitute. The sealed
attestation binds the canonical release root and digest, the exact preflight
script and `/usr/bin/python3` hashes, the current host boot ID, observation
time, systemd version, and the successful `LoadCredential`, private-loopback,
host-loopback, non-loopback-denial, private-to-host-denial, and
shared-network-namespace probes. Activation recomputes the document seal,
hashes the current candidate files, rejects another release or boot, and
allows at most five minutes between observation and use.

Console/API code uses start-verify-switch-drain. Same-schema broker code uses
socket-preserving replacement. Test, observer, notification,
and their databases replace locally. Only an authority transaction uses the
global mutation fence.

## Acceptance contract

Readiness requires focused and full tests for manifest fuzzing, source
selection, live supersession, immutable provenance, fairness, sharding,
deduplication, cancellation, timeouts, lost heartbeats, spool replay, reporter
integration, secret leakage, cross-UID authorization, stale-generation reuse,
artifact substitution, fresh-store interruption, and rollback.

Fault and load gates must prove that project/test fork bombs, OOMs, crash
loops, malformed output, slow upstreams, and request bursts cannot restart,
starve, banner, or clear another project or control-plane view. Continuous
probes across replacement must observe no project-route failure and no
`ECONNREFUSED`.

Performance gates are cached Console/Test API TTFB below 100 ms, retained shell
and Tests LCP below one second, warm planning below 300 ms, submission
acknowledgement below 100 ms, control-plane p99 below 100 ms under maximum
ingestion, and the 8 KiB agent summary bound.

Deterministic source-local gates exercise 40-sample p99 budgets for a warm
repository plan preview, ordinary asynchronous submission acknowledgement,
the cached Console overview and 50-repository Tests fleet handlers, and the
authenticated test-plane health read while 500-case result chunks are being
committed. These tests prove local handler/storage regressions, not public
network latency. Browser LCP, live-server TTFB, and the five-second operator
comprehension outcome remain deployment/browser acceptance evidence and must
not be inferred from the source benchmarks.
