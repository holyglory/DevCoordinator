# Availability foundation

These templates define the target host boundary in which project work cannot
restart, starve, or replace the DevCoordinator control plane. They are staged
architecture artifacts, not the currently installed production units. The
installer may render and install them only after each referenced executable
supports the declared socket-activation and readiness contract.

The topology follows the
[single-developer local trust model](single-developer-local-trust.md). Dedicated
service accounts and slices isolate failures and resources; UID/GID, modes,
ACLs, socket ownership, and shared groups never authorize local communication.

## Failure domains

- `devcoordinator-edge.service` is the stable public boundary. PID 1 owns its
  port 80 and 443 sockets, so Console, API, authority, observer, test scheduler,
  and project changes cannot remove the public listeners. The edge consumes an
  atomic last-known-good route/access publication; it never performs live host
  observation in a request path.
- Edge, API, authority, and Console slots run in
  `devcoordinator-control.slice`. Observer, notification delivery, and test
  scheduler run in the lower priority `devcoordinator-background.slice`.
  Telegram state, polling, and delivery belong only to the dedicated
  `devcoordinator-notifications` identity; Console uses bounded authenticated
  Unix IPC and remains healthy when that worker is absent. Managed project processes,
  container scopes, and project-owned fixtures are placed below
  `devcoordinator-projects.slice`. Ordinary test attempts use accounting-only
  per-UID/per-repository leaves below `devcoordinator-tests.slice`, outside the
  background daemon hierarchy. The leaves record CPU, memory, I/O, and tasks
  and provide exact cancellation/cleanup scope, but impose no CPU, memory, PID,
  task, or job quota.
- Each control/background role has a dedicated service account. Project users
  do not share the UID that owns OIDC state, access grants, route credentials,
  test results, inventory projections, or API configuration.
- The authority and loopback API sockets are owned by systemd and have
  `RemoveOnStop=no`. A code replacement drains the old daemon while the stable
  listener queues bounded new work. Clients must not observe `ECONNREFUSED`.

## Immutable releases

`RELEASE_DIGEST` is a required installer substitution. It must be replaced by
one validated content digest; Console slot `%i` must be that same digest syntax.
The rendered executable must resolve beneath
`/opt/devcoordinator/releases/<digest>/`, and every component of that release
tree is root-owned and non-writable by service and project users. Production
units never execute from `<mutable-repository-checkout>`, an installed skill
symlink, or an `active`/`current` source pointer.

Installing a new release consists of writing and verifying a new immutable
directory, starting the candidate service or Console slot, proving readiness,
switching the relevant publication/socket consumer, and draining the old
process. It never checks out another Git ref in the canonical repository.

The first notification split is an explicit fenced handoff, not a startup
migration. Keep the new notification unit stopped, switch the candidate Console
to IPC, stop the legacy Console writer, atomically copy and validate the final
`telegram-control.json` under the notification UID, start the notification
worker, and only then clear maintenance. The worker unit is conditioned on the
new state file so it cannot create an empty competing writer before that
handoff. During the short gap Telegram endpoints return typed local
unavailability; Console, Board, project routes, and unrelated APIs stay up.

The immutable edge owns Google OIDC, session issuance, TLS termination, and
route authorization. Activation requires private root-owned OIDC client ID,
OIDC client secret, and session-secret files plus a successful issuer metadata
preflight. Console backend replacement therefore cannot remove authentication
or project routing.

## Schema boundary

Startup may perform only a read-only schema/profile compatibility check. A
daemon must refuse readiness on an unsupported schema and must never create a
table, backfill a row, or advance schema metadata from `ExecStartPre` or
`ExecStart`.

Authority schema work is an explicit administrator transaction: rehearse and
verify the backup, activate the broker-independent maintenance marker, drain
admissions, stop only the authority writer, take the writer-free checkpoint,
apply and verify the migration, restart the compatible authority, then clear
the exact marker. Edge, Console shell, API listener, and project runtimes remain
available. Inventory or test database migrations fence only their own
background subsystem.

The final storage boundary is explicit and single-writer:

| Store | Production path | Owner | Contents |
| --- | --- | --- | --- |
| Authority | `/var/lib/devcoordinator/authority.sqlite3` | `root` / authority | identity, grants, policy, active lifecycle state, and bounded referenced evidence only |
| Inventory | `/var/lib/devcoordinator-observer/inventory.sqlite3` | `devcoordinator-observer` | bounded retained observer generations; its sibling `inventory.publication` is the Console/API read projection |
| Tests | `/var/lib/devcoordinator-testd/tests.sqlite3` | `devcoordinator-testd` | runs, attempts, cases, failures, artifacts, events, and rollups |
| Console access | `/var/lib/devcoordinator-console/access-control.json` | `devcoordinator-console` | Google-account grants, invite requests, and Console-scoped access state |

First adoption never clones the legacy SQLite file. With the legacy writer
fenced, the logical splitter measures the selected authority rows, rejects
insufficient capacity, copies only the fail-closed authority allowlist, creates
empty legacy test tables in authority, seeds the observer store, and seals exact
row-count, logical-digest, file-digest, owner, and generation evidence. The
legacy database remains unchanged and read-only as the rollback source. Both
new store directories are fsynced before the split attestation is published;
activation refuses missing or drifting evidence.

All authority transactions enforce retention caps on telemetry, observation
snapshots, lifecycle proofs, worker history, and events. High-volume test and
inventory writes are accepted only by their dedicated service-owned stores, so
normal observation and test traffic cannot regrow the authority database.

## Installation gate

Before rendering units, run:

```bash
python3 scripts/check_availability_topology.py --json
python3 scripts/self_test_check_availability_topology.py
```

The static checker requires dedicated identities and slices, stable socket
ownership, immutable release executables, no startup migration command, and no
control-to-project dependency. Candidate activation then proves the rendered
digest, loaded fragment path, service UID, cgroup, socket inode, release
ownership, and readiness before it can publish the release.

Host-specific memory ceilings are not hard-coded into the portable templates.
The immutable renderer derives byte-exact control, background, and project
budgets from `/proc/meminfo`, retains explicit operating-system and protected
control reserves, and proves that aggregate maximums do not overcommit the
host. The loaded-unit gate rejects percentages, unresolved placeholders,
reversed high/max bounds, and an unbounded project hierarchy. Ordinary test
attempts are deliberately excluded from those fixed budgets: testd admits them
from current `/proc/meminfo` `MemAvailable` after the control reserve and a
learned per-target memory peak. CPU and task counts are accounting data only and
never admission inputs. The topology gate rejects any CPU, memory, PID, task,
weight, or fixed-job control on `devcoordinator-tests.slice` or testd.

## Clean schema-12 bridge successor

A ready schema-12 bridge whose original release root is contaminated is
replaced only through the immutable `successor-apply` primitive exposed by
`devcoordinator-schema12-bridge`. The candidate is staged under a different,
root-owned release root; sharing or cleaning the predecessor release root is
rejected even when both clean trees have the same content digest. The outer
transaction binds the exact historical broker release and the separate exact
current client release. The historical client proves the predecessor before
any mutation. After replacement, the current client performs strict profile
parsing and the exact GlobalFinance inventory canary against the unchanged
schema-12 server protocol.

The transaction uses the shared server-wide installer fence and sealed,
root-private journals. It consumes the exact still-active maintenance marker
and predecessor proof produced by the authority lifecycle recovery; it never
creates, replaces, or silently reactivates that marker. It seals and stops the
exact predecessor invocation, removes only its recorded drop-in, validates
the complete sealed repository-owner map against the stopped schema-12
database, and exports every active client enrollment into a new profile.
Legacy profile bytes are backed up but never merged. Every repository owner is
copied from the sealed map, every resource grant is copied from authority, and
every client entry must pass the current immutable parser before atomic
publication. The clean schema-12 broker then starts with current-client
inventory canaries for both the GlobalFinance owner and enrolled collaborator,
receives a strict stable process/socket/drop-in/inventory proof, and publishes
a clear-intent terminal. Maintenance is cleared last; a separate immutable
completion is published only after a fresh post-clear multi-account inventory
proof. Every replay rechecks the live successor even when the marker is already
absent.

Every effect has a preceding durable intent. Replaying `successor-apply` after
process loss converges without duplicating the bridge or rewriting the
historical journal. An inherited successor is forward-only: `successor-abort`
is rejected because restoring the owner-less legacy profile would make current
clients invalid while clearing the shared marker. Replay either completes the
strict successor or leaves maintenance active. Existing bridge journals and
backups are never deleted.

A successor that has already retired its predecessor but must retain a
historical journal-bound client is not admitted through `successor-apply`.
Only `successor-executor-rescue` may resume that exact pre-export boundary. It
requires the inherited raw and sealed journal digests plus the exact previous
executor, retained client, and new immutable executor identities; it preserves
the sole client handoff, seals one singular `executor_rescue`, and carries that
lineage through candidate, canary, terminal, and completion evidence. A second
rescue, another client handoff, or ordinary historical-client activation is
always rejected.

The immutable release also exposes `devcoordinator-maintenance`; it is the only
standalone interface for the fixed typed maintenance contract. Direct marker
editing is not supported.

## First-deployment and cutover runbook

The first deployment has one fixed two-phase transaction: prepare all five
listener ports under one stopped-writer fence, re-attest the resulting exact
ready authority without SQL or service mutation, render and bootstrap from
that exact prepared document, initialize the cutover ledger, then finalize the
transaction. Preparation leaves the exact maintenance marker active and the
legacy broker stopped. The re-attestation consumes that prepared quiescence
seal and writes only a root-private intent and result. Finalization publishes
the compatible port document and swaps the ledger while maintenance is still
active, restores the broker, clears maintenance last, and only then publishes
the terminal result. Do not invoke the standalone readiness-rebind and port-
reservation wrappers back to back for first deployment; a broker write between
them makes the ledger contract unsatisfiable by design.

An older populated schema-12 authority can legitimately still carry
`migration_state=empty`. Recover that one metadata fence only through the
immutable readiness wrapper. This resumable transaction publishes the exact
server-wide maintenance marker, stops only the legacy broker, acquires its
private lifetime lock, performs the repair, restores the broker baseline, and
clears its own marker. Clients receive the fixed maintenance/retry response
throughout; no direct `systemctl` or SQL step is part of the runbook. The
wrapper takes a WAL-aware verified backup, seals its exact
schema/generation/revision and population invariants in a durable intent, then
performs one conditional transaction. Replaying after either intent
publication or commit is safe:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-authority-readiness \
  --release /opt/devcoordinator/releases/<digest> \
  --database <legacy-authority-database> \
  --backup /var/lib/devcoordinator/cutover/authority-readiness/authority.sqlite3 \
  --backup-attestation /var/lib/devcoordinator/cutover/authority-readiness/backup.json \
  --journal /var/lib/devcoordinator/cutover/authority-readiness/intent.json \
  --attestation /var/lib/devcoordinator/cutover/authority-readiness/result.json \
  --transaction-journal /var/lib/devcoordinator/cutover/authority-readiness/service-intent.json \
  --transaction-attestation /var/lib/devcoordinator/cutover/authority-readiness/service-result.json \
  --maintenance-root /run/devcoordinator-maintenance \
  --maintenance-gid <devcoordinator-clients-gid> \
  --maintenance-deployment-id UUID \
  --operation-id UUID
```

If that readiness seal was produced by an earlier immutable release, never
edit or copy it into the new release. The atomic preparation below performs
the read-only rebind and port reservation while holding the same broker
lifetime lock. A broker write before that lock is accepted only when the
database device/inode, schema-12 generation, ready migration state, SQLite
authority mode, creation timestamp, and first-mutation timestamp remain fixed;
state and observation revisions and `updated_at` must be monotonic, and every
population/integrity invariant must still pass. The fenced descendant, not the
preliminary snapshot, is published in the new release-bound seal. Preserve the
prior seal and backup as immutable lineage. A direct SQL update or hand-edited
seal is never supported.

When an installed schema-13 entry point prevents the still-schema-12 authority
from starting, the immutable schema-12 bridge is the only supported temporary
writer. Its release is reconstructed from one exact Git object, its systemd
drop-in and active invocation are sealed, and owner-scoped inventory canaries
must pass before first adoption may reference it. A fresh bridge transaction
may inherit a newer ready authority descendant only from an exact root-private
predecessor journal: the raw file digest and sealed document digest must both
match a version-2 failure that reached durable systemd readiness and failed
only during canaries, cleanup must prove the service inactive and the owned
drop-in absent, and the database must remain a safe descendant of the original
readiness seal. The new transaction records that predecessor evidence while
allowing a corrected canary set; unrelated failures never authorize lineage.

First adoption then owns the writer handoff. It publishes the permanent
retirement guard while the bridge is still healthy, performs the storage
split, disables the legacy unit and removes only the exactly sealed bridge
drop-in before schema-13 authority starts, and retains the guard after success.
Rollback writes the exact bridge drop-in while that guard still blocks starts,
restores the schema-12 authority bytes, removes the guard immediately before
restoring the legacy unit, proves the resulting invocation and socket, and
clears global maintenance last. Each mutation has a sealed intent so a process
loss cannot expose the mutable checkout or an unfenced legacy writer.

Before preparation, prove the canonical repository-backed skill links for
every enrolled account with `manage_skill_links.py verify`, naming all Codex
and Claude target roots explicitly. Prove the transitional broker, protected
profile, drop-in, socket, database generation, and owner-scoped GlobalFinance
inventory with the immutable clean bridge's `verify-ready` command and its
exact transaction/journal digests. The ordinary server-wide installer
`verify` command deliberately rejects the temporary
`95-schema12-cutover-bridge.conf` drop-in and is therefore not the transition
gate while that exact sealed bridge is active; run it again after the bridge
is retired. A stale client profile, a missing skill link, an overlapping
installer transaction, or `broker_profile_invalid` blocks preparation; do not
repair a drop-in or installed copy by hand.

Prepare the release-bound readiness seal, two persistent Console ports, and
three positive-TTL handoff ports with one operation ID. The pending path is
mechanical: for final path `first-adoption-ports.json`, it must be
`.first-adoption-ports.json.<operation-id>.pending` in the same directory. The
repository ID and generation must be the exact active, unfenced Coordinator
repository record:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-first-adoption-bindings \
  prepare-first-adoption-bindings \
  --release /opt/devcoordinator/releases/<digest> \
  --database <legacy-authority-database> \
  --prior-attestation /var/lib/devcoordinator/cutover/authority-readiness/result.json \
  --readiness-attestation /var/lib/devcoordinator/cutover/authority-readiness/rebound.json \
  --project-root <canonical-coordinator-project-root> \
  --repository-id <coordinator-repository-id> \
  --repository-generation <coordinator-repository-generation> \
  --handoff-ttl-seconds 3600 \
  --port-journal /var/lib/devcoordinator/cutover/first-adoption-ports-intent.json \
  --prepared-attestation /var/lib/devcoordinator/cutover/.first-adoption-ports.json.<operation-id>.pending \
  --port-attestation /var/lib/devcoordinator/cutover/first-adoption-ports.json \
  --transaction-journal /var/lib/devcoordinator/cutover/first-adoption-bindings-intent.json \
  --transaction-attestation /var/lib/devcoordinator/cutover/first-adoption-bindings-result.json \
  --bridge-transaction <root-private-ready-bridge-transaction> \
  --bridge-operation-id <ready-bridge-operation-id> \
  --bridge-journal-sha256 <ready-bridge-raw-sha256> \
  --bridge-journal-document-sha256 <ready-bridge-document-sha256> \
  --bridge-profile /etc/devcoordinator/client-profiles.json \
  --bridge-socket /run/devcoordinator/broker.sock \
  --bridge-dropin /etc/systemd/system/devcoordinator-broker.service.d/95-schema12-cutover-bridge.conf \
  --bridge-canary-user <global-finance-owner-account> \
  --bridge-canary-owner-uid <global-finance-owner-uid> \
  --bridge-canary-project <canonical-global-finance-project-root> \
  --bridge-canary-repository-id <global-finance-repository-id> \
  --bridge-canary-repository-generation <global-finance-repository-generation> \
  --post-start-attestation /var/lib/devcoordinator/cutover/.first-adoption-bindings-result.json.<operation-id>.post-start-ready \
  --maintenance-root /run/devcoordinator-maintenance \
  --maintenance-gid <devcoordinator-clients-gid> \
  --maintenance-deployment-id UUID \
  --operation-id UUID \
  --authority-uid 0
```

The Coordinator repository in `--project-root` owns the five first-adoption
leases. The GlobalFinance repository in the `--bridge-canary-*` arguments is a
deliberately distinct availability canary: its exact owner UID, repository ID,
canonical root, generation, protected profile enrollment, authority socket,
and sole project-scoped inventory row must all agree. Never substitute one
role for the other.

Preparation publishes its intent before maintenance or service mutation,
advances the authority state revision exactly once for all five leases, and
leaves the legacy broker stopped with the exact root-owned marker active.
Supported CLI/API clients check that marker before touching the absent Unix
socket and therefore receive typed `maintenance_in_progress`, not
`ECONNREFUSED`. Do not start `devcoordinator-authority.socket` or the schema-13
authority during this prepared interval.

Retain the sealed `document_sha256` of the root-owned mode-0600 prepared
attestation. While that exact maintenance marker and stopped-writer fence
remain active, bind the post-reservation schema-12 image to the new immutable
release. This wrapper does not activate or clear maintenance, start or stop a
service, or execute migration/repair/write SQL. It acquires the already
established broker lifetime lock, reads SQLite through a retained no-follow
descriptor with `mode=ro&immutable=1`, verifies the original readiness result
and retained backup, and requires exact pre/post device, inode, digest,
generation, revisions, schema, ready state, and population/integrity
invariants. Replay is accepted only while the database and every referenced
seal remain byte-for-byte and semantically exact:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-authority-readiness-reattest \
  --release /opt/devcoordinator/releases/<digest> \
  --database <legacy-authority-database> \
  --prior-attestation /var/lib/devcoordinator/cutover/authority-readiness/result.json \
  --quiescence-attestation /var/lib/devcoordinator/cutover/.first-adoption-ports.json.<operation-id>.pending \
  --quiescence-attestation-sha256 <prepared-port-reservations-document-sha256> \
  --journal /var/lib/devcoordinator/cutover/authority-readiness/reattest-intent.json \
  --attestation /var/lib/devcoordinator/cutover/authority-readiness/reattested.json \
  --maintenance-root /run/devcoordinator-maintenance \
  --maintenance-gid <devcoordinator-clients-gid> \
  --maintenance-deployment-id <same-preparation-maintenance-uuid> \
  --operation-id <same-first-adoption-operation-uuid> \
  --authority-uid 0
```

Invoke the immutable release installer's `render-units` and
`render-console-slot` actions with the same `--port-reservations` path and the
sealed document digest as
`--port-reservations-sha256`. Render the topology to
`/run/devcoordinator/cutover/units` and the slot to
`/var/lib/devcoordinator-console/slots/<digest>.env`. The renderer revalidates
the stopped-broker maintenance fence and rejects
another release, changed inode/content, duplicate ports, expired handoff
leases, or any role set other than `console_outer`, `console_inner`,
`handoff_http`, `handoff_https`, and `handoff_api`.

The replay-safe bootstrap then installs only the declared system
identities/tmpfiles paths, creates the private Test Store under its dedicated
UID, and seals the exact schema branch. It does not start a service, split
authority data, or publish a route:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-cutover \
  bootstrap-first-deployment \
  --release /opt/devcoordinator/releases/<digest> \
  --rendered-units /run/devcoordinator/cutover/units \
  --authority-database /var/lib/devcoordinator/authority.sqlite3 \
  --inventory-database /var/lib/devcoordinator-observer/inventory.sqlite3 \
  --test-database /var/lib/devcoordinator-testd/tests.sqlite3 \
  --schema-attestation /var/lib/devcoordinator-testd/schema-readiness.json \
  --output /var/lib/devcoordinator/cutover/bootstrap.json \
  --operation-id UUID
```

The immutable Test Store helper records `schema_readiness_v5` for a newly
created schema-5 store. Test history is disposable: an older test database is
replaced through the explicit fresh-store initializer rather than migrated or
preserved. Authority, Console settings, inventory, and project data are outside
that discard boundary.

Initialize first with `--dry-run`, then replay the identical arguments without
that flag to publish the ledger. Initialization binds the bootstrap,
release-bound readiness seal, rendered topology, and port-reservation bundle.
The only permitted difference from the readiness snapshot is the reservation
transaction's exact one-revision advance; any other generation, metadata,
identity, digest, row, event, lease, or revision drift fails closed:

Test history is disposable by default. With explicit authorization, keep testd
offline and initialize its one private store before bootstrap/init:

```bash
sudo -n -H -u devcoordinator-testd \
  /opt/devcoordinator/releases/<digest>/bin/devcoordinator-test-history \
  testd-initialize-fresh \
  --test-database /var/lib/devcoordinator-testd/tests.sqlite3 \
  --operation-id <canonical-operation-uuid> \
  --attestation-output /var/lib/devcoordinator-testd/schema-readiness-<canonical-operation-uuid>.json \
  --expected-test-uid <devcoordinator-testd-uid> \
  --confirm-discard-test-history discard-test-history
```

Append these exact arguments to both the dry-run and persistent `init` calls:

```text
--discard-test-history discard-test-history
--fresh-test-store-attestation /var/lib/devcoordinator-testd/schema-readiness-<canonical-operation-uuid>.json
--fresh-test-store-attestation-sha256 <fresh-readiness-document-sha256>
```

The ledger verifies the operation-specific sibling path, digest, database,
schema-5 generation, bootstrap generation, and authority readiness, then
starts directly in `sealed`. Do not run test backup, capture, drain, export,
import, or history-seal commands on this branch. Authority backup/readiness
and profile reconstruction remain unchanged. First availability still
requires the dogfood manifest and complete read-only fleet census, but does
not repair or adopt unrelated repositories.

Only when the user explicitly requests history retention does the split
test-history exporter write into directories created by the testd identity.
Prepare both recipient lanes with the immutable release; do not create or chown
them with ad-hoc cutover shell commands:

```bash
sudo -n -H -u devcoordinator-testd \
  /opt/devcoordinator/releases/<digest>/bin/devcoordinator-test-history \
  testd-prepare-package-directories \
  --package-root /var/lib/devcoordinator-testd/history-migration-<operation-id> \
  --operation-id <canonical-operation-uuid> \
  --expected-test-uid <devcoordinator-testd-uid>
```

The command is crash-resumable, creates `initial` and `final` as mode-0700
testd-owned directories, and seals their exact paths in
`package-directories.json`. Authority capture/finalize must consume those two
reported paths. An existing preparation may replay only for the same operation
and directory binding.

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-cutover \
  init \
  --state /var/lib/devcoordinator/cutover/state.json \
  --release /opt/devcoordinator/releases/<digest> \
  --rendered-units /run/devcoordinator/cutover/units \
  --legacy-authority-database <legacy-authority-database> \
  --authority-database /var/lib/devcoordinator/authority.sqlite3 \
  --test-database /var/lib/devcoordinator-testd/tests.sqlite3 \
  --inventory-canary-project <owner-scoped-inventory-canary-project> \
  --authority-backup-directory /var/lib/devcoordinator/cutover/authority-backup \
  --test-backup-directory /var/lib/devcoordinator/cutover/test-backup \
  --migration-state /var/lib/devcoordinator/cutover/test-history-migration.json \
  --drain-proof /var/lib/devcoordinator/cutover/drain.json \
  --cutover-seal /var/lib/devcoordinator/cutover/test-history-seal.json \
  --first-deployment-bootstrap /var/lib/devcoordinator/cutover/bootstrap.json \
  --authority-readiness /var/lib/devcoordinator/cutover/authority-readiness/reattested.json \
  --first-adoption-port-reservations /var/lib/devcoordinator/cutover/.first-adoption-ports.json.<operation-id>.pending \
  --first-adoption-port-reservations-sha256 <prepared-port-reservations-document-sha256> \
  --authority-uid 0 \
  --testd-uid <devcoordinator-testd-uid> \
  --retain-until <UTC-rollback-retention-timestamp> \
  --authority-transaction-required \
  --dry-run
```

The prepared bundle path and sealed digest are cutover evidence, not disposable
renderer inputs. The long
`--first-adoption-port-reservations-sha256` initialization flag binds the same
sealed `document_sha256`. Preserve the pair through activation and rollback;
the first-adoption request uses it too, and post-split verification proves the
exact lease rows were copied into the final schema-13 authority.

After the non-dry-run `init` has durably published the planned ledger, finalize
the exact transaction. Finalization rejects an unrelated ledger generation or
digest. It publishes the existing compatible final-port schema and swaps that
document into the ledger before restoring the broker. Maintenance is cleared
last; a crash after the state swap, broker start, or marker clear replays from
the finalization journal without duplicating leases or reopening a mutation
window:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-first-adoption-bindings \
  finalize-first-adoption-bindings \
  --state /var/lib/devcoordinator/cutover/state.json \
  --transaction-journal /var/lib/devcoordinator/cutover/first-adoption-bindings-intent.json \
  --transaction-attestation /var/lib/devcoordinator/cutover/first-adoption-bindings-result.json \
  --successor-terminal-attestation /var/lib/devcoordinator/cutover/first-adoption-installation-hard-gate.json \
  --operation-id <same-first-adoption-operation-uuid> \
  --authority-uid 0
```

Successful binding finalization atomically transfers the durable server-wide
installer claim to the schema-13 first-adoption executor; it does not clear the
claim. The first-adoption command resumes that exact successor with
`--binding-attestation`, `--operation-id`, and `--hard-gate-attestation`.
After first adoption completes, the claim is released only by the explicit
installed-state gate:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-availability-activate \
  finalize-first-adoption-installation \
  --binding-attestation /var/lib/devcoordinator/cutover/first-adoption-bindings-result.json \
  --operation-id <same-first-adoption-operation-uuid> \
  --first-adoption-attestation /var/lib/devcoordinator/cutover/first-adoption.json \
  --release /opt/devcoordinator/releases/<digest> \
  --hard-gate-attestation /var/lib/devcoordinator/cutover/first-adoption-installation-hard-gate.json \
  --canonical-project <canonical-global-finance-project-root> \
  --canonical-repository-id <global-finance-repository-id> \
  --owner-user <global-finance-owner-user> \
  --collaborator-user <global-finance-collaborator-user> \
  --expected-uid 0
```

The terminal gate is root-owned mode `0600`. It verifies the loaded final
control-plane units, retired schema-12 broker, root-owned mode `0640` strict
all-client profile, canonical Codex and Claude skill links for the declared
owner and collaborator, and an immutable-client owner-scoped inventory read
for `<canonical-global-finance-project-root>` with repository ID
`<global-finance-repository-id>`, scope `server-wide`, and transport
`authenticated-unix-socket`. The four canonical hard-gate arguments are
sealed into the terminal attestation; changing any one on replay is rejected.
Any failed check retains the successor claim.

If initialization cannot be completed, abort is permitted only while the
ledger path is absent and finalization has not started. It deletes only the
five operation-bound lease/event rows, restores the exact readiness revision,
then restores the broker and clears maintenance. Replaying after the rollback
commit is safe:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-first-adoption-bindings \
  abort-first-adoption-bindings \
  --state /var/lib/devcoordinator/cutover/state.json \
  --transaction-journal /var/lib/devcoordinator/cutover/first-adoption-bindings-intent.json \
  --transaction-attestation /var/lib/devcoordinator/cutover/first-adoption-bindings-result.json \
  --operation-id <same-first-adoption-operation-uuid> \
  --authority-uid 0
```

If the retained schema-12 source contains the historically bogus `/tmp`
repository, prepare its exact no-write repair plan, then let the immutable
service transaction own the maintenance marker and broker drain. It stops only
the legacy broker, applies the already-sealed exact-ID repair under the broker
writer lock, restores the recorded active/enabled baseline, and clears only its
own marker. Restoration is not inferred from `systemctl is-active`: the
transaction requires one stable root-owned broker socket, the complete
schema-12 semantic-invariant set, and an owner-scoped authenticated inventory
canary. It reactivates the same maintenance marker if the canary fails after
normal broker traffic is temporarily enabled. The terminal result is published
only after all three proofs pass. Replaying the same operation and deployment
IDs reruns authenticated readiness without repeating the repair:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-cutover \
  plan-authority-repository-disable \
  --authority-database <legacy-authority-database> \
  --repository-id <exact-shared-tmp-repository-id> \
  --plan /var/lib/devcoordinator/cutover/tmp-repair-plan.json

/opt/devcoordinator/releases/<digest>/bin/devcoordinator-authority-repository-repair \
  --release /opt/devcoordinator/releases/<digest> \
  --plan /var/lib/devcoordinator/cutover/tmp-repair-plan.json \
  --plan-document-sha256 <sealed-plan-document-sha256> \
  --attestation /var/lib/devcoordinator/cutover/tmp-repair-result.json \
  --transaction-journal /var/lib/devcoordinator/cutover/tmp-repair-service-intent.json \
  --transaction-attestation /var/lib/devcoordinator/cutover/tmp-repair-service-result.json \
  --maintenance-root /run/devcoordinator-maintenance \
  --maintenance-gid <devcoordinator-clients-gid> \
  --maintenance-deployment-id UUID \
  --operation-id UUID \
  --broker-socket /run/devcoordinator/broker.sock \
  --canary-user <enrolled-canary-account> \
  --canary-uid <enrolled-canary-uid> \
  --canary-project <canonical-canary-project-root> \
  --canary-repository-id <canary-repository-id> \
  --canary-repository-generation <canary-repository-generation>
```

An older repair result can predate the startup-policy batch contract. If that
historical transaction already left the exact `/tmp` repository
`missing`/`disabled`/startup-fenced while its logical `coordinator` or `compose`
policy rows remained enabled, do not restart the crash-looping broker and do
not edit SQLite manually. Keep the exact maintenance marker active and the
broker stopped. Bind both the original repair plan and result by their sealed
digests, produce the no-write reconciliation plan, review its complete bounded
policy list, then apply it under the same broker lifetime lock:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-authority-repository-policy-reconciliation \
  plan-authority-repository-startup-policy-reconciliation \
  --source-repair-plan /var/lib/devcoordinator/cutover/tmp-repair-plan.json \
  --source-repair-plan-document-sha256 <original-repair-plan-document-sha256> \
  --source-repair-attestation /var/lib/devcoordinator/cutover/tmp-repair-result.json \
  --source-repair-attestation-document-sha256 <original-repair-result-document-sha256> \
  --plan /var/lib/devcoordinator/cutover/tmp-policy-reconciliation-plan.json

/opt/devcoordinator/releases/<digest>/bin/devcoordinator-authority-repository-policy-reconciliation \
  apply-authority-repository-startup-policy-reconciliation \
  --plan /var/lib/devcoordinator/cutover/tmp-policy-reconciliation-plan.json \
  --plan-document-sha256 <policy-reconciliation-plan-document-sha256> \
  --attestation /var/lib/devcoordinator/cutover/tmp-policy-reconciliation-result.json \
  --maintenance-root /run/devcoordinator-maintenance \
  --maintenance-gid <devcoordinator-clients-gid> \
  --maintenance-deployment-id <active-maintenance-deployment-uuid>
```

The plan enumerates every exact policy identity, kind, current/disabled value,
immutable fingerprint, generation, timestamp, and retained restore-state
record. Apply rejects missing, extra, adjacent, or drifted rows, changes only
the planned logical values with per-row compare-and-swap, holds both the broker
lifetime lock and the canonical maintenance-marker writer lock through the
commit, advances the authority revision once, leaves captured restore semantics
byte-for-byte unchanged, and seals replay evidence. Native Docker or supervisor
policy rows remain blocked until their underlying lifecycle absence is proved;
changing only their database values would invent a host mutation. After
reconciliation, do not use generic `activate` or `successor-apply` when the
retained predecessor journal is already schema-v3 `restored`: generic
activation requires the original exact readiness revision, while the generic
successor correctly requires a live `ready` predecessor. Use the dedicated
restored-policy transaction instead. It requires raw-file and sealed-document
digests for the original repair plan/result, policy plan/result, original
readiness, and restored predecessor journal. It accepts only the exact
one-revision post-CAS descendant, a distinct clean root with the predecessor's
exact release digest, the complete owner map, the stopped-writer and
maintenance locks, and owner plus collaborator canaries.

The clean broker starts while the inherited maintenance marker is still
active. Before clear, the transaction binds systemd InvocationID/MainPID to the
actual socket peer PID, immutable argv/source/database/drop-in, the strict
owner-bound profile, database SHA/inode/generation/revision, and the complete
schema-12 invariant contract. It then clears maintenance and runs exact
current-client inventory canaries. Any failure first re-arms the same marker,
then restores only the candidate invocation/drop-in and captured profile while
reproving the unchanged CAS and historical predecessor bytes. Ambiguous cleanup
is sealed `recovery-required` and remains fenced.

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-schema12-bridge \
  recover-policy-reconciled-restored \
  --candidate-release /opt/devcoordinator-legacy-broker-clean/releases/<schema12-digest> \
  --release-root /opt/devcoordinator-legacy-broker-clean/releases \
  --client-release /opt/devcoordinator/releases/<digest> \
  --transaction-dir /var/lib/devcoordinator/cutover/schema12-policy-recovery-<operation> \
  --operation-id <fresh-operation-uuid> \
  --predecessor-transaction /var/lib/devcoordinator/cutover/<restored-bridge-transaction> \
  --predecessor-operation-id <restored-bridge-operation-uuid> \
  --predecessor-journal-raw-sha256 <restored-journal-file-sha256> \
  --predecessor-journal-document-sha256 <restored-journal-document-sha256> \
  --failed-installer-transaction /var/lib/devcoordinator-installs/<failed-install-transaction> \
  --failed-installer-operation-id <failed-installer-activation-uuid> \
  --readiness-attestation /var/lib/devcoordinator/cutover/authority-readiness/result.json \
  --readiness-raw-sha256 <original-readiness-file-sha256> \
  --readiness-document-sha256 <original-readiness-document-sha256> \
  --source-repair-plan /var/lib/devcoordinator/cutover/tmp-repair-plan.json \
  --source-repair-plan-raw-sha256 <original-repair-plan-file-sha256> \
  --source-repair-plan-document-sha256 <original-repair-plan-document-sha256> \
  --source-repair-result /var/lib/devcoordinator/cutover/tmp-repair-result.json \
  --source-repair-result-raw-sha256 <original-repair-result-file-sha256> \
  --source-repair-result-document-sha256 <original-repair-result-document-sha256> \
  --policy-plan /var/lib/devcoordinator/cutover/tmp-policy-reconciliation-plan.json \
  --policy-plan-raw-sha256 <policy-plan-file-sha256> \
  --policy-plan-document-sha256 <policy-plan-document-sha256> \
  --policy-result /var/lib/devcoordinator/cutover/tmp-policy-reconciliation-result.json \
  --policy-result-raw-sha256 <policy-result-file-sha256> \
  --policy-result-document-sha256 <policy-result-document-sha256> \
  --database /var/lib/devcoordinator/coordinator.sqlite3 \
  --profile /etc/devcoordinator/client-profiles.json \
  --owner-map /var/lib/devcoordinator/cutover/repository-owner-map.json \
  --owner-map-sha256 <owner-map-file-sha256> \
  --socket /run/devcoordinator/broker.sock \
  --dropin /etc/systemd/system/devcoordinator-broker.service.d/95-schema12-cutover-bridge.conf \
  --maintenance-root /run/devcoordinator-maintenance \
  --maintenance-gid <devcoordinator-clients-gid> \
  --maintenance-deployment-id <policy-result-maintenance-uuid> \
  --canary-user <GlobalFinance-owner-account> \
  --expected-canary-uid <GlobalFinance-owner-uid> \
  --canary-project /home/<owner>/GlobalFinance \
  --canary-repository-id <GlobalFinance-repository-id> \
  --canary-repository-generation <GlobalFinance-generation> \
  --additional-canary <enrolled-collaborator>=<collaborator-uid>
```

Replay only the same operation and exact arguments. A committed replay reruns
the strong live proof. An aborted replay requires the same marker, unchanged
CAS/database and historical files, restored profile, absent candidate service,
and sealed restored candidate journal. Preserve the contaminated predecessor
release and crash journal as evidence.

Prepare the complete schema-13 repository execution-owner map only through the
same verified release. Repeat `--owner` for every repository in the legacy
authority database; missing, duplicate, stale-generation, or extra assignments
fail closed. The wrapper fixes the isolated Python interpreter and exact
release script, while the database and map owner arguments bind both inputs to
their expected service identities:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-repository-owner-authority \
  census \
  --database <legacy-authority-database> \
  --expected-database-owner-uid <authority-uid>

/opt/devcoordinator/releases/<digest>/bin/devcoordinator-repository-owner-authority \
  prepare \
  --database <legacy-authority-database> \
  --expected-database-owner-uid <authority-uid> \
  --owner <repository-id>=<repository-owner-uid> \
  --operation-id UUID \
  --actor cutover:repository-owner-map \
  --output /var/lib/devcoordinator/cutover/repository-owner-map.json

/opt/devcoordinator/releases/<digest>/bin/devcoordinator-repository-owner-authority \
  validate \
  --database <legacy-authority-database> \
  --expected-database-owner-uid <authority-uid> \
  --map /var/lib/devcoordinator/cutover/repository-owner-map.json \
  --expected-map-owner-uid 0
```

`census` is read-only and generation-fenced. It exposes the exact IDs, roots,
generations, display names, and lifecycle states requiring a decision, but it
never infers an execution owner from a path, inode, enrollment, or caller. The
administrator remains responsible for every explicit `--owner` assignment.

The same root-private map is also the only project execution-owner authority
used by the pre-split isolation audit. Run the audit against the still-live
schema-12 database before installing the deferred graph. The auditor validates
the map against the exact database generation, state revision, repository IDs,
roots, and repository generations; Docker source UIDs and worker policy UIDs
are deliberately ignored. Its evidence binds `source_schema_version=12` and
the sealed owner-map digest:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-project-isolation-audit \
  capture \
  --database <legacy-authority-database> \
  --repository-owner-map /var/lib/devcoordinator/cutover/repository-owner-map.json \
  --output /var/lib/devcoordinator/cutover/project-isolation.json
```

`prepare-first-adoption` requires the same `--legacy-authority-database` and
`--repository-owner-map` inputs and refuses to install the deferred graph
unless this pre-split audit is complete. It also requires the completed
binding attestation, the same first-adoption operation UUID, and the future
hard-gate attestation path. It recovers the exact
`schema13-first-adoption-executor` installer claim transferred by
`finalize-first-adoption-bindings`, holds the installer mutex throughout graph
installation, and retains the durable claim for `first-adoption`; a missing,
mismatched, or already-completed claim fails before installation. After the
split, the audit reads owner UIDs only from `repository_owners` and requires
its generation to match each repository generation; passing an owner map to
schema 13 is rejected. This keeps an isolation failure out of the already-
mutated first-adoption phase.

The canonical inventory hard-gate target is explicit and machine-neutral; it
is never inferred from account names or host paths. Supply the same four
values to graph preparation, the transaction, and installation finalization.
Preparation includes this argument bundle alongside its sealed graph,
isolation, port, credential, and predecessor inputs:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-availability-activate \
  prepare-first-adoption \
  --state /var/lib/devcoordinator/cutover/state.json \
  --binding-attestation /var/lib/devcoordinator/cutover/first-adoption-bindings-result.json \
  --operation-id <same-first-adoption-operation-uuid> \
  --hard-gate-attestation /var/lib/devcoordinator/cutover/first-adoption-installation-hard-gate.json \
  --canonical-project <canonical-global-finance-project-root> \
  --canonical-repository-id <global-finance-repository-id> \
  --owner-user <global-finance-owner-user> \
  --collaborator-user <global-finance-collaborator-user> \
  <sealed-graph-isolation-port-and-credential-arguments>
```

The resumable transaction repeats that exact target. Its terminal replay path
can therefore validate an existing installation hard gate before it releases
the inherited installer claim:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-availability-activate \
  first-adoption \
  --request /var/lib/devcoordinator/cutover/first-adoption-request.json \
  --journal /var/lib/devcoordinator/cutover/first-adoption-journal.json \
  --attestation /var/lib/devcoordinator/cutover/first-adoption.json \
  --rollback-evidence /var/lib/devcoordinator/cutover/first-adoption-rollback.json \
  --binding-attestation /var/lib/devcoordinator/cutover/first-adoption-bindings-result.json \
  --operation-id <same-first-adoption-operation-uuid> \
  --hard-gate-attestation /var/lib/devcoordinator/cutover/first-adoption-installation-hard-gate.json \
  --canonical-project <canonical-global-finance-project-root> \
  --canonical-repository-id <global-finance-repository-id> \
  --owner-user <global-finance-owner-user> \
  --collaborator-user <global-finance-collaborator-user> \
  --expected-uid 0
```

The fleet gate in this transaction is availability-scoped. It catalogs every
authority repository but writes no repository manifest or metadata. The
DevCoordinator dogfood repository must already have a valid, clean manifest;
other already-valid repositories become runnable, while missing, invalid, or
unsafe repositories are returned as Setup state for later explicit adoption.
They never block the first Console/API/test-plane availability cutover.

After the ledger exists and the repository repair and complete owner map have
been validated, migrate the existing Console session and Google OIDC values.
The bootstrap has already created the root-owned destination parents. The
command keeps root as the sole publisher while validating the legacy Console
environment under its declared source UID. Its sealed attestation contains
only identities and digests, never credential bytes. Replaying the same
command verifies the unchanged source identity and destination publications
without rewriting them:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-availability-activate \
  migrate-credentials \
  --legacy-env <legacy-console-environment> \
  --legacy-source-uid <legacy-console-source-uid> \
  --rollback-directory /var/lib/devcoordinator/cutover/credential-rollback \
  --attestation /var/lib/devcoordinator/cutover/credential-migration.json \
  --expected-uid 0
```

The source-owner UID is evidence, not publication authority. A source
symlink, owner mismatch, inode replacement, changed replay input, non-root
destination, or conflicting prior attestation fails closed. Do not chown,
duplicate, or place credential bytes in argv to bridge an ownership mismatch.

The loopback Coordinator API has no internal bearer secret. First-adoption
delegation is verified only by the immutable activation wrapper against the
trusted loopback HTTP endpoint and the authority-derived protected profile.
Public Google OIDC, Console session issuance, TLS, route authorization, and
external service credentials remain unchanged and mandatory at the edge.

After the initial history import, admission is drained only through the
supported generation-bound broker operation:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-cutover \
  admission-drain \
  --state /var/lib/devcoordinator/cutover/state.json \
  --proof-output /var/lib/devcoordinator/cutover/drain.json \
  --broker-socket /run/devcoordinator/broker.sock
```

The proof is checked against the authority database, published privately, and
recorded in the ledger idempotently. A broker reply from another authority
generation cannot advance the cutover.

Activation runs a bounded sampler before, throughout, and after the mutation.
Its sealed result contains real HTTP TTFB, control-plane latency, HTTP/WSS
sample counts, connection refusals, and project-route regressions. Both normal
activation and first adoption copy their continuity counters from that seal;
they never synthesize zeroes. The ordinary activation CLI also requires a
separate `--continuity-evidence` output so operators can retain and inspect the
collector result.

Activation consumes the exact browser runtime, authenticated storage state,
signing key, journal, attestation, and one-shot consumption marker. Omitting
any of those inputs is a hard error:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-availability-activate \
  activate \
  --state /var/lib/devcoordinator/cutover/state.json \
  --publication /var/lib/devcoordinator-edge/routes.json \
  --candidate-control /run/devcoordinator/console-<candidate>.sock \
  --previous-control /run/devcoordinator/console-<previous>.sock \
  --activation-evidence /var/lib/devcoordinator/cutover/activation.json \
  --continuity-evidence /var/lib/devcoordinator/cutover/activation-continuity.json \
  --credential-evidence /var/lib/devcoordinator/cutover/credential-preflight.json \
  --browser-runtime-lock /var/lib/devcoordinator/browser/runtime-lock.json \
  --browser-storage-state /var/lib/devcoordinator/browser/storage-state.json \
  --browser-signing-key /var/lib/devcoordinator/browser/signing-key \
  --browser-journal /var/lib/devcoordinator/cutover/browser-lcp-journal.json \
  --browser-attestation /var/lib/devcoordinator/cutover/browser-lcp-<cutover-uuid>.attestation.json \
  --browser-consumption /var/lib/devcoordinator/cutover/browser-lcp-<cutover-uuid>.consumption.json \
  --authority-uid 0
```

The command durably journals promotion and publication intent next to the
activation evidence as `.activation.json.switch-journal.json` before either
effect. Re-running the same command after power loss first converges the exact
slot/publication pair to the recorded predecessor and then performs a complete
fresh switch; a completed journal is replayed without mutation.

Once activated, first exercise the real blue/green traffic reversal, then the
offline data restore and retention producers:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-availability-activate \
  rehearse-live-rollback \
  --state /var/lib/devcoordinator/cutover/state.json \
  --publication /var/lib/devcoordinator-edge/routes.json \
  --candidate-control /run/devcoordinator/console-<candidate>.sock \
  --previous-control /run/devcoordinator/console-<previous>.sock \
  --journal /var/lib/devcoordinator/cutover/live-rollback-journal.json \
  --attestation /var/lib/devcoordinator/cutover/live-rollback.json \
  --continuity-evidence /var/lib/devcoordinator/cutover/live-continuity.json

/opt/devcoordinator/releases/<digest>/bin/devcoordinator-cutover \
  rehearse-rollback \
  --state /var/lib/devcoordinator/cutover/state.json \
  --scratch-directory /var/lib/devcoordinator/cutover/rollback-rehearsal \
  --output /var/lib/devcoordinator/cutover/rollback-rehearsal.json

/opt/devcoordinator/releases/<digest>/bin/devcoordinator-cutover \
  attest-retention \
  --state /var/lib/devcoordinator/cutover/state.json \
  --output /var/lib/devcoordinator/cutover/retention.json \
  --browser-attestation /var/lib/devcoordinator/cutover/browser-lcp-<cutover-uuid>.attestation.json \
  --browser-consumption /var/lib/devcoordinator/cutover/browser-lcp-<cutover-uuid>.consumption.json \
  --browser-runtime-lock /var/lib/devcoordinator/browser/runtime-lock.json \
  --browser-signing-key /var/lib/devcoordinator/browser/signing-key
```

The live rehearsal is available only when activation retained a previous
blue/green slot. It journals every slot and publication intent before its
effect, switches traffic to the previous release, verifies route/profile/data
health, and reactivates the candidate. One uninterrupted HTTP/WSS collector
spans the complete reverse/forward operation; nested rollback and reactivation
windows provide phase evidence without creating a gap. A crash abandons the
unobservable window, converges to the activated candidate, and repeats a fresh
complete attempt. The final monotonic publication generation/hash becomes the
supported rollback head.

The offline rehearsal restores every retained SQLite image into root-private
scratch, runs integrity and foreign-key checks, and binds the exact inverse
publication plan plus activation continuity digest. Retention then re-hashes
the backups, rechecks the legacy source, verifies the unexpired rollback
window, and requires both live and offline rehearsal seals. The short browser
attestation TTL is evaluated at its durable one-shot consumption timestamp;
retention separately observes current live health, so a valid consumed proof
does not become unusable merely because the retention window is longer than
the browser TTL. Replays converge on the same ledger evidence.

The continuity collector is not a browser and does not claim LCP. The
sub-second LCP acceptance gate requires a distinct browser-produced,
viewport-specific attestation bound to the same release. If that attestation
is absent, LCP is unmeasured and the performance acceptance gate fails closed.

### Broker-only Docker admission

Direct membership in the host `docker` group is equivalent to root and is not
an acceptable agent capability. The immutable
`devcoordinator-docker-admission` administrator wrapper removes only an exact,
root-private request's declared `docker` NSS memberships and named POSIX ACLs.
It does not edit Docker units, socket mode/owner, arbitrary groups, sudo policy,
rootless daemons, contexts, or client configuration.

Do not hand-seal the final request. Start with a root-owned mode-0600 draft of
kind `devcoordinator-docker-admission-request-draft`. It contains one operation
UUID, the complete user/project list, the `docker` group, the complete host
socket path set, the finite ACL grants to remove, the fixed protected-profile
path, the immutable client path and the selected canary user. Never include
credentials. The immutable wrapper derives every UID/GID/repository generation,
the broker socket and generation from the live protected profile, proves that
the draft covers its complete client set, verifies the content-addressed
release manifest, and writes a new mode-0600 sealed request:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-docker-admission \
  seal-request \
  --draft /var/lib/devcoordinator-installs/docker-admission-draft.json \
  --output /var/lib/devcoordinator-installs/docker-admission-request.json
```

The final `devcoordinator-docker-admission-request` independently binds the
protected profile SHA-256, the canonical complete client UID set and client-map
SHA-256, plus the immutable release, manifest and client digests. Every phase
revalidates those bindings. The administrator reviews that produced document
before planning:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-docker-admission \
  plan \
  --request /var/lib/devcoordinator-installs/docker-admission-request.json \
  --transaction /var/lib/devcoordinator-installs/docker-admission-<operation-id>
```

Planning fails closed unless NSS identity, every declared socket and ACL,
client contexts, rootless endpoints, process credentials/start identities/file
descriptors, mount/network/user namespaces, privileged Unix-socket connections,
CLI `--host`/`--context` selections, endpoint environment, alternate engines,
anonymous connected peers, and sudo/wheel/LXD bypass groups are completely
observable. Every mutation is
one journaled absolute `gpasswd -d <user> docker` or `setfacl -x` command. Apply
requires the returned plan ID and stable plan SHA-256:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-docker-admission \
  apply \
  --transaction /var/lib/devcoordinator-installs/docker-admission-<operation-id> \
  --plan-id <plan-id> --plan-sha256 <plan-sha256>
```

Apply deliberately returns `awaiting_session_convergence`. Existing shells,
agents, and services may retain the old supplementary GID or an open Docker
connection even after NSS changes. Restart those attributed sessions through
their normal owner lifecycle; do not kill or inspect them ad hoc. Re-run
verification with the stable apply digest until it reports `broker_only`:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-docker-admission \
  verify \
  --transaction /var/lib/devcoordinator-installs/docker-admission-<operation-id> \
  --apply-sha256 <apply-sha256>
```

Verification keeps the durable global installer fence while any original GID,
direct FD/connection, unknown process/namespace, rootless or custom context,
socket recreation, fresh direct connection, or broker-canary mismatch remains.
It clears the fence only after a clean-group fresh process is denied by every
socket and the immutable client succeeds through the authenticated broker with
the exact authority generation and repository ownership binding.

Before successful verification, rollback may restore only grants actually
removed by this journal. It requires the same stable apply digest (or the plan
digest after an interrupted apply), executes the exact inverse commands in
reverse order, and refuses socket/configuration drift. Interrupted apply and
rollback replay from observed postconditions without duplicating mutations:

```bash
/opt/devcoordinator/releases/<digest>/bin/devcoordinator-docker-admission \
  rollback \
  --transaction /var/lib/devcoordinator-installs/docker-admission-<operation-id> \
  --apply-sha256 <apply-or-plan-sha256>
```

Preserve the journal and terminal evidence with the release/cutover rollback
records. Docker admission is an explicit host-security transaction, never an
implicit side effect of installing skills or starting the broker.

The deterministic self-test uses a fake NSS/ACL/socket mutator so it is safe on
build hosts. It does not claim a live Linux authorization proof. Production
acceptance still requires the immutable wrapper's real root-only observation
and denial probes on the target host (including NSS, POSIX ACL, `/proc`, Unix
socket attribution and namespace visibility); an environment that cannot
provide all of that evidence remains fenced rather than being waived.

### Live fault/load isolation acceptance

The destructive fork/OOM/crash-loop campaign is disabled in the ordinary test
harness. Its scenarios intentionally consume resources and therefore must not
share the accounting-only attempt manager or smuggle hidden quotas into normal
tests. Re-enable this acceptance gate only after it has a separate trusted,
bounded launcher with explicit scenario limits and continuity probes. Until
then, no release or operator workflow may present ordinary test execution as
providing live fork-bomb or cgroup-OOM acceptance evidence.
