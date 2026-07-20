# DevCoordinator

DevCoordinator is the canonical public repository for two agent-facing local
operations skills and the interfaces built on top of them:

- `codex-dev-coordinator` coordinates attributed port leases, dev processes,
  Docker resources, project runtimes, health evidence, and a loopback bearer-
  authenticated HTTP API.
- `postgres-docker-backup` creates, verifies, and safety-gates logical
  PostgreSQL backups and database restores for explicitly selected Docker
  containers.
- `DevOpsBoard` is the native macOS interface for local coordinator inventory,
  actions, leases, Docker, and PostgreSQL protection.
- `DevOpsConsole` is the zero-dependency Node 20 web console and TLS/subdomain
  edge used at `console.vr.ae`.

The repository is independent. Its source, build, runtime, tests, CI, and
packaging do not import or pin holyskills. Historical attribution from the
original monorepository is retained in [docs/history](docs/history/README.md).

## Layout

- `skills/codex-dev-coordinator/`
- `skills/postgres-docker-backup/`
- `apps/DevOpsBoard/`
- `apps/DevOpsConsole/`
- `scripts/validate.py` and deterministic repository guards
- `ci/playwright/` for the locked, isolated Console fixture renderer

## Install the skills

This checkout is the only writable source for its two skills. Install direct
absolute symlinks into each explicit runtime root; never hand-edit an installed
copy or derive another runtime's home from the current shell's `$HOME`.

```bash
DEVCOORDINATOR_ROOT="/absolute/path/to/DevCoordinator"
python3 scripts/manage_skill_links.py plan \
  --repo-root "$DEVCOORDINATOR_ROOT" \
  --target-root "/absolute/path/to/codex/skills" \
  --target-root "/absolute/path/to/claude/skills" \
  --target-root "/absolute/path/to/desktop-codex/skills"
```

After reviewing drift and porting any intentional unique changes into this
repository, apply transactionally. The transaction must be private, outside
Git, and on the same filesystem as every named target root.

```bash
install -d -m 700 "$HOME/.local/state/devcoordinator/link-transactions"
python3 scripts/manage_skill_links.py apply \
  --repo-root "$DEVCOORDINATOR_ROOT" \
  --target-root "/absolute/path/to/codex/skills" \
  --target-root "/absolute/path/to/claude/skills" \
  --target-root "/absolute/path/to/desktop-codex/skills" \
  --transaction-dir "$HOME/.local/state/devcoordinator/link-transactions/$(date +%Y%m%d-%H%M%S)" \
  --allow-noncanonical

python3 scripts/manage_skill_links.py verify \
  --repo-root "$DEVCOORDINATOR_ROOT" \
  --target-root "/absolute/path/to/codex/skills" \
  --target-root "/absolute/path/to/claude/skills" \
  --target-root "/absolute/path/to/desktop-codex/skills"
```

Restart affected Codex, Claude, and desktop runtimes after the link migration;
skill metadata is loaded at session startup. Retain the rollback transaction
until fresh-session discovery and repository validation succeed.

## Coordinator state, identity, and refresh

The product default is one server-wide authority at
`/var/lib/devcoordinator/coordinator.sqlite3`, reached only through the
peer-authenticated `/run/devcoordinator/broker.sock`. The service database is
mode `0600` below a service-owned `0700` directory; clients never open it.
Every enrolled UID therefore sees the same repositories, servers, leases,
assignments, Docker resources, and lifecycle observations. A private client
journal at `/var/lib/devcoordinator-clients/<uid>/` retains launch and
reconciliation evidence without becoming a competing authority.

System mode requires the protected profile at
`/etc/devcoordinator/client-profiles.json` and fails closed when the broker is
unavailable. `DEVCOORDINATOR_AUTHORITY=account` is an explicit isolated
compatibility/test scope, not host-global evidence.

One canonical local Git worktree root is one repository/project. Coordinator
homes, application instances, display names, and container-name resemblance
are provenance or discovery evidence, never project identity. Resources whose
repository ownership cannot be proved appear once as **Unassigned Resources**
with their exact blocker. They can be attached only by an explicit operator
choice or retired through their immutable host-resource identity.

`inventory` is a pure database query: it does not run Docker, inspect
processes, scan backups, or rewrite state. `observe` is the explicit bounded
write path. Concurrent same-scope observations join one database-backed
single-flight ticket, while full-Docker, no-Docker, and different backup-scan
scopes cannot incorrectly satisfy one another. DevOps Board observes one
account source and then reads the committed snapshot; imported legacy Parall
homes are not polled as independent projects.

The first normalized observation transactionally imports eligible same-UID
legacy JSON homes after creating private, checksummed preservation evidence.
Exact duplicates collapse; conflicting repository, port, process, or immutable
Docker claims remain explicit and fail closed. Legacy files are retained for
rollback and later writes are reported as conflicts instead of silently
overwriting SQLite truth.

### Server-wide deployment

The deployment uses a root-owned, narrow authority broker, the
`devcoordinator-clients` socket access group, systemd sysusers/tmpfiles, a
supervised broker unit, and direct repository skill links for Codex and Claude.
Root is required to prove and stop exact cross-UID resources and to match the
administrator-owned enrollment store. The service protocol cannot launch user
account host processes; those launches remain in each enrolled client's
non-root process. Typed Docker lifecycle operations remain service-owned. The
installer grants the client group read/execute-only ACLs on the canonical skill
source (plus inherited ACLs for future files); the direct links therefore track
repository updates without granting source or authority-database write access.
Plan first; apply requires root once and does not start the service:

```bash
python3 scripts/install_server_wide_coordinator.py plan \
  --client-user alice --client-user console

sudo python3 scripts/install_server_wide_coordinator.py apply \
  --client-user alice --client-user console \
  --transaction-dir /var/lib/devcoordinator-install/$(date +%Y%m%d-%H%M%S)
```

The production broker keeps `ProtectSystem=strict`,
`ProtectHome=read-only`, `PrivateTmp=true`, `NoNewPrivileges=true`, and the
system manager's capability ceiling with no ambient capabilities. Its exact
writable base exceptions are `/var/lib/devcoordinator` and
`/run/devcoordinator`. The installer transaction also replaces one generated
drop-in with only the canonical, real, directly-under-`/home` home paths of the
complete explicit `--client-user` set. This is required because one
server-wide broker may remove an explicitly planned clean linked worktree owned
by any enrolled user. Reapply with the complete current client list when
enrollment changes; omitted homes are removed from the writable set instead of
accumulating in the configured unit. A running broker retains its existing
mount namespace until it is safely drained and restarted, so do not treat the
omission as live revocation before that restart. `/home` itself, `/root`,
`/etc`, other users' homes, and the rest of the host remain read-only, while
the broker's peer ACL, cleanup plan, immutable target identity, and safety
checks remain the authorization boundary. After installation and the safe
restart, run
`scripts/check_broker_shutdown_unit.py` against the loaded unit before enabling
new cleanup operations.

Before apply mutates the host, it verifies `/usr/bin/python3` has PyYAML 6.x
and that the service's exact Docker CLI provides a stable Compose plugin in
`>=2.17,<3` or `>=5,<6`. The same systemd preflight runs before every broker
start. Its Docker proof is non-mutating: a throwaway
`docker compose config --format json` must honor two ordered explicit
environment files, the second-file override, and implicit `.env` suppression;
it does not contact the daemon or start containers.

Then enroll each exact UID/repository before enabling the broker. Repeated
`--server` flags form that account's server allowlist; re-enrollment atomically
revokes omitted server grants. Omitting both `--server` and the explicit
`--all-servers` override grants no server control:

```bash
sudo python3 /absolute/path/to/dev_coordinator.py broker enroll \
  --database /var/lib/devcoordinator/coordinator.sqlite3 \
  --socket /run/devcoordinator/broker.sock \
  --access-group devcoordinator-clients \
  --client-uid NUMERIC_CLIENT_UID \
  --account-id EXACT_CLIENT_ACCOUNT_ID \
  --project /absolute/path/to/repository \
  --agent "$USER" \
  --server web \
  --server worker \
  --port-range 3000-3999

sudo systemctl enable --now devcoordinator-broker.service
```

Enrollment resolves the real Git root, imports its declared runtime, performs a
fresh full-Docker observation, grants only exact normalized repository/resource
IDs, and installs the protected client profile at
`/etc/devcoordinator/client-profiles.json` on Linux or
`/private/etc/devcoordinator/client-profiles.json` on macOS. It starts no
resource. Register any pre-existing running listener as its owning UID after
enrollment; publication succeeds only after the service proves its exact UID,
PID, repository cwd, port, and listener. Keep the old account store until the
server appears in the shared inventory and DevOps Console. The installer
transaction can roll back system configuration and canonical skill links.

#### Authorization-schema upgrade recovery

Run the server-wide installer `plan` with the complete client list before a
broker restart. `profile_database_enrollment_drift` blocks restart. After a
verified private service-store backup and an orderly stop of Console, API, and
broker, reconcile only explicitly reported generation drift:

```bash
sudo python3 /absolute/path/to/dev_coordinator.py broker reconcile-profile-repository-generation \
  --database /var/lib/devcoordinator/coordinator.sqlite3 \
  --profile /etc/devcoordinator/client-profiles.json \
  --client-uid NUMERIC_CLIENT_UID \
  --account-id EXACT_CLIENT_ACCOUNT_ID \
  --repo-id EXACT_REPOSITORY_ID \
  --canonical-root /absolute/canonical/repository \
  --rollback-root /var/lib/devcoordinator-install/PRIVATE-TRANSACTION \
  --from-generation OLD_GENERATION \
  --to-generation CURRENT_GENERATION

sudo python3 /absolute/path/to/dev_coordinator.py broker migrate-profile-enrollments \
  --database /var/lib/devcoordinator/coordinator.sqlite3 \
  --profile /etc/devcoordinator/client-profiles.json
```

The first command creates private rollback evidence and changes exactly one
proved generation scalar without rebuilding grants. The second inserts only
missing rows backed by the current protected profile and existing exact ACL
evidence. Prove the migration is idempotent, rerun installer `plan` and
`verify`, then restart and verify every UID/repository plus the Console's exact
registered listener, assignment, lease, and public login path.

### Coordinator-store backup and recovery

Use the same administrative surface for either an account-owned or
service-owned normalized store. Artifact roots must be private absolute paths
outside Git:

```bash
python3 /absolute/path/to/dev_coordinator.py broker store-backup \
  --database /absolute/path/to/coordinator.sqlite3 \
  --store-role account \
  --output-root /private/backup/root

python3 /absolute/path/to/dev_coordinator.py broker store-export \
  --database /absolute/path/to/coordinator.sqlite3 \
  --store-role account \
  --output-root /private/backup/root
```

`store-restore` restores a verified binary backup of the same database
generation; `store-import` imports a verified logical export. Both require a
readable current normalized store, create and verify a safety backup first, and
require `--manifest`, `--safety-root`, and explicit `--confirm`. A logical
export is a migration/reconstruction artifact, not a corrupt-database recovery
shortcut.

If SQLite validation fails, stop every service and client using that authority
and preserve the evidence. Recovery is a separate explicit journey:

```bash
python3 /absolute/path/to/dev_coordinator.py broker store-recover \
  --database /absolute/path/to/coordinator.sqlite3 \
  --store-role account \
  --manifest /private/backup/root/VERIFIED_BINARY_MANIFEST.json \
  --forensic-root /private/forensic/root \
  --confirm-corrupt-recovery
```

`store-recover` accepts only a strongly verified binary artifact for the same
store role. Because a corrupt current database cannot prove its generation, it
first captures the exact database, WAL, and shared-memory bytes with SHA-256
evidence, retains that forensic capture, validates the replacement, and rolls
back exact bytes if publication fails. It is an offline recovery operation;
the command does not stop or supervise services for the operator.

## Reversible repository removal

Removing a repository is a coordinated decommission, not a Board preference or
filesystem deletion. The coordinator first records a durable start fence,
captures and disables every proved automatic-start policy, stops each exact
owned process/container/supervisor, verifies the stopped and listener
boundaries, releases active leases and assignments, and only then removes the
repository from active inventory. Repository files, containers, volumes,
databases, backups, and audit history are retained.

The destructive step requires the exact plan identifier and fingerprint
returned by the read/observe-backed planning command:

```bash
PROJECT_ROOT="$(git rev-parse --show-toplevel)"
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py \
  repository plan-remove \
  --agent "$USER" \
  --project "$PROJECT_ROOT" \
  --reason "No longer used on this machine"

python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py \
  repository remove \
  --agent "$USER" \
  --project "$PROJECT_ROOT" \
  --plan-id EXACT_PLAN_ID \
  --plan-fingerprint EXACT_PLAN_FINGERPRINT
```

Any ownership, observation, policy, or plan drift blocks before the unsafe
effect. Partial host failure keeps the start fence and exact per-target evidence
visible for an idempotent retry; it never reports the repository removed.

List retained removal records or explicitly reinstall later:

```bash
python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py \
  repository list-removed

python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py \
  repository reinstall \
  --agent "$USER" \
  --project "$PROJECT_ROOT" \
  --reason "Needed again" \
  --explicit
```

Reinstall clears the fence but does not start anything. The first later
explicit Start restores only the exact automatic-start state captured during
removal before starting the retained runtime.

An unassigned resource is not silently folded into a similarly named project.
Use the immutable identity, control binding, and ownership fingerprint returned
by inventory to attach it explicitly, or use the two-step
`resource plan-retire` / `resource retire` journey to stop, fence, verify, and
hide that standalone resource without deleting its data.

## Coordinator API security

The coordinator API is a local capability boundary. It accepts only loopback
binds. `GET /healthz` is anonymous; every `/v1/*` request requires
`Authorization: Bearer <contents-of-api-token>`. The token file must be a
private mode-`0600` regular file and must never reach browser JavaScript, URLs,
logs, screenshots, or Git.

DevOps Console reads `COORDINATOR_TOKEN_FILE` only in its server-side client.
Its domain-wide Console session and OAuth-flow cookies are stripped from routed
HTTP/WebSocket requests and from every upstream response; unrelated application
cookies remain end-to-end. Routed projects therefore cannot read or overwrite
Console authentication cookies.
Production uses separate `dev-coordinator.service` and
`devops-console.service` units. Each unit requests and starts after its control
dependency without making listener availability cascade through `Requires=`:
broker maintenance therefore leaves the authenticated API listener and public
TLS edge running, with broker-backed actions failing closed until recovery.
Both API and Console restart after failed or unexpected clean process exits,
while an explicit systemd stop remains a deliberate maintenance stop. Their
stdout and stderr use persistent journald identities. The Console never spawns
a duplicate coordinator. Private configuration and mutable state stay outside
the checkout:

- `$HOME/.config/devops-console/console.env` — mode `0600`
- `$HOME/.local/state/devops-console` — mode `0700`
- `$HOME/.codex/agent-coordinator` — mode `0700`

`devops-console.service` runs `scripts/check_production_layout.py` before every
start. The preflight requires the environment/token files and all existing
state descendants to be private, rejects symlinks and any env/state/token path
inside Git, and fails closed before the Console binds a listener. Production-
critical coordinator/script/state/ACME values are pinned after environment-file
loading, so a preserved stale env file cannot re-enable coordinator autostart
or redirect the bearer credential to a remote origin.

Moving a pinned production listener between checkouts uses the coordinator's
first-class `port relocate` transaction with the exact captured lease ID. It
refuses live/pending/foreign or ambiguous state, preserves one reusable server
identity, and never infers availability by trying to bind a privileged port.
The Console deployment runbook includes private checksummed state backup,
strict ownership transfer, health/auth verification, and rollback.

See [apps/DevOpsConsole/README.md](apps/DevOpsConsole/README.md) for deployment
and TLS details.

## DevOps Board identity and packaging

The native product and Swift module are named `DevOpsBoard`. Its existing
bundle identifier (`local.holyskills.codex-ops-console`) and legacy settings
lookup intentionally remain unchanged so installed users keep application
identity and preferences across the rename; this compatibility identity is not
a source dependency.

Packaging bundles exact copies of both helper scripts from one
`DEVCOORDINATOR_ROOT` checkout. Provenance records the repository commit/tree,
the helper hashes, Swift/package input hashes, and executable hash. Helper,
source, executable, or provenance tampering fails closed.

Agents must build, test, snapshot, package, launch, and automate the native app
only through the Build macOS Apps plugin. Direct `swift`, `swiftc`,
`xcodebuild`, XCUI, `open`, or desktop control is not an accepted substitute.

## Validation

Run the complete safe non-native gate:

```bash
python3 scripts/validate.py --skip-macos-app
```

It checks repository freshness scenarios; exact ownership and cross-repository
boundaries; reachable-history artifact/secret/path policy; link rollback;
legacy Console environment/state migration rollback;
public artifacts and snapshot detector recall; coordinator and PostgreSQL P0
and self-tests; standalone copies of both skills; all DevOps Console unit/e2e
tests; Python compilation; and the Board's Python-only packaging/tamper suite.
CI repeats the non-native gate on Linux and macOS with Python 3.9 and 3.13 so
host discovery and exception/cleanup semantics cannot be validated by only one
developer environment.

The unflagged native gate is intentionally plugin-owned. A passing
`--skip-macos-app` run proves static, fixture, and non-native contracts only; it
does not prove the current Swift source builds or that committed native PNGs
depict it. The real disposable PostgreSQL integration additionally requires an
available Docker daemon and local test image, and CI runs it after coordinator
inventory.

## Boundaries

The coordinator is not a remote orchestrator, general identity provider,
container scheduler, or remote identity provider. Its default server-wide
broker is a narrow local peer-UID and explicit-ACL authority for inventory,
servers, ports, Docker, repository decommission, and protected database
actions; systemd supervises only the broker, not managed user workloads. It is
not remote IAM or a general workload supervisor. PostgreSQL logical backups
are not encryption, off-site storage, replication, continuous archiving, or
point-in-time recovery. The Console is purpose-built for an operator-controlled
host and adds owner-managed per-Google-account domain grants behind its
documented TLS/OIDC controls; it is not a general organization IAM service.
