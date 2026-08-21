# Server-wide administration

Read only the relevant section when the task changes the Coordinator host,
authority, installation, or fleet policy. Ordinary coding, runtime actions,
and repository tests do not need this reference.

## Contents

- [Release and installation](#release-and-installation)
- [Maintenance and authority changes](#maintenance-and-authority-changes)
- [Profiles and skill links](#profiles-and-skill-links)
- [Disposable test history](#disposable-test-history)
- [Docker admission](#docker-admission)
- [Sealed project capabilities](#sealed-project-capabilities)
- [Compose host-access approval](#compose-host-access-approval)
- [Exact Compose service recreation](#exact-compose-service-recreation)
- [Project systemd commissioning](#project-systemd-commissioning)
- [Database protection](#database-protection)
- [Headless browser lifecycle](#headless-browser-lifecycle)

## Release and installation

Use the repository-owned delivery driver rather than assembling a release by
hand:

```bash
python3 scripts/software_owned_delivery.py run --help
```

One `run` owns source verification, immutable packaging, deployment,
acceptance, event/log capture, and its concise final report. Reuse its run
directory for recovery. Do not mix its journal with manual installer,
systemd, database, or browser mutations.

Production runs from root-owned immutable release directories, never the
mutable Git checkout. A failed delivery remains incomplete until its own
report and recovery contract reach a terminal result.

## Maintenance and authority changes

Global maintenance is reserved for an authority-schema or authority-pointer
transaction. Console assets, Board, edge routing, and project traffic stay
available; only incompatible mutations receive the typed maintenance reply.

Use the fixed maintenance operation owned by the delivery workflow. Never
publish project progress or an ordinary code rollout through the global
marker. An active valid marker means wait and retry. An invalid marker or
routing-profile drift requires the installed verifier; never bypass the
broker with direct state, Docker, process, or database access.

Service startup performs no implicit migration. Same-schema service changes
use socket-preserving replacement; test, observer, or notification stores use
subsystem-local replacement. Only the authority transaction may fence global
mutations.

## Profiles and skill links

The server-wide installer publishes one readable local broker catalog for all
accounts. Its account entries provide attribution, repository roots, and
operation catalogs; they are not an access-control list. A client may use the
complete local view regardless of its UID. File owner, group, mode, ACL, link
count, and socket metadata are never admission conditions on this
single-developer host.

The installer also manages Codex and Claude links for both canonical
repository skills through `scripts/manage_skill_links.py`.

Never infer a repository from a process or port, create agent roots ad hoc, or
edit installed skill copies. Use installer `plan` and `verify` for protocol,
unit, or link drift. Do not investigate UID/GID/mode/ACL differences; attempt
the typed local connection and report only an actual connectivity or contract
failure.

## Disposable test history

Test history, execution state, and derived statistics are disposable. An
incompatible DevCoordinator release uses a fresh Test Store while preserving
retained authority control data, Console/user settings, repository source,
project databases, credentials, and recoverable backups.

Use the immutable release's
`devcoordinator-test-store initialize-fresh` operation through the
delivery workflow. It requires
the fixed discard confirmation, exact testd identity, operation UUID, and
readiness output. It must not open or change authority, profile, inventory, or
Console settings. It has no test-history importer, spool, recovery lease, or
result-chunk migration. Do not delete SQLite files manually.

## Docker admission

Agents use the broker for attributed Docker lifecycle so ownership and cleanup
stay software-owned. Local Unix groups and Docker socket ACLs are outside the
product trust model and must not be installed, repaired, or verified as an
admission step. Verify Docker support with one broker inventory/action canary;
repository/resource identity and the typed operation remain authoritative.

## Sealed project capabilities

Short-lived containers and Compose one-shots must come from administrator-
sealed `.codex/dev-runtime.json` declarations. Agents select only the named
template or service, timeout/TTL, repository, and replayable operation UUID.
They never provide an image, command, mount, privilege, secret, arbitrary
environment, Compose path, or Docker option.

Use executable help for the current contracts:

```bash
python3 "$COORDINATOR" ephemeral --help
python3 "$COORDINATOR" docker compose-run-once --help
```

## Compose host-access approval

A declared Compose model that requests non-loopback ports, bind mounts,
devices, host namespaces, added capabilities, or another host-equivalent risk
requires one explicit approval of its current rendered fingerprint. Use the
immutable live-authority wrapper; do not stop the authority or fall back to
offline `broker configure`:

```bash
devcoordinator-compose-host-access \
  --project /absolute/repository \
  --agent admin-session \
  --operation-id 00000000-0000-4000-8000-000000000000 \
  --approve-compose-host-access
```

The result names the exact Compose definition, generation, fingerprint, and
approved risk set. Replay only the same operation UUID after an uncertain
reply. Any changed or added risk requires a new explicit approval operation.
`devcoordinator-authority-repository-repair` is retained as a compatibility
alias for this same live command; it no longer invokes historical cutover
repair actions.

## Exact Compose service recreation

Use `docker compose-recreate-service` when one enrolled, single-replica
lifecycle service must be recreated without rebuilding an image or recreating
its dependencies. The broker resolves the sealed Compose definition, invokes
only `up --no-build --detach --no-deps --force-recreate --wait` for the named
service, preserves its declared volume model, and requires a fresh different
container identity in running readiness before success.

```bash
python3 "$COORDINATOR" docker compose-recreate-service --help
```

Do not use this operation for a run-once service, a scaled service, or a model
change. Those require their respective sealed enrollment/publication workflow.

## Project systemd commissioning

`systemd-unit` is a confirmation-bound administrative capability for one
canonical project `deploy/systemd/<unit>.service` and optional same-name timer.
Only a non-root, hardened `Type=oneshot` service with fixed absolute execution
and the exact sibling timer contract is eligible. `status` and `plan` are
read-only. `apply` requires the exact plan fingerprint and a canonical operation
UUID; its durable journal prevents uncertain run-once replay.

```bash
python3 "$COORDINATOR" systemd-unit plan --help
python3 "$COORDINATOR" systemd-unit apply --help
```

Commissioning installs and reloads without activating the service. Running the
one-shot or enabling its timer are separate desired states and require the
user's explicit confirmation for that exact unit.

## Database protection

Before migrations, destructive tests, reset, seed, restore, or any operation
that risks PostgreSQL data, use the `postgres-docker-backup` skill. Bind the
backup or restore to the Coordinator-verified immutable container ID. Do not
substitute a container name or Compose service name.

## Headless browser lifecycle

The authority observes explicit server-side headless/automation browser trees
as part of its existing bounded host-observation cycle. Normal agents do not
run a preflight or extra Coordinator command for this: the Performance page
receives measured Agent-browser CPU, proportional-set memory, process count,
last observed work, and lifecycle state from retained inventory. Project
containers stay in project accounting and governed test browsers stay under
their test runner, so the browser reaper never becomes a second owner.

Eligible developer-session trees are removed after the configured idle window
using exact PID plus kernel start identity. The release workflow owns the one
administrative exception: the first browser-aware release runs the candidate
`devcoordinator-browser-accounting cleanup-all` command immediately before
activation and retains its bounded result in the switch journal. Do not run
that administrative command from an ordinary agent task or substitute direct
process inspection/signalling.
