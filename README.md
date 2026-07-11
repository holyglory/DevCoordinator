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
`devops-console.service` units; the Console unit requires the coordinator and
does not spawn a duplicate. Private configuration and mutable state stay
outside the checkout:

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

The coordinator is not a remote orchestrator, multi-user authorization system,
container scheduler, or production service manager. PostgreSQL logical backups
are not encryption, off-site storage, replication, continuous archiving, or
point-in-time recovery. The Console is purpose-built for an operator-controlled
host and must remain behind its documented TLS/OIDC controls.
