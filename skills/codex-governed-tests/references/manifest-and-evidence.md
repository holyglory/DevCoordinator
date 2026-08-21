# Manifest and Evidence Contract

Read this reference when creating or repairing `.codex/tests.json`, selecting
advanced test operations, or consuming retained evidence.

## Contents

- [Manifest](#manifest)
- [Drivers and source](#drivers-and-source)
- [Capabilities and secrets](#capabilities-and-secrets)
- [Retry and terminal meaning](#retry-and-terminal-meaning)
- [Evidence and artifacts](#evidence-and-artifacts)
- [Installed and release acceptance](#installed-and-release-acceptance)

## Manifest

Manifest schema 3 is strict and fail closed. It declares bounded targets,
shell-free argv, contained cwd, dependencies, intent participation, source
mode, target timeout, launch timeout, reporter, artifacts, network policy,
fixtures, state handles, credential aliases, and explicit retry policy.

Unknown fields, graph cycles, unsafe paths, shell execution, undeclared
fixtures or credentials, secret-shaped literal environment names, and
contradictory target resources are invalid. The complete normalized target
execution specification is stored with plan registration and survives a
same-schema testd replacement; submission never falls back to process memory or
default resources.

## Drivers and source

Framework command adaptation, dependency preparation, and reporter parsing live
behind explicit drivers. Scheduler/store code consumes only normalized,
driver-neutral attempts and results.

Live change/checkpoint plans fingerprint the complete selected worktree. A
source change may supersede live evidence. Handoff and release use immutable
materialization containing tracked, staged, unstaged, and bounded non-ignored
untracked source. The protected snapshot boundary validates source and paths
without executing repository code.

Standard ignored dependency roots and exact external package-manager toolchains
are Coordinator-derived, snapshot-lock-bound, and read-only. Manifests cannot
supply arbitrary host mounts or expose a whole home.

## Capabilities and secrets

Targets requesting no protected capability do not need a capability grant.
Private isolated loopback is ordinary local test reachability. Host loopback,
external network, fixtures, operational credentials, and other declared
capabilities remain policy-gated.

Credential declarations contain only bounded aliases. The root boundary
resolves an administrator-sealed binding and supplies short-lived systemd
`LoadCredential=` files. Values and private paths never enter the manifest,
argv, literal environment, plan, result, artifact metadata, logs, or Console.

A named SQLite state handle may expose only a repository-contained,
identity-pinned live database directory read-only at its canonical private
namespace path. Only targets naming the handle receive its non-secret
environment path. Snapshots and artifacts never copy the database.

## Retry and terminal meaning

Each target declares `max_attempts` and reviewed `retry_on` values. Automatic
retry is limited to `lease_expired_before_launch`; assertion failure, ordinary
test failure, timeout, and post-launch loss are never silently retried as
infrastructure.

Stable `retry --failed-only` follows retained run/source policy. A changed live
source requires a fresh current plan; immutable failed work may retry only with
its exact dependency closure and replay identity.

Success, test failure, infrastructure failure, timeout, cancellation,
incomplete reporting, abandonment, and supersession remain distinct. A command
may return `ok: true` while reporting a failed run conclusion.

## Evidence and artifacts

The runner continuously drains bounded captures, retains structured cases and
one exact failure record for every failed/error case within report bounds, and
publishes atomic ordered result chunks. Testd alone determines completeness and
terminal meaning.

`failures` and `cases` are cursor-bounded. Never paste a large page or raw log
into model context; follow the returned cursor and export large evidence to a
file when needed.

Artifact resolution verifies immutable run/artifact identity, storage handle,
size, and full SHA-256. Text kinds may return a bounded UTF-8 tail with explicit
full size and truncation; binary kinds remain metadata-only. `artifact-export`
streams ordered bounded chunks, verifies the combined identity and digest, and
publishes a new mode-0600 file atomically without overwrite.

## Installed and release acceptance

Installed test-access acceptance performs the real repository setup and catalog
journey using explicit release-recovery deadlines at both client-to-broker and
broker-to-testd hops. A genuine deadline returns a typed failure; acceptance
never skips the installed probe or turns timeout into success.

DevCoordinator itself never self-hosts this verification through its installed
test plane. Its repository-owned `software_owned_delivery.py` workflow owns
source checks, immutable packaging, deployment, installed access, browser
acceptance, artifacts, and the final concise report.
