# Manifest and Evidence Contract

Read this reference when creating or repairing `.codex/tests.json`, selecting
advanced test operations, or consuming retained evidence.

## Contents

- [Manifest](#manifest)
- [Drivers and source](#drivers-and-source)
- [Capabilities and secrets](#capabilities-and-secrets)
- [Manual retry and terminal meaning](#manual-retry-and-terminal-meaning)
- [Evidence and artifacts](#evidence-and-artifacts)
- [Installed and release acceptance](#installed-and-release-acceptance)

## Manifest

Manifest schema 4 is strict and fail closed. It declares bounded targets,
shell-free argv, contained cwd, dependencies, intent participation, source
mode, target timeout, launch timeout, reporter, artifacts, network policy,
fixtures, state handles, and credential aliases. Automatic retry fields from
older schemas are invalid.

Unknown fields, graph cycles, unsafe paths, shell execution, undeclared
fixtures or credentials, secret-shaped literal environment names, and
contradictory target resources are invalid. The complete normalized target
execution specification is stored with plan registration. Submission never
falls back to process memory or default resources. A replacement imports a
complete atomic result package first, then cancels and cleans unfinished
executions rather than resurrecting them.

## Drivers and source

Framework command adaptation, dependency preparation, and reporter parsing live
behind explicit drivers. Scheduler/store code consumes only normalized,
driver-neutral executions and results.

Change/checkpoint planning inspects the complete current worktree, then captures
the selected source immutably before registration. A change between selection
and capture rejects the plan and requires a fresh one. Handoff, release, and
manual plans also use immutable materialization containing tracked, staged,
unstaged, and bounded non-ignored untracked source. The protected snapshot
boundary validates source and paths without executing repository code.

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

## Manual retry and terminal meaning

Every selected target has one execution slot in a run. There is no automatic,
lease-driven, or in-run retry and schema 4 has no target `retry` or
`max_attempts` field.

Stable `retry --failed-only` creates a new immutable plan/run with new execution
identities, already-satisfied dependencies normalized away, and selected
dependencies retained exactly. A changed source requires a fresh current plan.

Success, test failure, infrastructure failure, timeout, cancellation, and
incomplete reporting remain distinct. A command may return `ok: true` while
reporting a failed run conclusion.

## Evidence and artifacts

The runner continuously drains bounded captures, retains structured cases and
one exact failure record for every failed/error case within report bounds, and
publishes exactly one deterministic uncompressed USTAR `result-package.tar`
after the repository process exits. Its manifest binds exact repository,
run/target/execution generations, descriptor fingerprint, outcome, counts,
member sizes, and SHA-256 digests. Testd validates and imports the complete
package transactionally; there is no semantic result-chunk protocol or durable
result spool.

`failures` and `cases` are cursor-bounded. Never paste a large page or raw log
into model context; follow the returned cursor and export large evidence to a
file when needed.

Artifact resolution verifies immutable run/artifact identity, storage handle,
size, and full SHA-256. Text kinds may return a bounded UTF-8 tail with explicit
full size and truncation; binary kinds remain metadata-only. `artifact-export`
streams ordered bounded byte pages, verifies the combined identity and digest, and
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
