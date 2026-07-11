# DevCoordinator capability audit

Date: 2026-07-11

This repository owns exactly two canonical skills. The descriptions below are
bounded by implementation and deterministic evidence; they do not turn local
tools into broader infrastructure guarantees.

## `codex-dev-coordinator`

Honest description: a local, single-OS-user coordinator for attributed port
leases, managed development processes, explicit project runtimes, Docker
lifecycle and inventory, health evidence, and an IPv4-loopback bearer-
authenticated HTTP API. It is not a remote orchestrator, scheduler, production
service manager, or secure cross-user/VM coordination protocol.

Established strengths:

- structured argv and shell-control rejection;
- private atomic schema-v2 state, bounded journals, process-instance identity,
  durable port assignments, and short reservation/commit locks;
- exact manual-lease attachment and attributed mutations;
- bounded listener, health, process, and Docker operations with explicit
  preflight/partial-failure evidence;
- immutable Docker identity and one membership model for both display grouping
  and project-action blast radius;
- anonymous `/healthz`, bearer-required `/v1/*`, loopback/Host/Origin/content-
  type/body-size/concurrency enforcement, and private token-file handling;
- realistic self-tests covering concurrency, stale metadata, command
  injection, missing/hung Docker, API attacks, durable assignments, and
  membership ambiguity.

Possible improvements: replace Unix signal, process, and `flock` assumptions
for Windows; add a deliberately designed multi-user protocol rather than
sharing one private home; expand explicit runtime declaration adapters without
guessing dependency graphs; and add remote/off-host orchestration only as a
separate authenticated product boundary.

## `postgres-docker-backup`

Honest description: a safety-gated logical backup, strong verification, and
database-restore tool for an explicitly selected PostgreSQL Docker container.
It supports database custom/plain scope and isolated whole-cluster dump
verification. It is not encrypted, off-site, continuous, replicated, or PITR.

Established strengths:

- private staged/fsynced/collision-refusing publication with versioned,
  content-addressed manifests;
- passwords transported through ephemeral private pgpass files rather than CLI
  arguments, with redacted diagnostics;
- immutable full or unambiguous standard-short container identity required for
  every live backup, database verification, and restore phase;
- strong scratch restore and catalog comparison, fatal cleanup failures, and a
  verified safety backup before transactional database restore;
- whole-cluster verification in a distinct no-network disposable container and
  refusal of unsafe in-place cluster restore;
- deterministic P0/self-tests plus an optional real disposable PostgreSQL 16
  integration.

Possible improvements: design an explicit staged cluster-replacement topology;
add encrypted off-site retention and WAL/PITR as separate systems; validate
application semantics after logical restore; and expand supported Docker-
compatible runtimes only with equivalent immutable-identity evidence.

## Product surfaces and residual gates

DevOps Board consumes both skills and packages exact helper copies from one
DevCoordinator commit. Its source/product name is standardized, while the
legacy bundle identifier and settings migration path are intentionally retained
for user continuity. Python-only package/tamper checks are deterministic;
native build, XCTest, current-source snapshot regeneration, package signature,
launch, and UI acceptance require Build macOS Apps.

DevOps Console is a zero-third-party-dependency Node service with an isolated
109+ test unit/e2e suite. Its server-side coordinator client reads a private
token file, keeps credentials out of browser surfaces, and treats semantic
`ok:false` coordinator reports as failures. Production units separate process
ownership and externalize configuration/state. Real TLS, OIDC, listener, and
production-inventory acceptance remain deployment-environment checks.

The link manager, public-artifact guard, snapshot verifier, repository-
freshness detector, and repository-boundary/history guard each include
must-catch and false-positive tests. Passing them proves their fixtures and
invariants, not that every future environment or product journey is correct.
