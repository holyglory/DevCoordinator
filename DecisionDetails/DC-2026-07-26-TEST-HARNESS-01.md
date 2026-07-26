# DC-2026-07-26-TEST-HARNESS-01 — Supporting record

## Requirement

The owner changed the CI direction from a repository-local test service to a universal DevOps Coordinator capability. Agents must be able to run a full profile, selected groups, or individual tests while receiving only structured results. Every session, group, and individual case must retain start, finish, duration, and outcome, with repo-by-repo statistics visible in both DevOps Console and DevOps Board.

## Options considered

- A repository-local SQLite store and dashboard was rejected because every repository would own duplicate migrations, retention, authorization, APIs, and UI and no server-wide repo view would be authoritative.
- Broker-side subprocess execution was rejected because the privileged service would accept or resolve repository commands and violate the established typed broker boundary that forbids user host-process launch.
- CI-provider-only history was rejected because local agent runs, integration selectors, and non-provider automation would remain invisible and provider retention/identity would become the product authority.
- Coordinator-owned admission and records with an enrolled-user Python runner was selected. Repositories declare structured argv groups in `.codex/tests.json`; the client starts the durable broker record before child launch, framework reporters emit exact case timings, and the client finishes the record after termination. The broker stores only command fingerprints, selectors, timings, counts, and outcomes—not commands, environment values, child output, credentials, or failure payloads.

## Data and authorization contract

Schema v9 adds repository-bound `test_runs` and `test_case_results`. A parent `session` represents one requested selection, children represent test or automation groups, and every case has an exact identity and wall-clock/elapsed timing. Starts are idempotent by run UUID and immutable identity; finishes are idempotent by a canonical result fingerprint. Current repository enrollment authorizes starts, exact run ownership authorizes finishes, and retained repository access permits results/statistics after decommission while new starts remain fenced.

## Product projection

`GET /v1/tests` returns bounded arbitrary-date statistics for DevOps Console. Normalized broker inventory carries a bounded 30-day `test_statistics` projection for DevOps Board. Both expose totals, daily test/run/time statistics, time and percentage by suite, individual test time and percentage, failures, and recent runs by exact repository ID.

## Verification evidence

- Python compile and 148 combined broker/startup/CLI/test-record tests pass, including exact repository authorization, durable lifecycle, aggregate statistics, inconsistent pass/failure rejection, and manifest path traversal rejection.
- DevOps Console's full suite passes (247 tests), including coordinator-client, immutable-asset, and Tests-page guards.
- The formal web verifier self-test passes against the repository-locked Playwright runtime. A representative long-content Tests projection passes deterministic 1440x900 and 390x844 verification with zero findings after mobile tables were changed from off-canvas scrolling columns to labeled rows.
- Native Board source is implemented through the Build macOS Apps SwiftPM workflow contract, but this Linux host has no Swift toolchain; signed macOS build/test/launch verification remains an activation gate in `CompletionLedger.md`.
