# DC-2026-08-04-BUG-INTAKE-01 — Coordinator failures use an independent open-bug channel

## User intent

Agents need a reliable way to report failures in the Coordinator itself, even when the failing Coordinator cannot accept a request. Reports must contain useful reproduction instructions. A test-harness outage must not block ordinary coding: agents may run repository-native tests while the harness is unavailable, but they must report the failure and must not misrepresent local results as Coordinator evidence. The Console must show only current open bugs; closing one removes it so multiple instances converge without synchronizing a second history.

## Selected design

- One canonical local directory contains one bounded, validated JSON file per open report. Presence means open.
- Reporting does not load repository enrollment, broker profiles, authority state, API state, testd state, or the call journal. The dedicated CLI and MCP operation share the same filesystem implementation.
- Writers use atomic replacement and bounded records. Identical current failures update one open report's occurrence count; after physical deletion, a recurrence receives a new identity.
- Reports require a human summary, expected behavior, actual behavior, and ordered reproduction steps. Structured argv and existing call, operation, run, or attempt identities are optional evidence. Obvious secret material is redacted and unbounded logs are rejected.
- Closing unlinks the exact open file. There is no closed table, archive, tombstone, migration, or hidden Console history.
- The Console reads the registry directly and independently from Coordinator inventory. Authenticated users can inspect it; the existing public-Console administrator boundary controls deletion.
- The Console exports the complete bounded open collection as one portable JSON bundle. Administrators may import a bundle; imported records retain their originating server, bug identity, and fingerprint, remain visibly remote, and never deduplicate with a local observation.
- Reproduction packets assume the original checkout is absent on the receiving server: private repository roots become `$REPOSITORY`, prerequisites are explicit, and no report depends only on a local log, temporary file, task, or agent memory.
- If the failure affects governed tests, the agent may continue repository-native isolated unit/static tests. It labels them local/advisory, excludes them from Coordinator statistics and release/handoff evidence, and retries governed verification after repair. This exception does not permit direct manipulation of shared listeners, containers, databases, or host services. Its previously qualitative scope is superseded by [DC-2026-08-09-TEST-BATCHING-01](DC-2026-08-09-TEST-BATCHING-01.md): each local test invocation is limited to 20 collected cases and 10 seconds and cannot reconstruct a broader suite through repetition.

## Why this fits the confirmed trust model

[`security-assumptions.md`](../security-assumptions.md) confirms that the host belongs to one developer, its Unix accounts are attribution domains rather than mutually distrusting principals, another local account is not a credible adversary, and non-secret coordination metadata may be shared. It explicitly says UID/GID/owner/mode/ACL are not local authorization gates and same-host communication needs no duplicate bearer token, signature, encryption, or cryptographic handshake. Therefore the local open-bug registry has no account-ownership authorization gate.

The same assumptions keep public Console identities and secrets as real boundaries. Consequently Console reads still require authentication, close remains an administrator mutation with origin validation, and reports exclude credentials, bot tokens, fixture secrets, environment dumps, and raw unbounded payloads. Shape, size, path, and exact bug-identity validation remain mistake-containment controls rather than cross-account authentication.

## Alternatives considered

- **Authority or broker table:** rejected because intake would disappear during the exact outage it needs to report.
- **Call journal only:** rejected because it is diagnostic evidence, best effort, and may not exist for pre-admission failures; it also cannot hold the agent's expected behavior and reproduction narrative.
- **Closed-report history or tombstones:** rejected because the user values current coordination, not bug-history retention, and deletion is the simplest convergence primitive across same-host instances.
- **Database-backed cross-server replication:** rejected because servers may be intermittently disconnected and the user requested copy/paste transfer. A self-contained origin-aware bundle is reversible, inspectable, and needs no synchronization service.
- **Stop development until the harness recovers:** rejected because it turns an infrastructure problem into a coding blocker.
- **Treat native tests as equivalent evidence:** rejected because it poisons testing statistics and makes immutable/release claims untruthful.
- **Direct runtime fallback:** rejected because a broken control plane does not make shared host state safe for unowned mutation.

## Verification

- Report, list, and close while authority, API, broker, testd, profiles, and repository enrollment are unavailable.
- Cross-account reporting and closing on this trusted host with no permission/ownership authorization gate.
- Concurrent report deduplication, atomic file replacement, idempotent close, malformed-record isolation, size limits, sanitization, and a new identity after close/re-report.
- Dedicated CLI, ordinary CLI, MCP, packaging, stable-launcher, and installed-skill parity.
- Console populated, empty, malformed, refresh-failure, non-admin, close-convergence, and Coordinator-down states at 320, 390, 768, 981, and 1440 pixels with no closed report or zero badge visible.
- Export clipboard success/failure with manual-select fallback; valid, malformed, duplicate, concurrent, and maximum-bounded imports; origin labels and local/remote non-deduplication on desktop and mobile.
- Skill checks require the bug-first/local-advisory fallback wording and forbid shared-runtime bypass or governed-evidence claims.
