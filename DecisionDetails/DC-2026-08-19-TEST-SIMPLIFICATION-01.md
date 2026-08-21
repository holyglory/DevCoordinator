# DC-2026-08-19-TEST-SIMPLIFICATION-01 — Testd owns one disposable execution state machine

## Confirmed scope

The user approved implementation of the testing simplifications identified by the August 19 testing/API review. “Production,” “installation,” and “cutover” in this decision refer only to DevCoordinator itself, never to deployment of a repository under test. One developer owns the server. Every repository's test runs, cases, artifacts, timing, rollups, queues, execution state, and Test Store compatibility history are disposable. Repository registrations, routes, users and grants remain durable control data; repository source and project databases may be valuable. Crashes, stale work, lost replies, path escape, runaway processes, and cross-project interference remain credible; secrets and public identities retain their dedicated boundaries.

## Selected architecture

- Keep testd, the root snapshot helper, transient non-root systemd executions, exact repository/execution identities, source containment, secret transport, bounded results, idempotent host operations, TTL containment, and explicit cancellation.
- Make testd and its Test Store the sole semantic authority for registered plan inputs, runs, one execution slot per target, dependency readiness, target deadlines, atomic result-package import, and terminal conclusions. The privileged runtime reports exact process/result facts and executes prepare/start/observe/stop/collect; it never invents or persists a competing run conclusion.
- Persist the complete normalized target execution specification with plan registration. Do not keep submission-critical plan resources only in process memory.
- Introduce the next Test Store schema without compatibility-only CPU, memory, or PID target declarations. Admission continues to use learned measured memory; CPU and PID observations remain telemetry, not schema placeholders or quotas.
- Treat an incompatible Test Store release as a controlled disposable-state reset inside the DevCoordinator delivery: stop testd, import any complete atomic result package, cancel and cgroup-clean unfinished executions, delete only the isolated Test Store, activate a fresh store, and retain no history importer, backup, admission-drain, spool, lease, or Test Store payload-compatibility protocol. Same-schema replacement uses the same result-first cleanup and does not resurrect unfinished work.
- Keep the routine agent journey centered on `enqueue`, reviewed `submit`, `follow`, and `cancel`. Bounded failure/artifact/retry diagnostics remain continuation actions; redundant routine status/summary/wait aliases are removed. The advanced administrative CLI retains exact drill-down operations.
- Move framework-specific command adaptation, dependency preparation, and reporter parsing into explicit driver modules. The scheduler, store, and agent projections consume normalized driver-neutral executions and results.
- Use manifest schema 4 without target `retry` or `max_attempts`; manual failed-only retry creates a new immutable run.

## Why this preserves the security posture

This change applies the confirmed assumptions in `security-assumptions.md`; it does not weaken a security control. Repository code still never runs as root or as the control plane. Exact identities, generation fences, path containment, dedicated credential transport, systemd cgroup isolation, output bounds, and TTL/cancellation remain. Removed fields and migration paths are compatibility mechanisms for disposable test data, not authorization, secret, source-protection, route, user/grant, or retained repository-registration gates. The integrity-gated compatibility that preserves a sealed DevCoordinator authority cutover's exact old/new database paths remains because it protects retained control data rather than test history.

## Supersession and compatibility

DC-2026-08-19-ARCHITECTURE-SIMPLIFICATION-02 supersedes this decision's
lease-based same-schema recovery, result-chunk ordering, and target retry
policy. Current recovery imports a complete atomic package or cancels and
cleans the unfinished exact execution. This decision still preserves
DevCoordinator authority-database recovery, repository/route/user/grant
retention, DC-2026-08-09-TEST-BATCHING-01, and the agent-local
20-case/10-second boundary.

## Verification

- Static contracts prove no packaged production or delivery path imports the retired migration/admission modules or serializes compatibility-only target resource fields.
- Store tests prove registered target execution specifications survive testd replacement without process-memory fallback.
- Lifecycle tests prove testd determines terminal meaning, validates one atomic result package, requests exact privileged collection, enforces semantic deadlines, and retains systemd TTL as independent containment.
- CLI/MCP/docs tests prove the routine surface and returned continuations agree.
- Driver tests cover automation, pytest, .NET/TRX, JUnit, JSONL, immutable Python/Node dependencies, fixtures, and bounded diagnostics through driver-neutral results.
- The complete repository-owned delivery cycle must pass before readiness.
