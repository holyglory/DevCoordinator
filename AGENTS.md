# DevCoordinator Agent Instructions

These rules apply to Codex and Claude Code in this repository.

## Repository freshness

- Before a repository-wide audit, broad refactor, migration, history rewrite,
  or split, run `python3 scripts/check_repository_freshness.py --repo "$PWD" --json`
  and inspect fetched remote-default ancestry.
- `current` and `ahead` are safe ancestry states. Reconcile `behind`,
  `diverged`, and `dirty-on-stale-base` before implementation.
  `remote-unavailable` is unknown, not proof of freshness.
- Never reset, rebase, stash, clean, or overwrite valuable dirty work to make a
  checkout current. Preserve it and reconcile from an isolated remote-fresh
  clone with an evidence-backed three-way merge.

## Incident and detector work

- Reproduce a user-reported error through the original surface before fixing
  it when reproduction is reasonable. Trace user intent, requirements,
  implementation, tests, tooling, and the missed-detection path first.
- Update the nearest durable guardrail before the product fix when practical.
  Keep one-off incident narratives in `DecisionHistory.md`, not policy.
- Detector changes must prove realistic recall for every advertised class and
  include false-positive controls for common intentional patterns.
- Re-test the original reproduction, the guardrail, and adjacent failure paths
  before reporting completion.
- Deterministic tests must isolate every host-sensitive discovery channel they
  assert is absent: global Git identity/configuration, executable `PATH`,
  standard binary fallbacks, ignored/generated files, credentials, ports, and
  runtime state. A developer machine's installed tools or leftovers must not
  make a negative fixture pass or fail.
- Tamper tests for base64/base64url or other encoded cryptographic material
  must change a decoded byte (or assert the decoded bytes changed). Do not
  mutate a trailing encoded character and assume it changed the payload;
  alternate encodings can differ only in unused padding bits.
- A concurrency test must stub every capability check that precedes its
  intended blocking boundary, prove the worker reached that boundary, and
  include any worker error in a timeout failure. Do not mistake failure to
  satisfy a prerequisite for evidence about serialization or locking.
- Never launch a bare `python -m http.server` test fixture on macOS-capable
  paths. Its inherited `HTTPServer.server_bind` can block on reverse DNS after
  bind but before listen. Use the repository's fast-bind socketserver fixture,
  and keep the AST recall/control guard that rejects literal raw http.server
  argv in the coordinator self-test.
- When a deterministic test passes its own temporary paths into production
  code that rejects symlink components, canonicalize only the test-created
  temporary root before deriving fixture paths. Keep a separate must-catch
  case proving that an operator-supplied path component symlink is rejected;
  never weaken the production guard for a host-managed alias such as macOS
  `/var -> /private/var`. Canonicalize other test-owned temporary roots before
  asserting path identity, provenance, or persisted canonical paths.
- When a body operation and its cleanup, rollback, diagnostic collection, or
  restoration can both fail, the top-level redacted structured error must
  retain every operator-relevant failure. Tests must inject returned failures
  and invocation exceptions at each boundary; causes or exception notes that
  the CLI serializer does not expose are not sufficient evidence.

## Canonical skill ownership

- This repository is the only writable source for exactly
  `codex-dev-coordinator` and `postgres-docker-backup`.
- Install them only through `scripts/manage_skill_links.py` as direct absolute
  symlinks to this checkout. Never hand-edit a Codex, Claude, Parall, or other
  installed copy.
- Before relying on an installed skill, verify both direct `readlink` and
  canonical `realpath`. Preserve drift in a private rollback transaction and
  port intentional unique work here before replacement.
- Keep `SKILL.md` authoritative and mirror enforceable safety behavior in the
  deterministic self-tests.

## Repository independence and public history

- DevCoordinator must not acquire a source, build, runtime, test, CI, or pinned
  dependency on holyskills. `DEVCOORDINATOR_ROOT` is the only repository-root
  override for these products.
- Preserve the legacy Board bundle identifier/settings lookup solely for
  application identity migration; do not use it to resolve source.
- Keep actual environment files, credentials, private keys, runtime state,
  backups, logs, and rollback transactions outside Git. Only `.env.example`
  and provenance-bound deterministic fixtures may be published.
- Do not add non-canonical screenshots to reachable history. Run
  `scripts/check_repository_boundaries.py` before release.
- Record architectural decisions and later contradictions in
  `DecisionHistory.md`, including expected behavioral consequences.

## macOS app workflow

- Load and use the Build macOS Apps plugin before building, testing,
  snapshotting, packaging, launching, debugging, or automating DevOps Board.
- Do not use direct `swift`, `swiftc`, `xcodebuild`, XCUI, `open`, ad-hoc mouse,
  or keyboard control as a substitute.
- If the plugin is unavailable, stop the native gate and report it as pending;
  continue only non-native work.

## Services, Docker, and databases

- Before starting, stopping, restarting, or replacing a service, Docker
  resource, or local database stack, set
  `PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"` and run
  `python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py inventory --project "$PROJECT_ROOT"`.
- Every mutation must include `--agent "$USER"` and
  `--project "$PROJECT_ROOT"`. Lease ports; do not probe a default port and
  silently move after a collision.
- Register an already-running owned resource rather than creating a duplicate.
- Before destructive PostgreSQL-in-Docker work, create and verify a backup with
  `postgres-docker-backup` and bind every live operation to the expected
  immutable container ID.
- In system-level systemd units, never use `%h` to address a non-root
  `User=` service account's home. The system manager resolves `%h` from its
  own root context before the service changes user. Pin the intended account
  home (or use a deliberately configured systemd-managed directory), reject
  manager-home paths in deterministic unit checks, and inspect resolved
  `ExecStart`, `Environment`, and file paths with `systemctl show` before the
  first production start.
- Effective-unit tests must use the target systemd version's real `show`
  serialization, including properties it omits when undefined. Treat a missing
  property as empty only for an explicit per-unit allowlist backed by real
  output and must-reject non-empty override fixtures; never apply a global
  missing-as-empty normalization to security-relevant unit properties.
- During an existing-host Console cutover, preserve checksummed per-process
  evidence for repeated clean cgroup samples and recheck immediately before
  stop. Every copied mutation phase must enable fail-fast shell semantics.
  Never treat state copied while a writer is active as lossless; checkpoint
  only after verified shutdown and immediately before relocation, and bind
  rollback to durable phase markers. Parse Linux `/proc/PID/stat` around its
  final parenthesized `comm` delimiter and use pidfds for signaling so PID reuse
  cannot redirect a signal. After the legacy writers are stopped, normalize both external
  state trees to private modes and rerun production layout preflight before
  state migration, relocation, or new-unit start.
- Treat the writer-free post-stop checkpoint through successful relocation as
  an operator-exclusive coordinator mutation window. Do not run another API or
  coordinator CLI against that home until relocation is committed or rollback
  is complete.
- When one Linux service discovers another service's listener through
  `/proc/<pid>/fd`, model the target's effective capability set in both the
  service design and its tests. Same UID is not sufficient: a process carrying
  a permitted capability can make its fd/cwd links unreadable to an otherwise
  unprivileged peer. A capability-matched observer must clear ambient and
  inheritable capabilities before it can exec managed children, and tests must
  prove those children receive empty inheritable, permitted, effective, and
  ambient sets. The coordinator must not narrow the system manager's bounding
  ceiling merely to constrain its own observer capability: a bounding ceiling
  is not an active capability, and narrowing it would mask legitimate file
  capabilities on managed executables.
- A production Console cutover is not healthy merely because ports 80/443 and
  `/healthz` answer. Its coordinator registration is required and must prove
  the exact relocated server identity is running, healthy, bound to the
  systemd MainPID, and linked in both directions to one active replacement
  lease and the exact durable assignment. Exercise the capability-asymmetric
  split-unit topology; an ordinary same-process listener fixture is not enough.
- Never trust a caller-supplied registration PID only because it is alive.
  Registration must prove readable project ownership and that the exact PID
  owns a LISTEN socket for the declared port. Keep must-reject controls for a
  same-project non-listener, foreign listener, dead PID, wrong port, and
  unreadable process identity.
- Treat listener identity as tri-state. If ownership is unobservable, every
  server or project lifecycle mutation must fail before it writes an operation,
  changes lifecycle or lease state, sends a signal, launches a process, acts on
  Docker, or records sidecar metadata. Status and inventory may return the
  unknown observation but must preserve the last strictly proved lifecycle and
  lease. Never coerce unknown ownership to false through truthiness.
- When a lifecycle command combines pending-operation exclusion with an
  out-of-lock safety preflight, check the existing conflict read-only before
  interpreting preflight fingerprint drift, then repeat the conflict check at
  reservation. A pending operation can legitimately cause the observed state
  change; report that actionable conflict instead of misclassifying it as a
  generic retry race.
- Treat procfs symlink readability as a tri-state security boundary. Read
  `/proc/PID/cwd` with `os.readlink` and require a concrete strict target;
  never use a best-effort path normalization that can turn `EACCES` into a
  path-like error string. Permission denial is unknown ownership, not foreign
  ownership evidence.
- Preserve that ownership tri-state for every managed and adopted server, not
  only rows carrying explicit registration evidence. On non-Linux platforms,
  `lsof` exit 1 is a clean no-match only when it has no diagnostic output;
  permission/error diagnostics make the observation unknown. Read-only status
  and inventory must never convert observer failure into a stopped row or
  release its lease.
- A successfully completed process-cwd probe with no concrete cwd is only a
  negative probe result. It is not positive project attribution for a live
  managed PID. Preserve that live server as unverified and forbid lifecycle
  mutation until a concrete cwd proves ownership.
- Do not use `kill(pid, 0)` alone as process-liveness evidence: it succeeds for
  unreaped zombies. Prove that a PID is non-zombie before treating retained PID
  metadata as a live ownership boundary; keep observer failure conservative.
