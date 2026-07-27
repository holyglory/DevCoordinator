# DC-2026-07-26-MAINTENANCE-01 — Supporting record

## Context

The production broker must cross an offline SQLite schema and protected-profile
boundary. New clients cannot speak safely to the old broker protocol, and the
authority database cannot truthfully carry an availability message while it is
closed for migration. The public Console and loopback API are already separate
systemd availability boundaries.

## Options considered

- Let callers receive socket errors. This requires every agent and UI to guess
  whether the failure is transient and provides no bounded retry instruction.
- Stop broker, API, and Console together. This is simple but unnecessarily
  removes the public TLS edge and its honest maintenance/error presentation.
- Store maintenance state beside the broker socket. This initially looked
  local and convenient, but systemd removes the broker runtime directory on an
  intentional stop, erasing the state at the exact offline boundary.
- Store maintenance state in SQLite. That couples the message to the database
  that must be unavailable and makes pre/post-schema readers disagree.
- Use a separate protected runtime marker. This keeps the response independent
  of broker process, socket, database, and wire-schema lifetimes.

## Selected contract

`/run/devcoordinator-maintenance` is created as `root:devcoordinator-clients`
mode `0750`; its marker and writer lock are regular no-follow files mode
`0640`. The exact document is bounded and contains version, active status,
canonical deployment UUID, trimmed operator message, retry interval, and UTC
start time. Client reads verify parent/file ownership, modes, identity
stability, size, JSON fields, and values. Writer operations serialize, publish
without overwrite, fsync, and only clear the matching deployment UUID.

Every normal and descriptor-returning broker call checks the marker before
socket access. Active state returns `maintenance_in_progress`; invalid or
untrusted state returns `maintenance_state_invalid`; both are classification
`maintenance` with a bounded retry and an instruction to wait. Agents must not
bypass the fence with lower-level host access.

## Deployment and recovery

One root foreground transaction owns an outer deployment lock and the marker.
It verifies a pre-migration backup, terminal operation state, and rollback
material before stopping the Console, API, and broker writers. It creates and
verifies writer-free checkpoints for both the service authority and per-user
client reconciliation journal before either crosses its schema boundary. It
performs the installer/profile/schema transition and proves the exact target
broker active while the fence remains.
API readiness and Console self-registration intentionally require normal broker
traffic, so the transaction clears the owner-bound marker immediately before
starting those independently supervised services, then proves authenticated
inventory, exact Console registration/assignment/lease, and public routes. A
later failure first republishes the same owner-bound maintenance state and only
then restores the exact stopped database and installation transaction, starts
the compatible services, proves the old readiness graph, and clears it.
Checkpoint restore stages and checksums every file before atomically replacing
the live SQLite names, so a concurrently recreated empty database cannot win a
slow multi-gigabyte copy window. The marker does not claim that unsupported
runtime, database cancellation, or replay combinations are implemented; those
remain fail-closed Completion Ledger work.

Console listener adoption first reconciles any saved active client link. The
broker permits a repeated release only after the normal peer, account,
repository, resource, and lease authorization succeeds, and returns the exact
already-released lease without another generation change. The client then
records that link released before reserving and binding its replacement. This
preserves evidence across a crash between authoritative release and client
journal completion without deleting local state or weakening the one-active
lease invariant.

## Verification

Focused tests cover active/absent behavior, malformed modes and content,
symlink refusal, descriptor transport, deployment-bound clear, competing
publication, removal of the separate broker runtime directory, inventory above
the former 8 MiB ceiling and the new hard bound, atomic replacement against a
recreated database target, post-clear fence reactivation, and legacy Console
state privacy normalization. The deployment self-test additionally requires
all three writers to stop before dual checkpoints, restores the client journal
before compatibility source, runs the private authentication probe as its
actual account, and normalizes the Console identity before and after rollback
startup. Broker/link regressions prove authorized repeated release,
foreign-owner rejection, and release-before-reserve listener adoption in both
normal and optimized Python. Installer tests require the independent tmpfiles
entry. Release validation and the live cutover must additionally prove the same
authenticated and public surfaces used in production readiness.

## Live cutover evidence

The 2026-07-26 production cutover exposed two recovery gaps before readiness:
the original transaction checkpointed only the authority database while the
API/Console client journal crossed the schema boundary, and Console listener
adoption attempted a replacement reservation while its saved link still
appeared active even though the broker had already released the exact lease.
The strengthened guards reproduced both cases before the fixes. Normal and
optimized full skill self-tests and focused broker/link suites passed before
activation.

The final cutover migrated both databases to schema 12, restarted the broker,
API, and Console under systemd, and cleared maintenance only after the broker
ready event. Systemd's capability-matched Console `ExecStartPost` proved PID,
listener, working directory, assignment, active lease, and exact server ID.
Read-only checks returned `integrity_check=ok`, no foreign-key violations, no
planned/running operations, the prior Console lease released, and exactly one
replacement active. Server-wide normalized inventory reported that exact
Console PID healthy and running. The public Console health endpoint and the
Console, gf2, and PRTZN HTTPS/auth journeys returned 200; effective loaded
systemd paths passed their production preflight; all three units were enabled
and active; and the owner-bound maintenance marker was absent.
