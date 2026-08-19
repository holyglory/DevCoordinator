# DevCoordinator Agent Instructions

These rules apply to every agent working in this repository.

## Work from current, preserved source

- Before broad changes, run `python3 scripts/check_repository_freshness.py --repo "$PWD" --json`.
- Reconcile `behind`, `diverged`, and `dirty-on-stale-base` without resetting,
  rebasing, stashing, cleaning, or overwriting valuable work.
- This checkout is the only writable source for both skills. Install links only
  with `scripts/manage_skill_links.py`; never edit installed copies.
- Keep credentials, environment files, logs, backups, runtime state, rollback
  data, and non-canonical screenshots out of Git.

## Delegate runtime coordination to Python

- Ordinary source inspection, editing, formatting, and static checks do not
  need a Coordinator preflight or inventory call. A direct local test is
  permitted only when its selector is proven before launch to collect at most
  20 cases, a runner deadline limits execution to at most 10 seconds, it needs
  no host-visible or shared state, and it is not one fragment of a suite split
  across repeated local commands. Use one Coordinator test enqueue when either
  bound is unknown or exceeded, or when durable shared evidence is required.
- Never start, stop, restart, replace, remove, or inspect a process, Docker
  resource, Compose stack, or local database directly. Use:
  `python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py runtime --help`.
- Use runtime flags for ordinary status/start/stop/restart/remove calls. Use a
  request file only for a structured definition, replacement, or bounded run;
  never hand-build JSON in routine shell/Python wrappers.
- Every runtime request must identify the agent, original root repository, and
  an explicit nullable temporary repository. Use immutable resource IDs; do not
  infer ownership from names, ports, image names, or paths in UI code.
- Test/temporary start-like actions require a positive TTL; every request has
  an explicit `kill_after_run` boolean. Let the runtime session own cleanup; do
  not hand-roll traps, background killers, port probes, or database-row deletion.
- Treat `ok=false`, unclassified resources, unknown listener ownership, stale
  identity, or incomplete cleanup as failure. Preserve the returned operation,
  artifact, and log links.
- Register an already-running, provably owned resource instead of creating a
  duplicate. Never move to another port after a collision unless the user
  explicitly changes the durable assignment.
- For a persistent worker, set `keep_alive` explicitly on first start. A crash
  loop stays stopped until an attributed start explicitly re-arms it. Remove
  through the returned archive and permanent-cleanup plans; never delete rows
  or native service registrations directly.
- Before destructive PostgreSQL-in-Docker work, use `postgres-docker-backup`
  and bind the operation to the verified immutable container ID.

## Product boundaries

- One canonical Git worktree is one repository/project. Python owns the
  root-repository -> temporary-repository -> service hierarchy and exact
  non-authorizing association. Board and Console only render the returned tree
  and action context.
- Keep listener/process ownership tri-state and fail closed when it is not
  observable. The executable guards and tests—not agent prose—own platform,
  capability, PID-reuse, transaction, and cleanup details.
- DevCoordinator must remain independent of holyskills.

## Native and verification work

- Use Build macOS Apps before any Board build/test/run/package/automation work.
- Reproduce reported failures when feasible and strengthen the nearest
  regression guard, but do not replay the whole suite after each small edit.
- Accumulate related edits, then run one software-owned validation cycle that
  records every independent failure. Batch-fix the report and repeat the whole
  cycle once. DevCoordinator delivery uses
  `scripts/software_owned_delivery.py`; do not reconstruct its test, package,
  deploy, and browser workflow manually.
- Never use the installed DevCoordinator skill, `devcoordinator test`, runtime
  orchestration, or installation surfaces to test or install DevCoordinator
  itself. That creates a circular self-hosting dependency on the product under
  repair. The repository-owned `scripts/software_owned_delivery.py` workflow is
  the sole complete verification and delivery authority for this repository.
- Before readiness, the accumulated cycle must include repository boundaries
  and the applicable repository validation. Report unresolved ledger items as
  incomplete; never describe partial or unverified behavior as ready.
