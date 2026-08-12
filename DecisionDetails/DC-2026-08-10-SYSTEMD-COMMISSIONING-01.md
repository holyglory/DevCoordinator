# DC-2026-08-10-SYSTEMD-COMMISSIONING-01

The user approved implementing a narrow root administrative commissioning
capability while explicitly withholding authorization to run the GlobalFinance
retention unit during this task.

The immutable release publishes `devcoordinator-systemd-unit`. A selector maps
only to `deploy/systemd/<unit>.service` and an optional same-name `.timer`
beneath the canonical project. The service must be a non-root `Type=oneshot`
with one absolute `ExecStart`, no auxiliary Exec actions, no privileges, strict
system protection, and an exact timer binding when present. No caller payload,
source path, command, user, group, timer target, or systemd option crosses the
interface.

`plan` and `status` perform no mutation. `apply` revalidates the project inode,
source hashes, installed hashes and systemd state against the confirmed plan.
It journals the operation before mutation and distinguishes commissioning,
one-shot execution, timer enable, and timer disable. Exact replays repair
idempotent commissioning/timer operations; a one-shot is never repeated after
an uncertain journal boundary unless a changed invocation ID and successful
terminal systemd result prove the prior execution.

Verification requires source-policy failures, source-change rejection, exact
installation with no activation, one-shot replay without re-execution, timer
selection, release packaging, installed help/capability discovery, and an
installed plan/status canary. A particular one-shot start or timer enable still
requires its own confirmed apply fingerprint and operation UUID.
