# DC-2026-07-20-CONSOLE-RESILIENCE-01 — Listener availability does not cascade through control dependencies

## Supporting record

Decision: Treat the public Console, authenticated loopback API, and
server-wide broker as separately supervised availability boundaries. The
Console uses `Wants=` plus `After=` for the API, and the API uses the same soft
startup relationship for the broker. Both listener services use
`Restart=always` with a three-second backoff so a failed or unexpected clean
daemon exit is restarted; systemd still honors an explicit unit stop. Console
startup remains fail closed behind its exact MainPID/listener/health/
assignment/lease registration gate, and API startup remains fail closed behind
its authenticated `200/401/200` boundary probe.

Journald is the only durable service log sink. The units pin stdout and stderr
to the journal, stable `devops-console` and `dev-coordinator` identifiers, and
a bounded high burst allowance. The Console installs process lifecycle
handling early, treats unhandled rejections and uncaught exceptions as fatal,
runs bounded cleanup, and logs fatal trigger, shutdown result, cleanup
failures, elapsed time, and readiness before systemd observes the exit.

Why: On 2026-07-20 at 01:36:40 UTC, the sudo audit journal proved UID 1001
running `systemctl stop dev-coordinator.service` from the GlobalFinance
checkout during an offline enrollment. The then-loaded hard `Requires=` edge
caused systemd to send SIGTERM to the Console. The Console logged shutdown and
listener closure, exited zero, and systemd recorded a successful stop with no
restart. The maintenance sequence later started the broker and API only;
starting a required unit does not start its reverse dependents, so ports 80 and
443 remained absent and the exact public login URL returned connection
refused. There was no crash, OOM, core dump, DNS fault, or firewall fault.

Options considered:

- Retaining hard `Requires=` edges plus runbook discipline was rejected because
  that exact manual restore workflow had already omitted the Console and caused
  the recurrence.
- Changing only to `Restart=always` was rejected because systemd deliberately
  suppresses every restart policy for a stop job; it would not fix the observed
  cascade.
- A systemd `Upholds=` stack supervisor was rejected for this boundary because
  it would immediately counter an intentional independent service stop and
  require a separate maintenance-mode control plane.
- Soft startup ordering plus independent supervision was selected because it
  keeps listeners available while dependency-backed requests fail closed and
  naturally recover, yet preserves explicit maintenance stops and all existing
  readiness/security checks.

Prevention evidence: the deployment test first failed on the old hard Console
dependency, then on the adjacent hard API dependency. Source/effective-unit
guards now reject either hard edge, any non-`always` listener restart policy,
journal sink/identity/rate-limit drift, duplicate relationship fields, and
startup/readiness drift. Real `systemd-analyze verify`, the Console deployment
test, and the loaded-unit recall/false-positive self-test pass. Production
activation used the private rollback transaction
`/var/lib/devcoordinator-install/20260720T115733Z-console-resilience`; its
verified manifest retains the prior and installed units, loaded-unit evidence,
sudo provenance, incident and recovery journals, listener state, persistent
journal evidence, and exact public response bytes.

The original path was then reproduced through the live service manager.
Stopping `dev-coordinator.service` left Console PID 38979 active with ports 80
and 443, while both `/healthz` and the exact requested login URL returned HTTP
200. Restarting the API passed its authenticated `200/401/200` boundary and did
not change the Console PID. SIGKILL of API PID 76692 produced systemd result
`signal`, incremented its restart counter, started PID 99410, and restored the
authenticated boundary while the public URL remained 200.

Console fault injection then covered both unexpected clean and crashed exits.
SIGTERM of PID 38979 logged `shutdown started`, listener closure, and
`shutdown complete` with exit zero, five milliseconds elapsed, and zero
cleanup failures before systemd restarted PID 123449. SIGKILL of PID 123449
recorded status `9/KILL` and systemd restarted PID 136789. Both replacements
passed the exact bounded registration gate and restored public health/login to
HTTP 200. Final server-wide inventory proves server
`144ba3fb-9939-5a81-91b1-f1bb3a5db418`, assignment
`/home/DevCoordinator::devops-console`, active lease
`ed23f012-e5b8-49a7-9372-d8b34247b1ce`, owner PID 136789, port 443, healthy
status, no lifecycle violations, and no active operations.

Final verification: the complete DevOps Console suite passes 217/217,
including its full TLS/auth/proxy/WebSocket/coordinator journey. The first full
run exposed one preexisting corrupt-policy fixture that inherited the host
umask and therefore failed the production private-mode gate before exercising
corruption recovery; pinning that test-created file to mode `0600` made the
fixture deterministic without weakening production. The focused lifecycle
suite passes 22/22, loaded-unit must-catch/false-positive tests pass,
`systemd-analyze verify` passes, the repository boundary/reachable-history
guard passes, `git diff --check` passes, and the trusted public TLS login and
health requests both return HTTP 200.
