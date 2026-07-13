# Decision History

## 2026-07-11 - The final legacy-cgroup gate is a handoff, not a second quiescence window

Decision: Existing-host cutover keeps the initial five-second exact-cgroup
window as the durable proof that the legacy topology is the captured Console
and coordinator pair. After installing the temporary `KillMode=process`
override, the final just-in-time handoff requires a 250-millisecond exact
window immediately before the stop marker. After stopping the Console main PID
and terminating the captured coordinator through its pidfd, the stopped
boundary waits up to ten seconds for already-started transient descendants to
exit. It retains each observed cgroup member's PID and process start time for
the whole wait, refusing a child that escapes the cgroup but remains alive, as
well as any surviving captured process or listener. State capture and migration
remain forbidden until that post-stop boundary succeeds and its JSON evidence
is stored in the private backup, immediately bound into the verified manifest,
and rechecked before the first writer-free state copy.

Why: Retry 12 passed its initial five-second proof with 247 observations, then
failed closed before the stop marker because the redundant second five-second
window never became quiet for a full five seconds. Its ledger recorded 91
membership transitions and a 4.871-second longest clean interval. The extra
members were short-lived `git` and Docker inspection processes spawned by the
live coordinator while the Console and browser clients sampled real inventory;
they were expected descendants, not unknown long-lived writers. Requiring a
second five-second idle period made normal production activity a false abort.
The failure handler removed the override with `prestop_cleanup_rc=0`; the exact
legacy PIDs, listeners, external files, and public TLS health remained intact.

Result: The first window still catches persistent or foreign cgroup ownership.
The short final window minimizes the handoff race, and the bounded post-stop
wait closes it: a child that starts immediately after the handoff must disappear
before any writer-free snapshot, while a persistent process or listener still
forces rollback. The phase marker and in-memory rollback flag are the only
transaction steps between the final handoff and `systemctl stop`; the post-stop
gate protects that unavoidable residual interval. Detector tests cover
realistic transient exit, cgroup escape without exit, persistent timeout, live
listener timeout, permanent evidence failures, clock failures, and already-clean
controls.

## 2026-07-11 - Retired checkout assignments require an explicit migration disposition

Decision: Existing-host cutover must enumerate every durable port assignment
owned by the retiring checkout before the service-stop boundary. The Console
443 assignment is relocated with its captured server identity. Every other
assignment must have an explicit, hash-bound disposition: migrate it only when
the corresponding feature and runnable command moved, or unassign it only when
the captured inventory proves it is stopped residue with no active lease or
listener. Unknown or current assignments abort before stop. Cleanup is an
exact allowlist revalidated against global raw state and applied as one commit
under the coordinator state lock. It runs only after the pre-relocation state
checkpoint and before the separate relocation transaction, whose normal state
maintenance can prune the stopped-server evidence. Rollback restores the
complete original assignment map while holding the same state lock. Blanket
project-wide unassignment is forbidden. A name-plus-port unassignment must
conjoin both selectors; `--port` may not be advisory when `--name` is present.

Why: The first transaction from the verified retry-11 backup successfully
started both split services and passed the coordinator authentication and
Console registration readiness gates. The post-cutover verifier then found
three remaining durable assignments under the legacy `$HOME/holyskills` and
failed closed. They were stopped real test/demo servers (`web-demo` on 3000,
`ws-echo-demo` on 3001, and `demo-web` on 3002), had no active lease or
listener, and their commands or captured working directories referenced the
retired checkout. Relocating them
would create broken DevCoordinator records; retaining them would reserve ports
for a retired owner. The candidate relocated only the Console assignment and
did not inventory-classify its siblings. The verifier already had the correct
must-catch rule, so this was an operational migration gap rather than a
detector miss.

Result: The transaction rolled back with `rollback_rc=0`. Its checksummed
rollback evidence proved the exact legacy Node/coordinator cgroup, listeners
80/443/29876, captured Console server ID with a replacement active lease, and
local TLS health; five subsequent public probes returned HTTP 200 with TLS
verification zero. The failed attempt's backup and manifest are retained. The next
attempt uses a fresh backup and an explicit allowlist for only those three
stopped residues. Deterministic tests require extra, missing, current,
repinned, leased, listening, live-PID, pending-operation, malformed, and
partial-mutation cases to fail without committing state; unrelated assignments
must remain byte-for-byte unchanged.

## 2026-07-11 - Legacy rollback readiness includes coordinator registration

Decision: Rollback terminal success now requires the restored Console's exact
current coordinator graph in addition to systemd identity, process/cgroup
identity, listener ownership, and public TLS. The verifier queries only the
credential-free IPv4-loopback legacy `/v1/inventory` endpoint, binds its port
to the exact child argv/listener already under observation, and uses the
captured pre-cutover server ID with the old project, `devops-console`, port 443,
and restored systemd MainPID. It retries only the captured server's exact 40a
stopped/dead graph: exact old PID/cwd/project, exact stopped health/check/
identity proof, and the captured pre-cutover lease ID dangling after its lease
row was pruned. Clean absence and assignment-only unregistered state are
terminal identity loss because old `register_server` creates a new UUID when
the server record is absent. Any relevant active lease or current graph that
fails identity, health, assignment, or linkage; any foreign claim; and any
transport, HTTP, protocol, or JSON failure is terminal. A ready graph may use
only the replacement lease created while restoring the captured server ID;
its lease ID must differ from the captured pre-cutover ID and no row with the
captured lease ID may survive. One
monotonic deadline covers topology, TLS, graph convergence, a fresh post-graph
listener-owner snapshot, and the final topology confirmation. Evidence contains
only the small allowlisted verifier result, never raw inventory or credentials.

Why: The legacy Node process catches a failed coordinator `server register`
attempt and continues serving HTTPS. The previous rollback verifier could
therefore declare success after proving listeners and TLS while the restored
Console was still absent from coordinator inventory. Production evidence also
showed that the old coordinator predates `registration_identity`, listener
inode fields, and lease `assignment_key`; applying the new binary's schema
literally would reject the real healthy legacy graph. The shared graph verifier
now has an explicit legacy contract that keeps every assignment, server,
MainPID, cwd, health identity/check, active lease, and bidirectional link the
old binary can emit. Its default current contract remains unchanged, while the
rollback verifier separately proves exact listener PIDs. The retained
pre-relocate checkpoint and an isolated real 40a API reproduction also proved
the exact precursor the earlier fixtures missed: `locked_state` prunes the dead
PID's active lease first; `build_inventory` then marks the captured server
stopped while preserving the now-dangling old lease ID. Absence cannot preserve
identity because registration generates a fresh UUID.

Result: Realistic regression fixtures cover delayed stopped-to-ready
registration, permanent timeout, terminal absent/unregistered identity loss,
wrong captured/current server and lease identity, MainPID, exact stopped
health/check/identity/classification, assignment, and foreign current
claims. Actual loopback HTTP fixtures cover credential omission, status,
content type, malformed JSON, and non-object roots; both normal and `python -O`
CLI paths pass and raw future inventory fields are proven absent from the
private checksummed ledger. Production-shaped coverage accepts only the exact
stopped server with a dangling captured lease ID and rejects surviving active
lease state, malformed stopped proof, or rollback MainPID. Post-inventory wrong and ambiguous
listener-owner swaps are also terminal, and the HTTP fixture avoids macOS
reverse-DNS binding by using `ThreadingMixIn` with `TCPServer`.

## 2026-07-11 - Private cutover helpers have a tracked executable CLI contract

Decision: Validation invokes all seven repository helpers used by the private
production cutover as real subprocess CLIs with the exact candidate flag
combinations. The matrix covers token-required layout waiting, state-only
migration, captured coordinator termination, the three stopped-listener ports,
authenticated inventory evidence, every Console registration readiness flag,
and loaded-unit evidence. It runs normally and with optimized Python, rejects
argparse/usage exit 2 explicitly, and uses private fake systemd, socket, HTTP,
process, and state fixtures instead of production resources.

Why: Shell syntax checks and direct function tests cannot prove that a private
retry script still matches a deployed helper's argparse interface. A renamed,
missing, or misclassified option could otherwise remain invisible until after
the legacy service had been stopped.

Result: CLI drift is now a pre-cutover validation failure. Linux exercises the
complete MainPID/procfs and loaded-systemd success paths; platforms without the
required Linux kernel surfaces must still reach an exact helper-specific
post-parse result and can never pass on an argparse error. No service, private
cutover script, or server state is touched by this matrix.

## 2026-07-11 - Executable validation follows Git semantics across safe umasks

Decision: Deployment tests require the Console readiness helper to retain all
three executable bits and reject world-writable materializations. They accept
both the ordinary `0755` checkout mode and the safe group-shared `0775` mode.
The detector carries explicit true controls for both modes and must-catch
controls for non-executable `0644`/`0664` and world-writable `0757`/`0777`.

Why: The exact server-side validation reproduced one failure after all six CI
jobs and a local fresh clone passed. Git's index correctly recorded the helper
as `100755`, but `/home/DevCoordinator` is a group-shared checkout with umask
`0002`, so Git materialized the executable as `0775`. The test compared the
complete permission value to `0755`, confusing a host checkout policy with
Git's executable-bit contract. Every CI and local clone used an environment
that materialized `0755`, so none exercised the legitimate shared-checkout
case.

Result: The detector still fails if the helper loses executable permission or
becomes writable by unrelated users, while validation is portable across the
two actual checkout policies. The production service was not touched while the
gap was reproduced and corrected; the server remained on its healthy legacy
unit throughout.

## 2026-07-11 - Console readiness is the registered MainPID graph, not process creation

Decision: `devops-console.service` has one pinned `ExecStartPost` that receives
systemd's `$MAINPID`, proves the unit PID/cgroup and the process start/argv/cwd
identity remain stable, reads the private coordinator token, and observes the
authenticated `/v1/inventory/no-docker` graph until the exact current Console
assignment, server, listener identity, health, and lease linkage converge. The
80-second observer retries only explicit loopback transport startup, clean
absence, an exact relocated stopped record, or an exact ordinary-restart
stopped record whose old PID is proven dead and whose referenced lease is
inactive. A raw pre-registration listener is retryable only when its observed
PID is the systemd MainPID and its project/cwd remain inside the canonical
checkout. Current/foreign port ownership, an active lease, identity drift,
wrong HTTP/auth semantics, malformed evidence, and deadline overrun fail
immediately. `TimeoutStartSec=90` bounds the complete unit start transaction.

Why: `Type=simple` establishes only that Node was spawned. Console listener
creation and its coordinator registration occur afterward, so a successful
`systemctl start` previously did not itself prove that production inventory
contained the running systemd MainPID. A runbook `sleep 2` plus a later
cutover-only verifier made correctness depend on timing and did not protect
ordinary boots or restarts.

Result: The coordinator now exposes an authenticated no-Docker inventory route
whose observation does not depend on Docker availability. Current-graph
validation is shared with the stricter cutover history verifier. Regression
coverage runs normally and with `python -O`, covers real evidence-shaped clean,
relocated, and restart-stale states, must-catch live/active/foreign conflicts,
process/unit drift, terminal deadline crossing, explicit transport startup,
and a delayed graph around a real listener on Linux. Loaded-unit, deploy,
repository-boundary, and runbook checks pin the exact helper argv, uniqueness,
and deadlines.

## 2026-07-11 - Split-service and rollback readiness require proven convergence

Decision: `dev-coordinator.service` now remains in its systemd start transaction
until a pinned `ExecStartPost` proves the loopback API's exact anonymous and
authenticated contract (`/healthz` 200, anonymous `/v1/inventory` 401,
authenticated inventory 200). The probe uses one monotonic deadline across all
three requests, retries only an atomically pending token or explicit transport
startup errors, and immediately rejects unsafe credentials, protocol errors, or
wrong HTTP semantics. `TimeoutStartSec` bounds the unit, and the loaded-unit
verifier pins the exact post-start command and timeout so ordinary boot receives
the same protection as a manual cutover.

Legacy rollback has a separate bounded convergence verifier. It fixes the
restored systemd MainPID and cgroup, repeatedly proves stable process start/argv
identities, tolerates only temporary missing coordinator/listeners/TLS transport
and transient attributed children, and requires exact listener ownership
(80/443 by Node, 29876 by the old-checkout coordinator) plus HTTPS 200 with
certificate verification. The final listener snapshot is bracketed by fresh
identity/cgroup confirmations, and every observation and terminal result is
private and checksummed. One-shot `0600` cutover artifacts are invoked explicitly
through Bash rather than relying on an executable bit.

Why: The first transaction from the verified `8a892dd` backup started the new
`Type=simple` coordinator at 15:43:44.398 UTC, but the API did not announce its
bound URL until 15:43:44.727. The immediate one-shot auth check connected during
that 329 ms interval and received `ECONNREFUSED`. Rollback restored the legacy
unit at 15:43:46.621; its child coordinator was ready first, a one-shot `ss`
snapshot at 15:43:47.261 saw only 29876, and Node bound 443/80 at 15:43:47.737.
The old verifier therefore reported rollback failure about 476 ms before the
correct listeners appeared, even though the legacy service recovered.

Result: The failed attempt is retained with a verified 898-file manifest and
terminal evidence. The restored legacy service has the original checkout path,
one active legacy Console registration, three routes, three hidden-preference
owners/five hidden items, exact environment and state-file checks, and repeated
public HTTPS 200/TLS-verification-zero health. Regression coverage now includes
a real delayed coordinator subprocess/socket and CLI, permanent absence,
reachable wrong auth, malformed protocol, unsafe and delayed tokens, global
deadline overrun, delayed rollback listeners/TLS, wrong or ambiguous owners,
PID/start/argv/cgroup drift, post-health races, transient children, and a real
helper CLI with isolated systemd/ss/curl fixtures. A failed attempt is never
reused; the next cutover starts from a fresh backup and exact reviewed hashes.

## 2026-07-11 - Cutover helper interfaces are executable contracts

Decision: The durable marker helper supports and tests the complete transaction
lifecycle: `cutover-run-started`, `service-stop-attempted`,
`state-migration-attempted`, `relocation-attempted`, and `cutover-success`.
Its self-test invokes the real subprocess CLI for every supported phase, in
addition to testing atomic exclusivity, private modes, invalid phases, and
symlink refusal. A production candidate must exercise every repo-helper
subcommand and flag combination against the exact deployed commit; `bash -n`
alone is only shell syntax evidence.

Why: A private one-shot cutover candidate was shell-syntax valid but used three
phase strings that the deployed helper's argparse contract rejected. Earlier
attempts had stopped before those calls, and direct-function tests covered only
the two original state-mutation phases, so neither path exercised the real CLI
boundary. The mismatch was found during pre-cutover interface inspection before
the production service was stopped.

Result: All five lifecycle markers are now one durable implementation contract,
the exact CLI mismatch is a permanent must-catch fixture, and staged cutover
validation includes helper-interface smoke tests before any service mutation.

## 2026-07-11 - Cutover readiness is a bounded observed-clean window, not lucky point samples

Status: Superseded in part by “The final legacy-cgroup gate is a handoff, not
a second quiescence window” above. The first five-second topology proof remains;
the redundant second five-second window is now a 250-millisecond handoff plus
the identity-retaining bounded post-stop drain.

Decision: Existing-host cutover now waits for one five-second observed-clean
legacy cgroup window before the runtime override and another five-second
observed-clean window immediately before stop. The verifier uses bounded
user-space polling at 20 ms or tighter; it is not a kernel-continuous monitor.
It durably records every observed membership/identity transition and one-second
checkpoint, resets on every extra child or overlong observation gap, fails
immediately when a captured PID disappears/reuses/changes identity, and fails
on timeout when no full window exists. Each observation reads cgroup membership,
reads stable identities, confirms membership again, and then rereads every
confirmed identity; a PID reused between those passes is therefore unsafe, not
clean. No child command is allowlisted. Only a
terminal successful ledger is evidence: `SIGKILL`, host power loss, or storage
loss may leave `running` or incomplete evidence, which never counts as success.
Every attempt receives a new timestamped backup path, and every backup is
retained after success or failure.

Why: Production retry evidence showed the legacy coordinator legitimately
spawns Git root discovery and Docker `ps`, `stats`, and `inspect` children while
the Console samples inventory. A 30-second 5 ms trace captured 182 membership
changes. Internal exact gaps reached about 3.3 seconds, while true inter-cycle
gaps were about 6.4 seconds. The old five point samples could fail randomly on
an attributed child or, conversely, miss activity between samples. Operator
attempts that tuned a point-in-time precheck merely moved the race; every one
failed before the stop marker and left the legacy TLS service healthy.

Result: The realistic self-test includes a 3.2-second internal clean gap that
must be rejected, a later five-second inter-cycle window that must pass, a
periodic-child workload that must time out, and captured-PID reuse that must
fail immediately rather than being waited through, including reuse on the
would-be terminal success observation between the first identity pass and the
confirmed membership/identity pass. The durable ledger retains
the attributed transient command/start evidence and its own verified checksum.
There remains a bounded interval between verifier return and `systemctl stop`;
the runtime `KillMode=process` override prevents a newly appearing child from
being hidden by the Console stop, and the immediate post-stop exact
identity/cgroup/listener verifier rejects survivors before any state copy.

## 2026-07-11 - Split-service listener discovery must capability-match without capability propagation

Decision: The production coordinator process will receive only
`CAP_NET_BIND_SERVICE`, matching the Console capability that makes Linux allow
the coordinator to inspect the Console's `/proc/<pid>/fd` and `cwd` evidence.
At API startup the coordinator must immediately clear its ambient and
inheritable capability sets while retaining the effective capability needed by
the long-lived observer. Every subsequently exec'd managed child must therefore
start with empty inheritable, permitted, effective, and ambient sets. Production
Console self-registration is required rather than best-effort. Explicit
registration PIDs must independently prove exact LISTEN-socket ownership and a
readable cwd inside the canonical project. The production registration and
post-cutover gates require `/healthz` to return exactly HTTP 200; a redirect is
not accepted as service health. The public TLS evidence also requires status
200 and curl's certificate verification result zero; `--fail` alone is not
sufficient because curl accepts 3xx responses. The post-cutover gate must validate
the full assignment/server/lease graph and the systemd MainPID, not merely the
presence of rows on port 443.

Linux Console registration requires procfs socket-inode evidence. Optional
non-Linux direct Console runs accept the coordinator's platform-specific
listener proof, because they do not expose Linux procfs inodes; that fallback
is rejected when `process.platform` is Linux and is never accepted by the
production post-cutover verifier.

The production unit continues to omit `NoNewPrivileges`: this is a generic
process coordinator whose managed children may have legitimate executable
privilege semantics. It also leaves the system manager's capability bounding
ceiling unchanged. A bounding ceiling is inherited but is not an active
capability; narrowing it would silently mask legitimate file capabilities on
managed executables. The non-propagation claim and test are therefore
explicitly limited to inheritable, permitted, effective, and ambient sets on
ordinary managed executables, while separately proving that the child's
bounding ceiling matches the coordinator's inherited manager ceiling.

The Console production listener is explicitly bound to IPv4 wildcard
`0.0.0.0`, while registration and health use `127.0.0.1`. This replaces Node's
platform-dependent omitted-host IPv6 dual-stack default, matches the deployed
IPv4-only DNS records, and makes address-specific listener ownership
deterministic. The server test verifies the real TLS listener reports an IPv4
wildcard address and answers through IPv4 loopback.

An ordinary CLI process does not receive the observer capability. If it reads
the shared state after API registration, procfs ownership is explicitly
`unverified-listener`; the observation preserves the prior lifecycle and
active lease instead of treating permission denial as foreign ownership or
healthy proof. Cutover evidence is captured through authenticated API
inventory so the capable process supplies fresh PID/address/inode evidence.
Every lifecycle mutation, including whole-project actions, fails before any
operation record, signal, launch, lease change, Docker action, or metadata
write when a relevant listener has that unknown identity. This is a tri-state
contract; truthiness must not collapse unknown into stopped or unhealthy.

Why: The third split-unit cutover relocated the durable assignment and retained
the exact server ID correctly, intentionally stale-releasing the old lease.
The new Console then opened ports 80/443 and served valid public TLS, but its
`POST /v1/servers/register` failed with `port 443 is open but no listener PID
could be identified`. The Console Node process carried
`CAP_NET_BIND_SERVICE`; the separately launched unprivileged coordinator could
read the global TCP listener inode but received `EACCES` for that process's fd
and cwd links. The legacy topology worked only because its Console-spawned
coordinator inherited the same capability. Existing tests used an ordinary
same-process listener with no capability asymmetry, while the Console e2e
harness deliberately skipped production self-registration. The CLI's optional
`--pid` was not a safe workaround: any live PID bypassed listener ownership and
an unreadable cwd was accepted.

The adjacent lifecycle sweep reproduced a more dangerous consequence in the
pre-fix implementation: `server stop` treated only explicit wrong ownership as
unsafe, so unobservable ownership fell into the signal path, marked the server
stopped, and released its lease. Start/restart paths similarly treated unknown
as down and could attempt a duplicate launch. Project mutations could perform
metadata or Docker work before reaching the affected server. These behaviors
were not covered by the initial inventory-only preservation test.

Result: The failed cutover was rolled back from the checksummed pre-relocation
checkpoint to the untouched legacy unit; public `https://console.vr.ae/healthz`
returned HTTP 200 with valid TLS, and the legacy Console again registered on
443. The durable prevention boundary now requires a real Linux
capability-asymmetric fixture, capability non-propagation evidence for launched
children, explicit-PID false-positive guards, required production registration,
and an executable graph verifier before another cutover can be accepted. Each
cutover attempt retains its own immutable backup and incident evidence.

The first remote fresh-clone validation of this change exposed a concurrency
ordering regression that an earlier working-tree run did not reproduce. While
a project start held its pending reservation and created its child server, a
competing project stop observed the server set before and after that change.
The new identity preflight correctly detected fingerprint drift, but reported
generic retry advice before inspecting the already-pending project operation;
the existing conflict test consequently failed. Pending-operation exclusion is
now checked without mutation before interpreting fingerprint drift, and
`begin_operation` repeats the same check at reservation. The realistic
concurrent start/stop test retains the actual stdout/stderr in its failure so a
future ordering regression is diagnosable from clean-clone evidence.

The next Linux matrix run exposed a Python-version-specific procfs observation
failure before the capability integration executed. Python 3.9 represented an
unreadable `Path('/proc/PID/cwd').resolve()` as a pseudo-path containing
`readlink: Permission denied`; registration then misclassified that string as
a concrete foreign cwd instead of the expected unobservable identity. Linux
cwd discovery now uses direct `os.readlink`, requires an absolute strictly
resolvable target, and never falls back to `lsof` after procfs denial. A
cross-platform deterministic test injects `PermissionError` and requires
`None`, while the real Linux nondumpable listener remains the must-catch
integration fixture.

The adjacent cross-platform audit then found the same semantic boundary in
`lsof`: exit 1 represents both a clean empty selection and execution or
permission errors. The old listener and cwd probes treated every exit 1 as an
observable no-match. On macOS, a permission diagnostic could therefore become
`wrong-listener`, and read-only status could mark a live registered server
stopped and release its lease. Managed servers without `registration_identity`
had an additional gap: any unobservable cwd was returned as `ok=true`, so stop
could signal the PID. The lsof probes now accept a clean no-match only when no
diagnostic is present; cwd observation carries `observable=false` through every
live server identity. Deterministic macOS fixtures require both registered
status and managed stop to preserve PID, lifecycle, and lease without signals,
while clean empty lsof results remain valid negative controls.
The consumer boundary is deliberately stricter than the probe result: a clean
empty query proves only that lsof completed without diagnostics, not that a
still-live PID belongs to the recorded project. The lifecycle identity remains
unverified without a concrete cwd. A reviewer reproduced the pre-commit gap as
an HTTP-healthy managed row that was signalled and had its active lease removed;
the managed clean-no-match fixture now requires no signal and no state change.
That stricter consumer exposed a separate lifecycle fact in the existing
adopted-server restart test: `kill(pid, 0)` reports an unreaped child zombie as
alive, even though it cannot own a listener and its cwd is gone. The coordinator
now confirms non-zombie process state before treating a retained PID as live.
This preserves the ownership gate for genuinely live processes without adding
a broad stopped-row exemption that could hide a failed termination.

## 2026-07-11 - Loaded-unit checks model omitted undefined properties narrowly

Decision: The loaded-systemd checker accepts an omitted property as empty only
for `dev-coordinator.service`'s undefined `EnvironmentFiles` and
`ExecStartPre`. Every other expected property remains mandatory, and a
non-empty value for either optional field is rejected. The self-test fixture is
copied from the target systemd 257 output and includes must-reject extra env
file and pre-start command overrides.

Why: The second split-unit cutover reached the new pre-start gate with both
units safely inactive. All effective paths and commands were correct, but
systemd 257 omitted those two undefined coordinator properties instead of
printing `key=`. The synthetic fixture had printed empty keys, so the checker
mistook a semantically empty real unit for missing evidence. The gate failed
closed before listeners opened, and phase-aware rollback again restored the
legacy service at HTTP 200 with valid TLS.

Result: Missing-as-empty is not generalized: `DropInPaths`, fragment, identity,
working directory, environment, commands, and write paths remain exact. The
original real output now passes, while injected coordinator environment files
or pre-start commands fail. Each cutover attempt keeps its own immutable backup
and process/property evidence.

## 2026-07-11 - Authentication tamper fixtures change decoded bytes

Decision: Cookie/session tamper tests mutate an actual decoded signature byte
and re-encode it before expecting authentication rejection. Encoded-string
edits are valid only when the test proves the decoded bytes differ.

Why: A macOS Python 3.9 CI job landed on a session signature whose penultimate
character was already `A` while its final character was not. The old fixture
chose its replacement by inspecting the final character but replaced the
penultimate one, so it reproduced the original token and then expected the
valid token to fail. Trailing base64url edits can also differ only in unused
bits, so encoded-string mutation is the wrong proof boundary. Production
timing-safe verification behaved correctly. A 200-run local loop did not hit
the same timestamp-dependent HMAC, showing why probabilistic string mutation
was a weak guard.

Result: The exact CI failure is covered deterministically, the production
session code remains unchanged, and the adjacent session tests already mutate
significant leading characters. Repeated and clean-clone Console suites no
longer depend on random HMAC trailing bits.

## 2026-07-11 - System units pin the service account home

Decision: Production system-level units pin `/home/holyglory` anywhere they
address Console or coordinator runtime data. They must not use `%h` for those
paths. The repository boundary detector and deployment tests reject active
`%h` directives in a non-root system service, while permitting comments and
explicit service-account paths. The deployment runbook verifies the paths
resolved by systemd before the first process start.

Why: During the first split-unit cutover, `dev-coordinator.service` was loaded
by the system manager with `User=holyglory`, but `%h` expanded to `/root` in
both `CODEX_AGENT_COORDINATOR_HOME` and `--token-file`. The service correctly
failed with permission denied, the token-required layout gate prevented the
Console from starting, and the committed phase-aware rollback restored the
legacy topology and public TLS health. Source tests had asserted that the `%h`
text was present instead of modeling the system-manager expansion, so they
certified the defect.

Result: The incident exposed a missed-detection class rather than corrupted
state: no new Console listener opened, the pre-relocation state checksum was
restored, and the legacy Console/coordinator returned on ports 80, 443, and
29876 with `/healthz` at HTTP 200. The same resolved-path check now covers both
units and every external env, token, coordinator, Console state, and ACME path
before a second cutover attempt.

## 2026-07-11 - Cutover preconditions are sampled and revalidated after legacy stop

Status: Superseded by the five-second bounded observed-clean gates recorded
above. The point-sample contract below is retained only as incident history and
is not an executable cutover requirement.

Decision: An existing-host Console cutover requires five consecutive one-second
cgroup samples containing only the exact captured Node and coordinator process
instances, plus one final sample immediately before stop. A reusable sampler
atomically preserves an independently checksummed JSON ledger with accessible
process identity for every sample, including mismatches. Every mutation block
uses fail-fast shell semantics. A writer-free post-stop checkpoint, a
pre-relocation checkpoint, and durable migration/relocation phase markers make
rollback valid without restoring an active-writer snapshot. Linux process
start time is parsed after the final parenthesized `comm` delimiter, and exact
termination uses an immutable pidfd instead of a racy numeric PID. After the legacy
writers are gone, reset both external state trees to directory mode `0700` and
file mode `0600`, then rerun the production-layout preflight before final state
sync, ownership relocation, or split-unit start.

Why: The final live audit briefly observed a third cgroup PID that exited before
privileged attribution; five later samples contained only the two expected
processes. It also found `state.json` at `0644` even though the preparation phase
had normalized it earlier. The legacy coordinator can rewrite state while it
remains active, so an old clean snapshot or early chmod is not proof of the
actual cutover boundary.

Result: The runbook now fails closed if sampling, KillMode verification,
process/listener shutdown verification, permission repair, layout preflight,
migration, or relocation fails. A transient extra cgroup member leaves private
timestamped command/start evidence rather than only a terminal message. The
permission repair runs only after listener/process shutdown, when the legacy
writer cannot undo it, and proves the complete external layout again before
mutation continues. Recall tests exercise an extra real process, PID reuse,
the exact five/one-second cadence, fail-closed shell behavior, ordering, and
phase-aware rollback. Tests include process names containing spaces and `)`, a
realistic extra-process fixture arriving mid-sample, changed argv, missing
process evidence, duplicate role PIDs, symlinked evidence parents, concurrent
ledger writers, checksum tampering,
PID reuse during stat/cmdline reading and handle binding, a surviving
no-listener cgroup process during rollback, and a verifier failure that must
not reach relocation. The temporary KillMode override is removed by an exit
trap on every pre-stop abort, and optimized Python cannot disable the explicit
auth checks.

## 2026-07-11 - Every macOS HTTP fixture uses the fast-bind server

Decision: Ban bare `python -m http.server` argv from coordinator self-tests and
enforce the ban with an AST-based realistic must-catch fixture plus a
socketserver false-positive control. All executable HTTP fixtures use
`HTTP_FIXTURE_CODE`, which binds through `socketserver.TCPServer` without the
reverse-DNS work in `HTTPServer.server_bind`.

Why: The repository had already documented and fixed this macOS failure class,
but two later exact-lease tests still used raw module argv. Local Homebrew Python
3.13 reproduced the failure twice: the child stayed in `starting` until the
manual-lease health deadline expired. Text search showed exactly two
contradicting lists; the public matrix had not failed there consistently because
reverse-DNS behavior varies by Python build and host configuration.

Result: Both CLI and API exact-lease fixtures now use the fast-bind code path.
The structural self-guard detects a realistic `['python', '-m', 'http.server',
...]` argv list regardless of formatting while permitting the intended `-c`
socketserver fixture. Dynamically constructed and shell commands remain a
review-policy boundary; a tracked-tree search found no such executable use.
Direct Python 3.9 and 3.13 self-tests exercise the literal guard before any
server lifecycle test.

## 2026-07-11 - Concurrency fixtures isolate pre-lock capabilities

Decision: A concurrency fixture must make every prerequisite before its target
lock deterministic, explicitly prove that its worker reached the intended
blocking boundary, and surface any worker error when that boundary is not
reached. Capability discovery is tested separately from lock serialization.

Why: After the macOS path fixtures were repaired, both hosted macOS jobs reached
the coordinator's Docker name/ID alias serialization test and timed out waiting
for its fake subprocess. The fixture mocked container inspection and
`subprocess.run`, but left Docker executable discovery real. GitHub's macOS
runner has no Docker CLI, so the worker failed before reserving the immutable-ID
operation; the generic event timeout misreported this prerequisite failure as a
concurrency failure. Developer and Linux hosts with Docker masked the gap.

Result: The alias fixture supplies a sentinel Docker executable, verifies both
alias attempts used that resolver while only the winning attempt reached the
fake external command, and includes worker evidence if its gate is not reached.
The adjacent unverified-identity refusal uses the same isolated capability
boundary. Token creation, idempotent start, delegated restart, exact-lease
attachment, and Docker alias event fixtures now include worker evidence on
gate failure, restore patches even when startup fails, and assert every worker
terminated. Resolver call count is deliberately not pinned because
capability-check/lock ordering is not the behavior under test. The production
resolver and lifecycle locking are unchanged.

## 2026-07-11 - CI fixtures must prove canonical paths and usable database readiness

Decision: Keep production path validation strict about every symlink component,
including lexical system aliases, while canonicalizing only temporary roots
created and owned by a test before deriving fixture paths. PostgreSQL disposable
integration readiness must execute `SELECT 1` through `psql` against the exact
requested application database; an accepting listener is not sufficient.

Why: The first public DevCoordinator matrix exposed two assumptions hidden by
the development and Linux environments. A macOS runner returned its temporary
directory through `/var`, which is a platform alias for `/private/var`, so the
production-layout self-test accidentally supplied a symlinked fixture root and
failed before reaching its intended assertions. The next matrix run proved the
same contamination in the legacy-runtime migration self-test, and a deliberate
`TMPDIR=/var/tmp` sweep reproduced it in the link-manager self-test before CI
could reach that stage. Continuing that sweep found a coordinator relocation
assertion comparing a canonical persisted project to the lexical test root.
Separately, `pg_isready`
succeeded during official-image initialization before `POSTGRES_DB=appdb` had
been created, and the next backup query failed with `database "appdb" does not
exist`. Weakening the production guard or adding a blind delay would have hidden
the respective safety and lifecycle boundaries instead of proving them.

Result: The layout self-test canonicalizes its newly created infrastructure
root; migration and link-manager self-tests now apply the same boundary. Each
suite separately proves that an operator-supplied path component symlink is
still rejected, and the layout suite deterministically models the `/var`
alias. Repository policy now requires this fixture/production distinction for
future strict-path tests. Every test-owned temporary root used in path identity,
provenance, or standalone-copy checks is canonicalized, and the complete gate
is exercised with `TMPDIR=/var/tmp`. The Docker
integration performs a bounded `psql -X -qAt -v ON_ERROR_STOP=1 -U app -d
appdb -c "SELECT 1;"` probe against `127.0.0.1`. Binding the probe to TCP also
distinguishes the final server from the official image's socket-only temporary
initialization server. Its no-Docker contract deliberately makes a
listener-only probe appear successful while the first database query fails,
then proves retry-to-success; an already-queryable control proves there is no
unnecessary retry or sleep.

## 2026-07-11 - Cleanup and rollback failures are transaction evidence

Decision: Treat cleanup, rollback, restoration, and failure-diagnostic work as
part of the operator-visible transaction. When the requested operation and a
secondary boundary both fail, the top-level redacted error must name every
failure; exception notes or causes alone are insufficient when a CLI/API
serializes only `str(error)`. Retain the primary error as causal evidence,
attempt every independent cleanup, preserve recovery artifacts that could not
be restored or removed, and record their exact private paths.

Why: The Python 3.13 production-host gate first showed that exception notes
were absent from the PostgreSQL JSON error. The mandatory adjacent audit then
reproduced the same loss at credential-file removal, scratch-database drop,
disposable-cluster diagnostics/cleanup, partial backup publication rollback,
legacy Console migration finalizers, Board package restoration, coordinator
private-state temporary cleanup, and disposable integration cleanup. Existing
tests mostly modeled a command returning nonzero; they did not model the
cleanup invocation itself throwing, two rollback stages failing, or a later
finalizer replacing an already-combined error.

Result: Realistic fault injection now covers returned and thrown cleanup
failures, combined body/diagnostic/cleanup errors, partial publication with an
unremovable final artifact, migration body+rollback+finalizer failure, failed
app restoration with a retained backup, private-state write+temp-cleanup
failure, and integration removal timeout plus leak evidence. False-positive
controls prove successful cleanup does not invent secondary failures. Secret-
bearing PostgreSQL failures are redacted before combination, while CLI JSON
tests assert the combined text itself rather than traceback-only metadata.

CI now runs the complete non-native gate on Linux and macOS with Python 3.9
and 3.13; the real disposable PostgreSQL job uses 3.13. Host-absence fixtures
must control Git configuration, executable paths, binary fallbacks, ignored
files, ports, credentials, and runtime state instead of relying on a developer
or server machine not to provide them.

## 2026-07-11 - Fresh-clone validation is a publication gate, not a duplicate smoke test

Decision: Keep the unpublished DevCoordinator history free of credential-shaped
detector source by constructing the realistic private-key fixture at test
runtime, and make the Console configuration test create its declared TLS
fixture before loading non-development configuration. Validate again from a
new clone with no ignored files before creating the public repository.

Why: The in-place repository gate was green, but the first bundle clone exposed
two testing-procedure defects. The reachable-history scanner correctly treated
its self-test's literal private-key header as suspicious; allowing a special
path or comment would have created a blind spot, so the unpublished commit is
amended instead. Separately, the `HTTP_PORT=0` unit test assumed that an ignored
development certificate already existed because another test had generated it
in the long-lived checkout. That ordering and filesystem contamination do not
exist in a clean clone.

Result: The secret detector still exercises the exact unmarked key material in
the temporary Git repository, while no detector source blob contains it. The
Console test explicitly calls the concurrency-safe on-demand certificate
fixture and still verifies app-root-relative TLS path resolution. Publication
now requires the full non-native suite in a newly created clone, preventing
ignored build/runtime artifacts from masking prerequisites.

The first validation on the clean Linux production host found one further
environment leak before service cutover: ordinary fixture commits supplied an
inline author/committer identity, but the synthetic merge commit inherited the
developer machine's global Git identity. The temporary repository now sets its
own local fixture identity immediately after `git init`, so merge-history
recall is portable to hosts and CI runners with deliberately empty global Git
configuration. The server gate must be rerun after this correction; a green
developer checkout alone is not accepted as Linux evidence.

That rerun exposed the same class of contamination in the coordinator's Docker
capability test. Its negative case used macOS launchd's real minimal system
`PATH`, assuming Docker could not be installed there; `/usr/bin/docker` is a
normal Linux installation, so the test found the host binary through the very
fallback behavior it was meant to validate. The negative fixture now uses a
private empty executable directory and a missing explicit standard location,
while separate positive controls still prove normal-PATH, absolute fallback,
and multicall-symlink discovery. Host Docker availability can no longer turn a
deterministic missing-capability test into a false failure.

The next Linux pass found a genuine PostgreSQL error-reporting gap rather than
a fixture-only difference. On Python versions that support `BaseException`
notes, backup cleanup attached a failed scratch-database drop as a note to the
original restore exception. The CLI catches exceptions and serializes
`str(exc)` as JSON, which omits notes; operators therefore lost the cleanup
failure even though the process failed. Cleanup handling now always raises a
combined `RuntimeError` while retaining the body error as `__cause__`, so the
machine-readable CLI error includes both restore and cleanup failures on every
supported Python version. The existing realistic fake-Docker scenario proves
both causes remain visible and is rerun on the production Linux interpreter.

## 2026-07-11 - DevCoordinator became the independent owner of operations tooling

Decision: Extract the coordinator, PostgreSQL protection skill, DevOps Board,
and DevOps Console from the verified unified holyskills commit `8c416e2` into
the public `DevCoordinator` repository. The filtered equivalent was `1d33b3e`;
after removing every reachable non-canonical `design-qa-*.png` artifact it
became `335d2c6`. The final original-to-scrubbed mapping is tracked under
`docs/history/`, while commit authors, committers, timestamps, messages, and
retained file changes remain attributed to their original authors.

DevCoordinator now owns exactly `codex-dev-coordinator` and
`postgres-docker-backup`, plus `DevOpsBoard`, `DevOpsConsole`, their tests,
packaging/provenance, deterministic fixtures, runtime declaration, and
deployment units. Holyskills owns the remaining six audit/verification skills.
Neither repository imports, checks out, pins, or requires the other's source in
build, runtime, tests, or CI. `DEVCOORDINATOR_ROOT` is the only checkout-root
override for both bundled helpers. The Board's existing
`local.holyskills.codex-ops-console` bundle identifier and `CodexOpsConsole`
settings migration lookup remain solely to preserve installed identity and
preferences across the product rename.

Why: Continuing to deploy the coordinator and Console from holyskills coupled
unrelated audit-skill releases to runtime operations and made the server's
source of truth ambiguous. A history-preserving split keeps the mature behavior
and attribution while making ownership, packaging, deployment, and rollback
boundaries explicit.

Result: Root documentation, agent policy, skill audit, CI, link-manager naming,
PostgreSQL disposable labels, and repository validation now describe the
two-skill product. Production units split coordinator and Console ownership,
require the Console to depend on the coordinator, keep the API token server-
side, and externalize environment/state under private user paths. A new
repository-boundary detector checks exact tip ownership, holyskills source/
build/runtime/CI independence, required auth/unit/package contracts, current
Console fixture source hashes, and every reachable commit/tree for unsafe
artifact paths, missing/tampered canonical provenance, private key material,
and supported credential patterns. Its realistic tests cover linear and
merge-result-only history, later-deleted artifacts, tampered images/renderers,
secrets with redacted findings, and safe placeholders/canonical controls.

Native Board build, XCTest, current-source snapshots, packaging, launch, and UI
acceptance remain exclusively owned by Build macOS Apps. The repository CLI
refuses to substitute direct native commands. The real disposable PostgreSQL
integration remains an environment/CI gate when a Docker daemon and image are
available.

The coordinator unit uses `KillMode=process` because systemd keeps
coordinator-launched managed servers in the service cgroup even though each
starts a new process session. Default control-group shutdown would turn an API
restart into an unattributed stop of every managed server. Explicit
coordinator project/server actions remain responsible for those lifecycles;
the Console unit explicitly keeps `KillMode=control-group` because production
sets `COORDINATOR_AUTOSTART=0` and it owns no coordinator-managed children.

The coordinator unit intentionally omits `PrivateTmp`, `ProtectSystem`,
`ReadWritePaths`, `NoNewPrivileges`, and unit-wide `UMask`. Like cgroup
membership, those systemd properties are inherited by launched children;
`start_new_session` does not escape them. Applying API-process hardening to a
generic launcher would silently change managed application filesystem,
privilege, temporary-directory, and file-creation semantics, and a surviving
child could retain the old private mount namespace across API restart. Stronger
workload isolation must instead use an explicitly configured independent
transient scope/unit. Console hardening remains appropriate because production
disables coordinator autostart and the Console owns no managed children.

Production-critical Console values are pinned in the unit's `ExecStart` through
`/usr/bin/env` after `EnvironmentFile` loading: coordinator autostart remains
off, the API stays on loopback, the token/coordinator homes remain external,
and Console state stays outside Git even if a preserved environment file has
stale overrides. Configuration also rejects any non-loopback or path-bearing
coordinator URL so a bearer token cannot be sent to a remote origin. The
Console, unlike the generic coordinator launcher, retains
`ProtectHome=read-only`, `ProtectSystem=full`, `PrivateTmp`,
`NoNewPrivileges`, `UMask=0077`, and an explicit writable state exception.

Extraction hardening also exposed three trust/provenance checks that the prior
green suites did not enforce. First, the Console's domain-wide authentication
and OAuth-flow cookies were forwarded to routed HTTP/WebSocket applications,
and upstream `Set-Cookie` fields could mutate them; an old e2e assertion even
encoded the unsafe behavior as success. The proxy now isolates the configured
session name and `dc_flow` in both request and response directions for normal
HTTP, WebSocket 101, and upgrade refusal while preserving unrelated application
cookies. Real HTTP/WebSocket must-catch tests cover custom names, multiple
cookies, similarly named controls, and comma-bearing `Expires` attributes.

Second, Board package provenance allowed tracked dirty inputs and therefore
named a commit that could not reconstruct the bundled Swift/helper bytes. The
packager now refuses tracked changes and proves every packaged input equals its
recorded HEAD blob; its tests include both ordinary dirty work and a status-
clean index/worktree mismatch for Swift and helper inputs. Third, the skill-link
manager accepted a repository `skills` directory or nested canonical source as
a symlink to another checkout. It now requires one real in-repository skills
directory and a symlink-free canonical source tree, with must-catch external-
root and nested-link fixtures plus an unrelated-repository-symlink control.
The apply path additionally snapshots repository, `skills`, and per-skill
device/inode identity plus canonical tree content, then revalidates after
transaction creation, immediately before and after each link, and during final
verification. A realistic plan-to-apply source-swap fixture proves an external
tree is never installed and rollback uses the exact original link text instead
of following the swapped source.
These were detector misses, not changed requirements, so the durable guards and
realistic tests landed before deployment.

The server checkout cutover uses the coordinator's first-class `port relocate`
transaction rather than unassigning port 443 and racing to recreate ownership.
It requires the exact old assignment and captured lease identity, refuses live
listener/PID, pending, foreign, ambiguous, or destination-collision state,
migrates the reusable stopped server record and checkout-relative cwd, clears
stale process/launch fields, and records attributed history. Listener detection
uses positive socket/PID/connect evidence rather than a bind probe, avoiding the
false conclusion that an `EACCES` bind to a free privileged port means it is
occupied. Tests prove wrong-owner/lease/port, foreign lease, live listener/PID,
pending work, ambiguous record, byte-unchanged failure, pre-pruned stale lease,
and same-ID registration after transfer.

The prior deployment example also unconditionally installed `.env.example`
over the production `console.env`, contradicting the preservation requirement
and risking loss of OAuth, session, and TLS configuration during cutover. The
runbook now creates the template only when the external file is absent, backs
up and checksums the existing file before mutation, repairs its mode without
rewriting it, and has a deterministic documentation test that rejects an
unguarded template install.

The first existing-host rewrite still modeled the legacy host as if a separate
coordinator unit already existed and treated a live state tree like a fresh
install. In reality the legacy Console autostarts the coordinator inside its
own cgroup, reads secrets and routes/preferences/ACME/logs from the old
checkout, and has no `dev-coordinator.service` to restart or restore. The
cutover now captures exact PID/start-time/command/cgroup, listener, lease, and
server identities before stop; migrates secrets in an env-only phase that does
not read live logs; performs the exact state sync only after the old cgroup is
quiescent; transfers port ownership; then installs and starts the split units.
Rollback records whether each unit existed and removes the new-only coordinator
unit before restoring the legacy Console topology.

`migrate_legacy_console_runtime.py` is a journaled, same-filesystem transaction.
It preserves non-path environment bytes, rewrites only required external path
and split-service keys, publishes the environment with an atomic no-overwrite
link, verifies source identity/hashes before and after commit, stages and
checksum-verifies the complete state tree, and restores prior environment/state
on every injected commit-boundary failure. Its recall suite covers live-state
env-only isolation, symlink/special-object refusal, source mutation both during
copy and after staging, a concurrently created valuable environment, state/env
cross-phase rollback, post-link fsync failure, and explicit empty `acme/`
augmentation. These guards were added before server mutation because a command
that reports failure after partially moving production data is not a safe
rollback mechanism.

The live legacy host did not yet have a standalone coordinator unit: the old
Console autostarted a detached coordinator child inside its own systemd cgroup,
and kept `.env` plus routes/preferences/ACME/log state under the old checkout.
The first split runbook draft incorrectly treated that child as an existing
`dev-coordinator.service` MainPID and did not migrate checkout-local state. The
binding cutover procedure now captures exact legacy Console/coordinator process
instances, cgroup/listeners, lease and server IDs before stop; verifies the old
cgroup and listeners are gone; performs a final staged checksummed env/state
migration that rewrites only production path/control keys; relocates port
ownership; then installs and starts the new coordinator unit before the
Console. Deterministic runbook and migration tests cover the legacy topology,
relative-state-path removal, secret/value preservation, state hash/count
continuity, rollback evidence, and same-server-ID registration.

## 2026-07-11 - Stale-base work was recovered by a remote-first semantic merge

Decision: Preserve the stale checkout at `55e64d2`, establish remote `main`
(`40a27b8`) in an isolated clone, add the repository-freshness guard there,
and merge with explicit semantic precedence rather than pulling into the dirty
checkout or choosing one side wholesale. The remote `apps/DevOpsBoard` rename,
the complete remote `apps/DevOpsConsole`, durable port assignments, project
membership, Linux listener support, and later UI lifecycle behavior remain.
The stale branch's authentication, short-lock coordinator architecture,
Docker preflight/ownership, PostgreSQL restore safety, multi-source Board,
typed destructive actions, provenance, link rollback, detector recall, and
audit hardening were ported or adapted. The pre-split merge ledger accounted
for each local change group and the small set of intentionally superseded
implementations; current ownership is recorded in `OWNERSHIP.md`.

Why: The stale work was valuable but internally complete only against the old
base. Replacing remote code would have deleted the web Console and later
architecture; replacing local code would have discarded safety fixes and
realistic regression coverage. The merge therefore treated remote paths and
remote-only features as authoritative while reviewing coordinator auth/state,
PostgreSQL restore, Board identity/lifecycle, Console deployment, formal UI
verification, root validation, and artifact policy individually.

Result: The unified non-native gate passes all eight in-repository and
standalone-copy skill suites, 101 Console tests, freshness/link/artifact/
snapshot detector suites, PostgreSQL P0 checks, Python compilation, and the
Board's Python-only package/tamper suite. Four Console screenshots are now
deterministic isolated-fixture artifacts with reproducible hashes and source
provenance; 18 live-inventory screenshots and the obsolete native QA wall were
removed. Native Board build/XCTest/snapshot regeneration/package/launch remain
explicitly pending the required Build macOS Apps plugin. The local Docker
daemon did not answer bounded `docker info`, so the real disposable PostgreSQL
integration remains a Linux CI/server gate rather than being misreported as a
local pass.

## 2026-07-11 - Repository-wide work requires a fetched remote-ancestry preflight

Decision: Treat remote freshness as an explicit prerequisite for broad audits,
optimizations, migrations, history rewrites, and repository splits. The
incident that established this rule began with local work based on `348aa9f`
while remote `main` had advanced to `40a27b8`. No fetch/ancestry preflight ran
before the audit and optimization, so comprehensive tests proved the stale
tree internally consistent but could not detect the newer remote architecture.
The requirement did not change; the workflow omitted a source-of-truth check.

The durable guardrail is `scripts/check_repository_freshness.py`. It fetches
the selected remote without changing working-tree files, compares local HEAD
and the remote branch through their merge base, and reports `current`, `ahead`,
`behind`, `diverged`, `dirty-on-stale-base`, or `remote-unavailable`. A dirty
stale checkout is preserved and reconciled from an isolated remote-fresh clone;
it is never reset, rebased, stashed, cleaned, or overwritten to satisfy the
check. Its behavioral self-test uses real repositories and remotes to prove all
six classifications, including dirty-file preservation and false-positive
controls for current dirty work and legitimately ahead branches. Root
validation runs that self-test so the preflight cannot silently disappear.

## 2026-07-10 - GUI runtime actions preflight dependencies and bind delivered binaries

Decision: Codex Ops Console constructs one deterministic subprocess environment
from inherited absolute PATH entries plus `/etc/paths` and `/etc/paths.d`.
Docker-backed project mutations require Docker capability, always refresh after
success or failure, and retain structured preflight/partial evidence. The
coordinator independently resolves Docker through an explicit absolute override,
PATH, and standard macOS locations while preserving the discovered `docker`
entry-point path (multicall tools such as OrbStack select behavior from
`argv[0]`); it bounds Docker calls, preflights the CLI, daemon, and Compose
plugin before touching managed processes, parses Compose global flags correctly,
and gives Compose sole lifecycle ownership when a dependency maps to a declared
service.

Why: the launchd Board process inherited only
`/usr/bin:/bin:/usr/sbin:/sbin`, while OrbStack exposed Docker under
`/usr/local/bin`. A benzovozka project stop therefore stopped four workers before
the first bare `docker` call raised `ENOENT`; the Board then kept stale inventory.
The running Board was also an older bare SwiftPM process, and packaging did not
bind executable bytes to the Swift inputs that produced them.

Result: realistic minimal-PATH, multicall-symlink, zero-mutation preflight,
partial-result, Compose-option/ownership/restart, timeout, and false-positive
fixtures protect the coordinator contract. Board source has injectable
PATH/capability/refresh regressions. Packaging records exact production
Swift/manifest hashes and the executable hash, rejects unprovenanced
`--skip-build`, and has a Python-only stale/tamper suite in the non-native
validation gate. The user explicitly requires Build macOS Apps for compilation,
XCTest, packaging, launch, and native acceptance; replacing the still-running
bare process remains pending until that plugin is exposed.

## 2026-07-10 - Canonical direct-link skill installation

Decision: This repository is the only writable source for its eight skills.
Codex, Claude, and desktop Codex runtimes install each repo-owned skill as a
direct absolute symlink to `skills/<name>`. Installation changes go through the
transactional `scripts/manage_skill_links.py` plan/apply/verify/rollback
workflow, which locks every explicit root, preserves replaced objects, records
private rollback evidence, and refuses unreviewed divergence.

Why: The previous topology used copied Codex and Claude directories, while the
desktop runtime linked to the Codex copies. Installed copies were edited after
deployment, including `trace-fix-root-causes`, so repo changes and runtime
behavior could move independently and a chained desktop link amplified that
drift.

Result: The historical 2026-07-02 “Known drift” note below is superseded. On
2026-07-10 the 16 divergent directories and eight chained links were preserved
under the private transaction
`$HOME/.local/state/holyskills/backups/20260710-182238`, replaced, and verified
as 24 direct links to this repository. The transaction remains retained until
fresh Codex, Claude, and desktop sessions reload their startup metadata. Links
are absolute and must be reinstalled if the repository moves; roots on separate
filesystems require separate transactions.

## 2026-07-10 - Truthful, fail-closed skill and Board contracts

Decision: The eight skills expose only claims their implementations and
deterministic evidence can support. Detector-style skills must bind real
evidence and prove realistic recall plus intentional-pattern precision. The
coordinator uses private atomic state, structured commands, short reservation/
commit locks, attributed operations, exact manual-lease attachment, immutable
Docker identity, and a protected IPv4-loopback API. PostgreSQL protection binds
live work to immutable container identity, separates database and cluster
scope, strongly verifies scratch restores, and refuses unsafe cluster restore.
Codex Ops Console preserves source identity, partial capability truth, retained
action evidence, exact port-lease values, and strong database evidence instead
of inventing status or treating a failed optional integration as total source
failure.

Why: The repo-wide audit found several contracts that were stronger than their
deterministic proof, security/concurrency gaps at local control boundaries, and
Board state that could lose provenance or block unrelated actions. Those gaps
could make a passing self-test or green UI imply guarantees the user did not
actually have.

Result: Safe Python/static validation passes for the link manager, public
artifact guard, snapshot-verifier self-tests, audit, coverage, journey, trace,
and PostgreSQL suites, standalone skill copies, vendored harnesses, syntax
checks, and Board static guardrails. The four canonical PNGs pass pixel and
geometry checks only when source freshness is explicitly skipped;
current-source canonical verification remains pending native regeneration.
Coordinator process/API and standalone suites also pass in isolated temporary
homes.
Environment-dependent native Board verification remains separate and pending
the required Build macOS Apps workflow; the non-native results do not claim to
cover it.

## 2026-07-10 - Approved Board hierarchy and structured exact-lease starts

Decision: The user approved the ImageGen Board review on 2026-07-10, authorizing
the confirmed SwiftUI hierarchy: compact source health, dominant resource
inventory, retained typed results, focused lease/database safety flows,
explicit bulk selection, and secondary source configuration. Starting a server
from an existing port lease now accepts a typed executable plus argument list,
JSON-encodes that vector, and sends it to the coordinator with `--argv` and the
exact `--lease-id`. It must never combine exact-lease start with `--cmd` or ask
the user to edit a raw command payload.

Why: The coordinator deliberately rejects `server start --lease-id` with
`--cmd`; the previous Board path therefore exposed a start action that could not
succeed. Structured argv also preserves spaces and quotes as argument
boundaries without shell interpretation. The approved hierarchy removes
overexposed global/destructive controls and keeps source ownership and real
operation evidence adjacent to the affected resource.

Result: The approved Board and menu-bar source implementation is present, and
the static interaction gate checks the structured exact-lease path and approved
surface contracts. Swift compilation, XCTest, native rendering, accessibility,
packaging, and launch evidence are not claimed for this source until the Build
macOS Apps workflow is available.

## 2026-07-10 - Production-view, source-bound snapshot evidence

Decision: Native snapshot tools render the production `BoardView` and
`MenuBarRuntimeView` with deterministic fixture inventory and live loading
disabled. Each canonical sidecar must name the exact portable renderer inputs
and bind their current bytes through `source_files` and `source_sha256`, in
addition to binding the PNG bytes, dimensions, fixture, and generator.

Why: A separate menu snapshot shell could drift from the product view, while
PNG hashes and dimensions alone could let an old image keep passing after the
SwiftUI source changed. A current visual claim requires both real production
view rendering and evidence that the image came from the current renderer
inputs.

Result: The verifier now has realistic must-catch coverage for a UI source edit
and missing source provenance, plus a current-source passing control. The four
committed PNGs still pass structural pixel/geometry checks, but their existing
sidecars lack the new source binding and the default verifier rejects all four.
They must be regenerated through Build macOS Apps before they can be claimed as
current redesign evidence.

## 2026-07-10 - Attributed lease lifecycle and target-wide action isolation

Decision: Board lease release sends the coordinator's required acting agent and
exact lease project, and direct Start/Release controls are available only for
active, unbound manual leases with the ownership fields required by the chosen
operation. Inventory models retain `server_id` and pending attachment state.
Project-scoped inventory absence is not treated as release evidence for a lease
owned by another project. Running actions conflict by stable target domains,
including cross-kind server lifecycle operations and database/container
operations, rather than only by identical action names.

Why: A static recheck reproduced that the Board's old Release call was rejected
by the coordinator because it omitted `--agent` and `--project`; its unit test
had encoded the malformed call. The same review found that dropping attachment
metadata could expose guaranteed-failing Start and unsafe Release actions, a
scope change could fabricate a Released state, and Stop/Restart or
backup/restore/container actions could overlap on one real target. Those are
safety and truthfulness failures, not presentation details.

Result: The release contract, lease lifecycle fields, scope-aware reconciliation,
source provenance, issue/result association, stable source identity, and
target-conflict rules now have static guard requirements and focused XCTest
regressions. The malformed CLI path was reproduced with exit 2 before the fix.
The XCTest/native execution of these regressions remains pending Build macOS
Apps; the non-native gate checks that the guard and test source stay present.

## 2026-07-10 - Build macOS Apps is mandatory for native validation

Decision: At the user's direction, coding agents must use the Build macOS Apps
plugin for Swift/macOS build, test, packaging, launch, debugging, snapshots,
and native UI automation. Agents must not take over the user's desktop or
substitute direct Swift/Xcode, `open`, XCUI, mouse, or keyboard control. If the
plugin is unavailable, native validation stays explicitly pending. A user-
confirmed ImageGen mockup is also required before consequential Board view
changes.

Why: Native validation should use the purpose-built workflow and must not
interfere with the user's computer. Separating the native gate also prevents a
partial static/non-Swift pass from being reported as a compiled, tested, or
run macOS app.

Result: The rule is recorded in active Codex and Claude policy, the curated
app-wide reference, this repo policy, Board documentation, and the repository
validation instructions. `scripts/validate.py --skip-macos-app` provides an
honest non-native gate; the complete gate remains reserved for Build macOS Apps.
The user subsequently approved the ImageGen Board review, so source
implementation proceeded while native validation and canonical regeneration
remained pending the unavailable plugin.

## 2026-07-07 - DevOps Console: single-row header with a needs-attention badge; uniform color-coded actions (v1.5.1)

Decision: Two user requests shipped together. (1) Projects page action
alignment: project-header rows rendered Start/Restart/Stop while item rows
rendered Stop/Restart (or a lone Start), so right-aligned buttons landed in
mismatched columns. Every tree row now renders the SAME three fixed-width
(86px) slots through one `treeActionSlots` builder — Start | Restart | Stop,
inapplicable actions disabled with a title, never hidden — so buttons align
into exact columns (playwright-verified: one left-X per label on desktop and
phone). Actions are color-coded console-wide via `ACTION_CLS` — Start green,
Restart blue, Stop red, disabled drops to neutral so color always means
"available" — and the Servers/Docker pages adopted the same Restart-before-
Stop order. (2) Header reimagined: the status sentence and always-on
coordinator/TLS/dev-http chips are gone; the header is brand + inline nav
tabs (≥1024px; hamburger drawer that DROPS BELOW the row on narrower
screens) + a needs-attention badge + a compact account button (avatar
initial → popover with email + sign out) — ONE row on every viewport
(48px desktop, 54px phone, domain label hidden <480px; playwright-verified
one-row geometry + zero horizontal scroll). A quiet header means healthy:
`headerProblems()` collects coordinator-unreachable (red), TLS
expired/expiring<14d/unknown, insecure dev HTTP, unhealthy servers,
unresolving routes, docker down, and stale live data; the badge shows the
count in the worst severity color and its popover gives each problem facts,
a plain-language instruction and a direct action (Try again / Open page /
copyable `sudo certbot renew` / Refresh now). The stale-data path was
exercised end-to-end in a real browser (network cut → amber badge "1" →
popover names the problem with Refresh action → badge clears on recovery).
journeys.md J1, the information-relevance rows and the status-summary
interpretation were rewritten for badge semantics; validate.py pins
headerProblems/hdr-alert/treeActionSlots/ACTION_CLS. Residual: on the narrow
(<1100px) tree layout the container subdomain chip is hidden like
tree-detail (the tight cell wrapped it mid-word); subdomains remain fully
manageable on the Servers and Docker pages at every width.

## 2026-07-07 - DevOps Console: stable ordering contract — live metrics are never a sort key (v1.4.1)

Decision: User-reported incident, handled prevention-first. Symptom: project
groups on the Servers page (and Docker/Projects/Ports, which share
`projectGroupsOf`) changed position on every 6s poll, making targets
impossible to click. Reproduced at the data level against the live console:
three overview polls 7s apart, the v1.3.0 comparator (running-first, then
`cpu_percent` DESC, then name) flipped GlobalFinance/holyskills twice purely
on CPU jitter. Origin: the cpu tiebreak was added by the agent in the v1.3.0
projects-tree work as an unrequested "hot projects float up" flourish — the
user asked for grouping, never for load-ordered groups; no doc stated an
ordering contract, no test asserted order determinism, and three adversarial
review passes missed it (no lens asked "is ordering stable across polls?").
Guardrails first: docs/journeys.md gained a "Stable ordering contract"
acceptance criterion (live CPU/memory must never be an ordering key on
persistent lists; reorder only on state transitions, membership changes, or
user action); test/unit.uiorder.test.mjs extracts the comparator from app.js
and proves order is independent of cpu readings (mutation-verified: restoring
the old comparator fails all three tests); validate.py pins the comparator
(`projectGroupOrder` + its sort call site) and PROHIBITS the two live-metric
sort keys as needles. Fix: `projectGroupOrder` sorts running-first → name →
key (key breaks display-name collisions deterministically); the Performance
page's `lastCpu` card ordering — same class, found by the adjacent-surface
audit — became running-first → name → key too. The Swift board's
`hotProcesses` cpu sort was audited and kept: it selects top-5 content for a
label, it does not order persistent rows. Full validate ok; deployed and
verified stable across live polls.

## 2026-07-07 - DevOps Console: docker-hosted web servers are first-class servers (v1.4.0)

Decision: Containers that serve web traffic (the user's example:
`skydivelive-app-1`) now appear in the Servers list, can be
started/stopped/restarted there, and take subdomains like coordinator
servers. Membership rule: any non-database container publishing a TCP port
on a loopback-reachable address, plus stopped containers that still hold a
route (a stopped container publishes nothing, so the route is what keeps it
startable from the page). Subdomains use a new route kind `docker` whose
durable identity is container name + CONTAINER-side port; the published host
port is resolved live from the (cached) coordinator inventory on every
request, so restarts and remapped host ports keep working. One shared
subdomain control (spec-parametrized) serves server rows, docker rows, the
Docker tab and the Projects tree, growing a container-port picker when
several ports are published; `/api/docker/subdomain` mirrors the server
endpoint's assign/rename/auth/unassign semantics. Every resolved port —
docker included — passes the coordinator-API-port guard.

A five-lens adversarial review (57 agents, 24 confirmed findings, all fixed)
shaped the final design: v6-only publishes (`::`/`::1`) are now REJECTED as
unreachable because the proxy dials v4 loopback — a separate socket
namespace — so accepting them either 502s or cross-wires the route into
whatever unrelated v4 process holds that port number; same-slug updates
(auth changes, renames) no longer demand a currently-published port and
never silently repoint the stored container port (explicit `port` only, and
re-sending the route's own port is a no-op); paused containers
(`Up … (Paused)`) read as paused, not running, and their routes refuse to
proxy; the e2e docker-web fixture listener is closed in after() — leaving it
open wedged `node --test` after a green run, the exact hang class the macOS
CI work just fixed; an OS-assigned fixture port containing "5432" would have
silently reclassified the fixture as postgres (redrawn now). Coverage: e2e
tests 16–17 run a fake docker CLI under the real coordinator (assign →
proxied 200 through the TLS edge → actions logged → ambiguity/typo 400s →
stale-port lifecycle → idempotent unassign), and a drift test extracts the
UI's mirrored ports parser from app.js and runs it against the backend
parser over a shared corpus. Known residual, accepted: if several docker
routes point at one container (possible via the Routes form), the row
control manages the slug-sorted first — the same semantics server rows have
always had; extras are managed on the Routes page.

## 2026-07-07 - CI on macOS: never use bare `python3 -m http.server` as a test fixture

Decision: The repo's first full macOS CI runs exposed two independent
failures, both diagnosed by reproducing on the runner itself (a temporary
`debug-macos` probe workflow) rather than by guessing. (1) A cancelled-
after-30-minutes run was a HANG, not slowness: the e2e harness's coordinator
spawn missed its readiness window and the timeout path leaked the python
child, whose inherited stdio pipes kept the `node --test` worker alive
silently until the job timeout — every spawn-failure path now kills the
child, readiness gets 60s, and the workflow budget is 60 minutes. (2) With
the hang fixed, every coordinator-started fixture reported "unhealthy, pid
alive, port closed": the probe showed even a bare
`python3 -m http.server --bind 127.0.0.1 &` control never reaches listen()
on macos-latest — lsof shows the socket bound but stuck in CLOSED — because
`HTTPServer.server_bind` calls `socket.getfqdn()` and the runner's resolver
black-holes reverse DNS (`getfqdn('')`/`getfqdn(hostname)` hang 20s+; an
`/etc/hosts` entry does NOT cure it since macOS libinfo routes reverse
lookups through mDNSResponder). Policy: test fixtures must not use bare
`http.server`; the suites now share a getfqdn-free equivalent
(`socketserver.TCPServer` + `SimpleHTTPRequestHandler` — same directory
listing, no name resolution; `HTTP_FIXTURE_CODE` in the coordinator
self-test, `PY_HTTP_FIXTURE` in the console e2e), verified answering 200 on
the same runner where `http.server` hangs. Also: `apiCall` in the console
e2e forwards fetch options and whole-project actions carry a 330s client
budget (the coordinator legitimately runs them for minutes). The "successful"
earlier run that suggested macOS had ever been green was only the Copilot
review job — the full gate had never passed on macOS before this.

Follow-up (same day): the fixture sweep missed that the hazard is any stdlib
`HTTPServer` construction, not just `-m http.server` fixtures — the next run
passed all 81 node tests and then failed in the coordinator self-test because
`serve_api` itself builds a stock `ThreadingHTTPServer`, which pays the same
~30s getfqdn stall between bind() and listen() (the console e2e only passed
because its readiness budget is 60s). Cure at the source: the coordinator API
now binds through `FastBindThreadingHTTPServer` (a `server_bind` override
that binds like a plain `socketserver.TCPServer` and skips reverse DNS),
pinned by validate needles; the coordinator and formal-web-ui self-test
in-process fixtures use the same override, and `wait_for_api` gets 30s of
cold-runner headroom. Generalized policy: on this repo, never construct a
stdlib `HTTPServer`/`ThreadingHTTPServer` (or `-m http.server`) directly in
anything CI runs — always the fast-bind subclass or a plain `TCPServer`.

## 2026-07-07 - validate.py de-staled: needles pin code and call sites, not comments and definitions

Decision: A two-auditor adversarial pass over the gate itself (prompted by the
user's "validate.py seems stale") confirmed 13 weaknesses; all fixed. Weak
anchors replaced or reinforced: the slug-enumeration needle matched only a
COMMENT — now pins `const needAuth = !route || route.auth !== 'public';`;
two different Swift invariants shared the identical needle
`GeometryReader { proxy in` (5 matches — neither was pinned) — now unique
anchors; definition-only needles gained call-site pins so deleting the wiring
fails the gate (autoUnhide's refreshOverview call, buildAssignments'
setSection wiring, setSurfaceVisible's window/popover call sites, OpsStore's
deduplicatedManagedServers load wiring); the ambiguous `.frame(width: 14)`
pin now includes its contentShape context. Coverage gaps closed:
test/helpers/dev-cert.mjs joined the haystack with an openssl-generation
needle (its generation branch never runs locally, so only the needle guards
CI); metrics usage_key-first keying pinned by needle AND a same-project_key
collision unit fixture; server.mjs drain-timer cleanup pinned; the verifier's
object-form cookies gained self-test recall (domain/path-scoped cookie
reaches a gated page) plus a fail-fast malformed-domain assertion; the
DevOpsConsole banned-marker scan now covers index.html and app.css;
Tools/SnapshotMain.swift joined the ops haystack (was outside every guard).
Verified by mutation: deleting the autoUnhide call site now fails the gate
(it was green before). Also removed the ended background session's stale
worktree (.claude/worktrees/festive-herschel-713bfa, a clean pre-rename
checkout). Full validate.py ok; formal-web-ui self-test ok.

## 2026-07-07 - DevOpsBoard: project grouping consumes coordinator membership instead of re-deriving it

Decision: Closed the follow-up from the same-day coordinator membership fix —
the Swift menu-bar app was the last UI re-deriving container→project grouping
client-side (`projectKey(fromResourceName:)` name-key heuristics plus a
`projectPathForGroup` ~/src directory scan), so it could show a container
under a group that differs from the membership `project start/restart/stop`
acts on (the exact divergence class just fixed for the web console). Fix:
`makeProjectGroups(from:)` now iterates inventory `project_usage` rows and
resolves members strictly through `server_ids`/`container_names`;
`ProjectGroup.id` is the row's `usage_key` (unique — `project_key` is a
display name), `projectPath` comes from `row.project` only (name-keyed
`name:<key>` groups get no synthesized action path, matching the coordinator
refusing whole-project actions on unclaimed containers), and anything no row
claims stays visible in a stray "other" fallback group like the web console's.
`ProjectUsage` decodes `usage_key`/`server_ids`/`container_names`;
`OpsStore.mergeProjectUsage` buckets multi-home inventories by `usage_key` and
unions membership. The heuristic family (`projectKey(fromPath:/
fromDockerContainer:/fromResourceName:)`, token sets, `projectDisplayName`,
`projectPathForGroup`) is deleted; `resourceDisplayName` survives as a
cosmetic leaf-prefix strip (now fed by the group display name, normalized
case-insensitively) and Docker/DB table project labels resolve through group
membership. The details-panel fallback for a selection that dropped out of
cached groups parses the persisted `usage_key` contract (`path:<resolved>`)
instead of scanning ~/src. Coverage: `SplitSizingTest` gained must-catch
fixtures per divergence class — sidecar-attributed `aerodb-pg` must display
under XFoilFOAM (not a name-derived `aerodb` group), coordinator-claimed
`grouprepo-db` must display under the path-keyed repo, an unclaimed
same-name-key container must stay OUT of the repo group whose actions do not
touch it, membership-less containers must stay visible in the stray group,
and every container must render exactly once. validate.py replaced the
heuristic needles ("canonical project grouping", "project path grouping",
"project panel path fallback") with membership pins (decoding keys, usage-key
identity, stray group, multi-home union, the three board must-catch strings)
and added prohibited needles for `projectKey(fromResourceName` /
`projectPathForGroup(` so the heuristics cannot quietly return. Verified via
the local needle gate; Swift compile + QA tools need the macOS CI leg (no
Swift toolchain on this box).

## 2026-07-07 - Coordinator: one container-membership model for display grouping and whole-project actions

Decision: Closed the follow-up gap from the same-day console review — display
membership (`build_project_usage`/`resource_project_identity`) and
whole-project action membership (`build_project_runtime_spec` via
`matching_project_containers`) could disagree: an unattributed container like
`myrepo-db` displayed under a name-keyed group `name:myrepo` (project null)
while `project stop` on the path-keyed repo stopped it, and a container
explicitly attributed elsewhere (Compose labels) was still name-matched into a
different repo's blast radius. Reproduced both through the CLI (fake docker +
durable pins) before changing code. Root cause: two independent attribution
implementations. Fix: a single `container_project_attribution(container,
known_projects)` used by both paths, fed by one claim set
(`known_project_paths`: state server records, durable port pins, container
label/sidecar projects, plus the action's target repo). Rules: explicit
attribution (Compose labels, then coordinator sidecar) always wins; a unique
name-key match claims an unattributed container for the known repo; an
ambiguous name key (several known repos) stays in its own `name:<key>` group
and no whole-project action touches it (previously EVERY matching repo's stop
would stop it). `project stop` now records sidecar attribution for containers
it acts on (start/restart already did via `ensure_runtime_docker_metadata` /
`run_docker`), so grouping converges to explicit membership after any
whole-project action. Console UI unchanged by design — it already groups by
`project_usage` `usage_key`/`server_ids`/`container_names`, which are now also
the action contract. Coverage: coordinator self-test gained three must-catch
membership classes (name-claim divergence, explicit-attribution leak,
ambiguity refusal) — each proven to fail against the pre-fix coordinator via a
reconstructed old-behavior copy with an expected-fail harness — plus
convergence and display guards; five new validate.py needles (attribution
function, shared claim set, ambiguity refusal, must-catch fixture, SKILL blast
radius contract); SKILL.md and DevOpsConsole docs/coordinator-http-api.json
now state the unified membership contract (inventory `project_usage` rows
document `usage_key`/`server_ids`/`container_names` and the claim rules;
projects/start|stop purposes name the attribution). Known residuals, accepted:
a DECLARED dependency whose container name does not match the repo key stays
name-grouped until the first whole-project action records its sidecar
attribution (display cannot see runtime files; reading every known repo's
declaration on each inventory was rejected as new I/O/failure surface), and
the Swift DevOpsBoard app still re-derives grouping client-side
(`projectKey(fromResourceName:)`) — filed as a follow-up task since this box
has no Swift toolchain to verify a rework. Full validate.py ok.

## 2026-07-07 - DevOps Console: Projects tree, repo grouping everywhere, hideable items that self-reveal

Decision: Made the console project-centric (v1.3.0). New default `#/projects`
page renders a tree of repos with everything that belongs to each: servers,
databases (docker.postgres), containers — per-item AND per-project live
CPU/mem numbers + sparklines, per-item start/stop/restart, and whole-project
Start/Restart/Stop through new `POST /api/projects/action` → coordinator
`/v1/projects/*` (dependencies before web servers, pinned ports preserved,
300s budget, stop/restart confirmed with blast radius named). Grouping is
authoritative, not guessed: `build_project_usage` rows now carry
`server_ids`/`container_names`/`usage_key` membership, so the console never
re-implements the coordinator's repo-identity heuristics; the Servers,
Docker and Ports pages group their rows under the same project headers (with
aggregate CPU/mem + project sparkline). Hiding: stopped servers/containers
and idle projects can be hidden; hidden keys (server identity key, container
name, project usage_key) persist server-side in `<stateDir>/ui-prefs.json`
via new `GET/PATCH /api/prefs` (validated lists, Origin-guarded, atomic
writes) so the preference follows the operator across devices; anything the
coordinator reports as running is auto-unhidden on the next poll
(`autoUnhide` fire-and-forget PATCH), and every page shows a "Show N hidden
items" reveal with per-row unhide — nothing active can stay hidden, nothing
hidden is unrecoverable. Tests: e2e 14 (prefs round-trip, dedupe/trim,
validation 400s, forged-Origin 403, persistence) and e2e 15 (real
dev-runtime project started/stopped through the console; membership asserted
via server_ids) — suite 75/75 twice; coordinator self-test asserts the new
membership fields; four new validate.py needles (projects endpoint, ui-prefs
persistence, autoUnhide, coordinator-membership grouping). Full validate.py
ok.

Adversarial review (5 dimensions, 2-skeptic verification; several findings
reproduced by running code) confirmed 21 findings; root-cause fixes: (1) the
prefs PATCH was whole-list replacement, so a user hide racing the auto-unhide
poll, rapid double-hides, a failed boot fetch, or a second stale device could
silently wipe hides — redesigned to hide/unhide DELTAS merged server-side
(atomic in-process), plus prefs re-fetch on poll-retry and visibilitychange;
(2) prefs persist() swallowed disk errors and returned 200 — now propagates
PrefsError 500 and rolls back memory, with a new unit.prefs.test.mjs proving
durability from DISK; (3) project metrics/popovers were keyed by non-unique
project_key (two repos named "app" merge charts) — keyed by usage_key
everywhere, and the self-test now pins the 'path:<resolved>' usage_key format
(it lives in persisted prefs); (4) `project restart` ran docker restart
unguarded after stopping all servers (a missing declared container aborted
the restart half-done) — now skips missing containers and collects
action_errors like start/stop do; (5) /api/projects/action accepted arbitrary
paths — now requires the project to be coordinator-tracked or carry a real
declared runtime (synthetic missing-runtime placeholders don't count);
(6) crash-looping "Restarting" containers counted as not-running — hide
gates, auto-unhide and runningCount now use an is-active predicate and the
tree badges them "restarting"; (7) duplicate data-fk/popover keys between
tabs and the tree — usage cells are scope-prefixed; (8) reveal-toggle count
missed hidden items inside concealed projects; (9) project stop/restart
confirms now describe the coordinator's actual blast radius (declared
runtime); (10) e2e test 15's fixed random port window overlapped
coordinator-leased ranges — bind-checked ephemeral port, plus stop-idempotent
and unknown-path 404 coverage; (11) the vacuous --no-docker container-
membership assertion now asserts against the fake-docker fixture. Known
remaining gap (filed as follow-up): display membership (project_usage
identity) and runtime-action membership (build_project_runtime_spec) can
disagree for name-attributed containers — the confirm wording is honest about
it, unification needs a coordinator refactor. Post-fix: console 79/79 twice,
coordinator self-test ok, full validate.py ok.

## 2026-07-06 - Coordinator: durable per-repo port assignments (ports never drift across restarts)

Decision: The user requires ports to be fixed per repo server — agents must
always find a repo's servers on the same ports, across stops, restarts, and
time. Implemented durable port assignments in `dev_coordinator.py`: a new
top-level `state.port_assignments` map keyed `canonical_project::server_name`,
created automatically on `server start`/`server register` (and by explicit
`port assign`), surviving server stop, lease release/expiry/stale-reclaim, and
stopped-record pruning; removed only by `port unassign` (foreign pins need
`--force`). Allocation (`lease_port` and the register-adoption path) excludes
every foreign-assigned port; an explicit preferred on a foreign pin fails with
the owner named ("port N is durably assigned to server 'web' of /repo").
Owners are steered back: `server start` without `--range` pins hard to the
assigned port (a squatter is a loud error, never silent drift); with an
explicit range the pin is preferred inside it and a different landing re-pins.
`server restart` and project-runtime starts consult the assignment, so restart
works on the same port even after the stopped record was pruned. Existing
state files migrate by seeding pins from server records (running first, then
newest-stopped wins a contested port — resolves the demo-web/web-demo 3000
overlap in web-demo's favor). New surface: CLI `port assign|unassign|
assignments`, HTTP `GET /v1/ports/assignments`, `POST /v1/ports/assign|
unassign`, `port_assignments` in inventory (project-filtered, annotated with
live `server_status`, "unregistered" when only the pin remains). The
`server start --range` parser default was removed so the coordinator can tell
"no range given" (pin hard) from an explicit range. Chose a separate
assignments map over never-expiring leases because four independent reclaim
paths (TTL expiry, stale-server release, mismatched-listener release,
fixed-port reclaim) all delete leases by design. Cross-project port reuse now
requires an explicit unassign first — the self-test was updated to assert the
refusal, unassign, then proceed. Domains needed no change: console routes are
already durable per (project, serverName). Console v1.2.0 shows a "Pinned
ports" card on the Ports page (unassign with confirm, server status, pin
marker on Servers rows) via `POST /api/ports/unassign`. Coverage: self-test
blocks for pin lifecycle, prune survival, foreign refusal, unassign rules,
re-pin, register pinning, migration seeding, HTTP round-trip; console e2e 13;
six new validate.py needles. Full `validate.py`: ok.

Adversarial review (6-dimension multi-agent, 2-skeptic verification, one
finding reproduced by actually running the test) confirmed and led to fixes:
(1) `project start` resolved the fixed port as record-before-pin, silently
reverting an explicit `port assign` — precedence now declared-port > pin >
record, matching `server restart`, with a runtime fixture; (2) squatted-pin
failures through restart/project-start surfaced the opaque "no free port
available in N-N" — the loud pinned-port error now fires whenever the attempt
targeted exactly the pin; (3) owner passing `--preferred <own pin>` outside
3000-3999 without a range got a misleading range error — the pin now becomes
the range; (4) the healthy-existing short-circuit could move pins (duplicate
pins after force-assign, silent revert of an explicit re-pin) — it now only
heals a missing pin; (5) seeding could brick read_state on a malformed legacy
stopped_ts — guarded; (6) console e2e test 13 raced the console's 5s inventory
cache after direct coordinator mutations (reproduced failing) — now polls past
the window; (7) console section sigs included coordinator.lastOkAt, defeating
render memoization every 6s poll — sigs now use a stable {ok,lastError} slice;
(8) the Servers-page pin marker claimed the record port was pinned even after
a pin moved — it now compares ports and shows ":old → :new (next start)";
(9) console port-only unassign now demands `force: true` up front; (10)
self-test `free_port()` never re-issues a port any earlier fixture used,
eliminating pin-collision flakes structurally. Post-fix: self-test ok,
console 73/73, full validate.py ok.

## 2026-07-06 - DevOps Console: paged UI with hamburger nav, CPU/mem history charts, lease management

Decision: Restructured the console UI from one long page into five hash-routed
pages (`#/servers` default, `#/routes`, `#/docker`, `#/ports`,
`#/performance`) behind one sticky header (status summary + tab nav with live
counts on desktop, hamburger drawer on ≤719px). Added an in-process metrics
history store (`src/metrics.mjs`): a background sampler pulls coordinator
inventory every `METRICS_INTERVAL_MS` (default 10s) into per-entity ring
buffers (720 points) for servers (`process_usage`), running containers
(`stats`) and projects (`project_usage`); `/api/overview` fetches piggyback
into the same store. New `GET /api/metrics/history?limit=N` feeds the UI:
every running server and container row shows live CPU %/memory numbers plus a
sparkline whose click opens full CPU + memory charts; the Performance page
charts every sampled entity. Port leases became manageable from the UI via
`POST /api/ports/lease` (purpose/preferred/ttl/project, attributed
`devops-console:<email>`) and `POST /api/ports/release` (lease_id, confirmed
release). Chose in-memory history (resets on restart, UI says so) over disk
persistence — no retention policy needed, honest about scope.

Two correctness fixes surfaced by the new e2e tests: (1) the coordinator
client now invalidates its inventory/servers caches after any mutating call,
so a post-mutation overview can no longer show pre-mutation state for up to
the 5s cache window (a released lease used to linger); (2) `CoordError`s with
4xx statuses (coordinator answered, request bad — "matching lease not found")
now pass through as HTTP 400 instead of masquerading as 502 gateway failures.
Assets gained `?v=<version>` cache-busting because they are served with a 1h
immutable cache; `package.json` bumped to 1.1.0. Charts are SVG built via
`createElementNS` (the app.js innerHTML rule stays: icons map only).
validate.py gained needles for cache invalidation on mutations, the bounded
metrics ring, lease-id-required release, hamburger aria wiring, and
createElementNS charts. Tests: `unit.metrics.test.mjs` (ingest/dedupe/
trim/prune/limit/sampler) + e2e 11 (lease→overview→Origin 403→release→400 on
re-release) + e2e 12 (real coordinator server appears in metrics history with
positive RSS; limit validation; anonymous 401) — 72/72 green.

## 2026-07-06 - DevOps Console: Google OAuth live, Docker installed, per-server subdomains, HSTS

Decision: Three follow-ups after go-live. (1) Wired the real Google OAuth web
client into `.env` (gitignored) — the console left degraded mode; verified the
full authorization-code + PKCE flow reaches Google's account chooser
("continue to vr.ae", no redirect_uri_mismatch) with state/nonce/PKCE all
present. (2) Installed Docker Engine (`docker.io` 26.1.5) and enabled the
service — it was genuinely absent, which is why the console reported "Docker
unavailable"; the coordinator re-checks `docker` per inventory call so the
console now shows the Docker section as available (0 containers). (3) Added a
per-server subdomain control to the Servers block: each server row shows its
mapped `<slug>.vr.ae` (link + copy + access pill + Edit) or an "Assign
subdomain" affordance, backed by a new `POST /api/servers/subdomain
{id, slug, auth?}` endpoint that assigns/changes/removes a `kind:server` route
in one call (empty slug unassigns; a slug change creates-then-removes so a
server maps to a single subdomain). Also added an HSTS response header
(`max-age=31536000; includeSubDomains`) on the TLS listener.

Why: The user reported Chrome showing "not secure" (diagnosed as stale
browser state from the earlier self-signed period — the live cert is valid
production Let's Encrypt, confirmed by an off-VM fetch and `ssl_verify=0` on
every host; HSTS added to harden and prevent http:// confusion), asked whether
Docker was installed, and asked for subdomain assignment directly from the
Servers block rather than only the Routes form.

Result: OAuth reaches Google live; Docker available; the subdomain feature is
verified live (assign default-login → change slug+public in one call → old slug
unrouted, new public route reachable anonymously → CSRF `Origin` guard 403 →
unknown-id 404) and by a new e2e test (`9b`). The endpoint reads
`serversRaw({maxAgeMs:0})` so a just-started server is never missed by the 3s
cache. Suite 63/63; `scripts/validate.py` passes; formal UI verification of the
authenticated console (with the new controls) reported no findings at 1440x900
or 390x844 (evidence: `apps/DevOpsConsole/design-qa-servers-subdomain-*.png`).
The Google client id/secret and are in the gitignored `.env`, never in the repo.

## 2026-07-05 - DevOps Console: automated wildcard renewal via 101domain API

Decision: Replaced the manual DNS-01 renewal with fully unattended automation
using the 101domain REST API (the user supplied an API key to avoid recurring
manual TXT edits). Discovered the API by probing: base
`https://api.101domain.com/v1`, `Authorization: Bearer <key>`, DNS records at
`/v1/dns/vr.ae/records` — `GET` lists, `POST {"records":[{name,type,ttl,value}]}`
creates (TTL must be ≥300; values are stored quoted but published as the bare
string, which is what ACME needs), `DELETE {"ids":[...]}` removes. Wrote certbot
`manual_auth_hook`/`manual_cleanup_hook` scripts
(`apps/DevOpsConsole/deploy/101domain/{auth,cleanup}-hook.sh`, versioned in the
repo, no secret) that create/delete the `_acme-challenge.vr.ae` TXT via the API
and poll the authoritative nameservers for propagation before returning. The
API key is stored root-only at `/etc/letsencrypt/101domain/credentials.env`
(never in the public repo; the hooks source it) and the hooks are installed to
`/etc/letsencrypt/101domain/` and wired into
`/etc/letsencrypt/renewal/vr.ae.conf`.

Why: The wildcard must renew every ≤90 days; a manual TXT step each time is a
standing outage risk (forgotten renewal → every subdomain breaks). API-driven
DNS-01 makes the certbot systemd timer renew hands-off.

Result: Verified end-to-end. `certbot renew --dry-run` succeeded unattended
("TXT propagated after 2 check(s)" for both the apex and wildcard authz), then
a real `certbot renew --force-renewal` issued a new production cert
(serial …328AC → …2A77), the cleanup hook removed the challenge records, the
deploy hook reloaded the service (SIGHUP), and the live server served the new
serial with every host still `ssl_verify=0`. The certbot timer is enabled and
will now auto-renew within 30 days of expiry. The guided manual helper
(`deploy/renew-wildcard.sh`) remains as an API-outage fallback. Security: the
API key is confined to the root-only credentials file; a repo-wide grep
confirms it appears nowhere under version control.

## 2026-07-05 - DevOps Console: *.vr.ae wildcard cert via manual DNS-01

Decision: Issued the real `*.vr.ae` + `vr.ae` Let's Encrypt wildcard so proxied
`<slug>.vr.ae` subdomains (not just the console) present a browser-trusted cert.
DNS-01 is mandatory for wildcards and `vr.ae` DNS is at 101domain with no API
credential on the box, so the challenge TXT was published by hand: certbot was
run with a blocking `--manual-auth-hook` that captures the challenge value and
holds the order open (before CA submission) until a sentinel is created, so the
operator adds `_acme-challenge.vr.ae` TXT at 101domain with zero rate-limit
risk while certbot waits. Only one fresh authorization was needed — the apex
`vr.ae` authz was still cached valid from the morning's HTTP-01 console cert.
After the record propagated to the authoritative nameservers the sentinel was
created, certbot validated and issued, and the console reloaded the cert
(same `--cert-name vr.ae` path `.env` already targets).

Why: The wildcard is the design the app was built for (arbitrary subdomains
behind one cert); HTTP-01 only covers named hosts. Manual DNS-01 was the path
the user chose (no willingness to share registrar API credentials this pass).
The blocking-hook + sentinel pattern makes a cross-turn manual DNS step
reliable without burning Let's Encrypt's 5-failed-validations-per-hour budget.

Result: `console.vr.ae`, `vr.ae`, and every `*.vr.ae` subdomain now serve the
wildcard and validate with `ssl_verify_result=0` (confirmed both on-box and
via an off-VM fetch to `https://demo.vr.ae/healthz` → trusted cert, 200).
Cert valid 89 days. Two durability fixes: (1) a **default ACL**
(`setfacl -R -d -m u:holyglory:rX /etc/letsencrypt/{live,archive}`) so each
renewal's freshly-written `privkeyN.pem` stays readable by the service user —
without it the first same-path reload failed `EACCES` on the new key; (2) the
temporary challenge-hook path certbot recorded in
`/etc/letsencrypt/renewal/vr.ae.conf` was removed so the unattended certbot
timer cleanly SKIPS this manual cert instead of invoking a vanished script.
LIMITATION: renewal is manual (~60 days) — shipped
`apps/DevOpsConsole/deploy/renew-wildcard.sh`, a guided one-command helper that
runs certbot, prints the TXT record to add, verifies propagation at the
authoritative NS, completes issuance, and reloads the service. Fully hands-off
renewal still needs a DNS API hook or acme-dns CNAME delegation (documented).

## 2026-07-05 - DevOps Console: real Let's Encrypt cert via in-app ACME HTTP-01

Decision: The console served only the self-signed fallback cert ("SSL doesn't
work" — every browser rejected it). `vr.ae` DNS is at an external registrar
(101domain) and this VM's service account has no DNS API scope, so the DNS-01
wildcard the app was designed to consume could not be provisioned here. Added
native ACME HTTP-01 support instead: the plain-HTTP :80 listener serves
`/.well-known/acme-challenge/<token>` from `ACME_WEBROOT`
(`config.acmeWebroot`, default `<stateDir>/acme`) before the https redirect
(`src/server.mjs` `tryServeAcmeChallenge`, wired ahead of the redirect and the
`/healthz` handler), with token charset validation and a resolve+prefix
traversal guard. Issued a real Let's Encrypt cert for `console.vr.ae` + `vr.ae`
via `certbot --webroot`, granted the `holyglory` service user ACL read on
`/etc/letsencrypt/{live,archive}/vr.ae`, pointed `.env` at the live PEMs, and
installed a renewal deploy hook that reloads the service (SIGHUP) on renew.

Why: A wildcard `*.vr.ae` is only issuable via DNS-01, which needs registrar
DNS access not available on this box. HTTP-01 needs only inbound port 80, which
the app already owns and which is internet-reachable (confirmed by a
Let's Encrypt staging dry-run). Serving the challenge in-app (rather than
stopping the service for `certbot --standalone`) keeps port 80 continuously
owned and makes unattended renewal work without downtime.

Result: `https://console.vr.ae` and `https://vr.ae` now present a
browser-trusted Let's Encrypt cert (verified externally via an off-VM fetch
that previously failed on the self-signed cert; `curl` reports
`ssl_verify_result=0`), valid 89 days with the certbot timer active and the
deploy hook reload proven by `certbot renew --dry-run`. The cert-path change
required a full service restart (a SIGHUP reload only re-reads the
already-configured path — documented in the README). Coverage: added an e2e
test (`1b`) asserting the challenge is served as 200 over plain HTTP for any
vhost with no redirect, plus 404 for missing tokens and traversal attempts;
suite is 62/62 and `scripts/validate.py` passes. LIMITATION: this cert covers
only the two named hosts — proxied `<slug>.vr.ae` subdomains still fail cert
validation (name mismatch) until a `*.vr.ae` wildcard is provisioned via
DNS-01 (needs 101domain DNS credentials) or on-demand per-slug HTTP-01
issuance is added. Surfaced to the user as an open decision.

## 2026-07-05 - DevOps Console web app: TLS edge + subdomain reverse proxy on vr.ae

Decision: Added `apps/DevOpsConsole/`, a zero-third-party-dependency Node 20
web app that is the public edge of the `vr.ae` VPS. It terminates TLS for
`*.vr.ae` on 443 (wildcard cert read from `.env`, hot-reloaded on file change
and SIGHUP), redirects 80→443, and Host-routes: `console.vr.ae` serves an
authenticated control panel (REST API + vanilla-JS UI), `<slug>.vr.ae`
reverse-proxies to `127.0.0.1:<port>` including WebSocket/HMR upgrades, and the
apex redirects to the console. Each subdomain route is `google` (default) or
`public`; anonymous requests to unknown slugs are made indistinguishable from
protected ones so route names cannot be enumerated. Google sign-in uses an
in-process OIDC authorization-code + PKCE flow with ID-token signature
verification against Google's JWKS (no auth library); sessions are
HMAC-SHA256-signed cookies scoped to `Domain=.vr.ae` so one login covers every
subdomain. All server/Docker/lease state and mutations go through the existing
`codex-dev-coordinator` HTTP API on loopback `127.0.0.1:29876`, which the app
autostarts if absent. Deployed via a systemd unit that grants only
`CAP_NET_BIND_SERVICE` (no root) and reloads the cert on SIGHUP. The app runs
in a degraded-but-real mode (public routes still proxy; auth-gated surfaces
show a setup page) until the operator creates the Google OAuth client, and
serves a self-signed `*.vr.ae` cert until the Let's Encrypt DNS-01 wildcard is
provisioned out-of-band.

Two shared coordinator changes were required and made general (the coordinator
advertises itself as pure-stdlib and Linux-ready): `listening_pid_for_port`
now resolves the owning PID via `/proc/net/tcp{,6}` + `/proc/<pid>/fd` before
falling back to `lsof`, so `server register`/adoption works on Linux hosts
without `lsof` installed (this VPS had none, which had been silently failing
the coordinator self-test and the console's own port-443 self-registration);
and `http_health` skips TLS certificate verification for loopback targets
(`127.0.0.1`/`localhost`/`::1`), because an HTTPS edge on loopback serves a
public-hostname cert that can never validate against the loopback address.

Why: The user asked for a web control center for the VPS that reuses the
coordinator as its control engine and adds in-app subdomain reverse-proxying
with Google auth on `vr.ae`. The zero-dependency Node 20 constraint keeps the
public edge auditable and free of a supply chain. Routing every control action
through the coordinator (rather than shelling out or duplicating logic) keeps
one source of truth for servers, ports, Docker, and leases shared with DevOps
Board and Codex. The coordinator portability fixes were prerequisites: without
`/proc` PID resolution the app could not register itself, and without
loopback-relaxed health checks a TLS edge could never report healthy.

Result: Live on `https://console.vr.ae` under systemd. Verified end-to-end on
the real domain: 80→443 redirect, apex/`www` redirect, 421 for foreign hosts,
anonymous console and protected/unknown slugs redirect to Google login
(indistinguishable), full route lifecycle (create defaults to login-required →
authed 200 / anon 302 → flip to public → anon 200 with no restart), CSRF
`Origin` check (mutations without a same-origin `Origin` → 403), a WebSocket
echo relayed through the 443 edge (anonymous WS upgrade to a protected slug
refused with 401 before 101), and the console self-registered with the
coordinator as a healthy server on 443. Tests: 61 node:test cases (unit + real
end-to-end against a spawned coordinator, a local OIDC issuer with real
RS256-signed tokens, and HTTP/SSE/WebSocket upstreams), all green across 10+
consecutive runs. An adversarial multi-lens security review (auth/proxy,
correctness, policy) surfaced one defense-in-depth gap — the coordinator-port
guard was enforced only on the create-route API path, not on disk-loaded or
`kind:server` routes — which was fixed in `routes.mjs`/`router.mjs` and locked
with two regression tests proven to fail pre-fix. Formal web UI verification
(mobile 390x844 + desktop 1440x900) passed with no critical or warning
findings on both the control panel and login page. `scripts/validate.py` gained
a `check_devops_console` guardrail (security-invariant text anchors,
zero-dependency enforcement, stdlib-only import scan, single-purpose innerHTML
check, `node --check` + full `node --test`) and was made resilient to hosts
without a Swift toolchain or a global git identity; the coordinator and
formal-web-ui-verification self-tests were extended to cover the new code
paths. The `formal-web-ui-verification` skill gained `--cookie` and
`--ignore-https-errors` (with must-catch self-test fixtures) so auth-gated,
self-signed-TLS pages can be verified.

## 2026-07-05 - Codex Ops Console renamed to DevOps Board; idle CPU eliminated

Decision: The macOS console app is now DevOps Board (`apps/DevOpsBoard/`,
SwiftPM package/product/executable `DevOpsBoard`), and its inventory refresh is
visibility-gated instead of free-running. The store polls only while the main
window is actually visible (tracked through `windowDidChangeOcclusionState`)
or the menu bar popover is open (tracked through the popover delegate), at a
5-second cadence; concurrent refreshes coalesce into one in-flight coordinator
run with at most one queued follow-up pass. Inventory is published only when
the decoded payload differs from the current one, project groups are computed
once per inventory change and cached on the store (`store.projectGroups`)
instead of being re-derived in every view body, per-coordinator-home inventory
commands run concurrently in a task group, and `runPython` waits via a
termination handler instead of blocking a cooperative-pool thread in
`waitUntilExit()`, with a SIGTERM/SIGKILL watchdog (60 s for inventory, 10 min
for actions, 1 h for backups) so a wedged coordinator child cannot freeze the
single-flight refresh pipeline.

Why: The app previously ran `python3 dev_coordinator.py inventory` (which
itself samples `docker stats`) every 2.5 seconds forever — including while the
window was hidden to the menu bar — so the app consumed CPU and power
continuously even when nobody was looking at it. The 2.5-second cadence also
republished identical inventory each cycle, re-rendering the whole window and
recomputing project grouping several times per pass.

Result: A hidden DevOps Board spawns no subprocesses at all; a visible one
samples half as often, skips UI work when nothing changed, and never blocks
Swift concurrency threads. `scripts/validate.py` guardrails were updated to
enforce the new contract (visibility-gated refresh, publish-on-change, cached
project groups, non-blocking process wait) and all `CodexOpsConsole` paths and
strings were renamed across the app, validation gate, CI workflow, README, and
design QA notes.

## 2026-07-03 - Functional hardening pass across all skills

Decision: A functional-only audit (security excluded per user) drove concrete
improvements. Landed: the interaction 10-label "hard reporting gate" is now
enforced by code (a shared `verify_common.interaction_checklist_missing` used by
the full-repo-audit and ui-implementation-audit verifiers) rather than SKILL.md
prose, and the ui-implementation SKILL Final Output list was reconciled from 6
labels back to the canonical 10. A new shared `full_repo_harness/merge_findings.py`
consolidates/ranks findings across hundreds of batch reports (wired into all
three audit skills' synthesis step). The coordinator gained health retry/backoff,
a `starting` vs `unhealthy` grace classification, bounded stopped-server
retention, and corrupt-state recovery (no more `SystemExit` on read). A
concurrency stress self-test now proves no double-lease. formal-web-ui added a
full-page scroll pass, `unmeasurable` contrast handling for gradient/image
backgrounds, shadow-DOM/iframe not-inspected reporting, and natural-position
occlusion. postgres-docker-backup added `verify --test-restore` (restore into a
throwaway scratch DB with guaranteed cleanup). The root-cause verifier now
recognizes `~/.claude/CLAUDE.md` as a valid global policy target (dual-runtime
parity), and journey-doc discovery covers `.rst`/`.adoc` and code-comment
journeys. CI (`.github/workflows/validate.yml`) now runs `scripts/validate.py`,
and validate.py gained a label-parity guard.

Why: The prior audit found the deterministic gates had honor-system joints
(the label gate was prose-only), synthesis did not scale, and several verifiers
produced false gates or crashed on edge states.

Result: `scripts/validate.py` passes end to end. Two audit claims were checked
against the code and found FALSE, so no change was made: the coordinator
port-lease is already serialized under `locked_state()` (no double-lease TOCTOU),
and source-backed audit checks already hard-fail (`source_text_errors` /
`verification_warnings` already force `ok=False`; SHA re-hash is on by default).
Excerpt-proof for non-interface files was descoped as disproportionate risk to
the 3.7k-line fixture suite; interface files already require real source quotes.

## 2026-07-02 - Dual-runtime skills and mirrored global policy (Codex + Claude Code)

Decision: Holy Skills now targets both Codex and Claude Code. Skill contracts
were made runtime-neutral (descriptions and actor wording say "agent (Codex,
Claude Code)"; `trace-fix-root-causes` names both global policy files;
`user-journey-docs-audit` maps `request_user_input` to `AskUserQuestion`).
All eight skills install into `~/.claude/skills/` in addition to
`~/.codex/skills/`, and global agent policy is maintained as a mirrored pair:
`~/.codex/AGENTS.md` (Codex) and `~/.claude/CLAUDE.md` (Claude Code). A repo
`CLAUDE.md` imports `AGENTS.md` so both runtimes read one repo policy.

Why: The same machine runs both agent runtimes against the same projects,
dev servers, Docker containers, and databases. Coordination only works if both
runtimes follow the same policies and share one coordinator state
(`~/.codex/agent-coordinator/`), and skill descriptions must trigger in both
apps.

Result: `scripts/validate.py` passes after the curation; all eight skills pass
self-tests from `~/.claude/skills/`; the installed coordinator reads the
shared machine-wide inventory. The `server_health` early-return fix for dead
PIDs (previously hand-applied only in `~/.codex/skills/`) was backported into
the repo. Known drift: `~/.codex/skills/trace-fix-root-causes/` carries a
later hand-edited revision (SKILL.md, README, openai.yaml, self_test,
verifier) that was never backported here, and `~/.codex/skills/`
`ui-implementation-audit` + `full-repo-audit` are stale deployments of commit
13b4f1e — reconcile and redeploy both directions.

## 2026-07-02 - Coordinator project resource telemetry

Decision: The Codex dev coordinator inventory emits real per-server process-tree CPU/RSS telemetry and project-level resource rollups, and CodexOpsConsole (renamed to DevOps Board on 2026-07-05) displays those rollups by repo.

Why: Managed dev servers often launch child processes that own the actual listener and resource usage. A launcher PID alone can hide runaway Next/Vite/node child processes, especially across multiple Codex/Parall coordinator homes.

Result: Inventory now includes `process_usage` per server and `project_usage` per repo. The console discovers coordinator homes, merges read-only inventory, shows project load, and flags high-load projects in the status bar.

## 2026-07-02 - Formal Web UI DOM verification

Decision: Holy Skills now includes `formal-web-ui-verification`, a Playwright-driven skill that injects deterministic JavaScript into rendered web pages to measure DOM geometry, computed styles, text fit, occlusion, media health, area-of-interest boundaries, document overflow, and visible scrollbars.

Why: UI implementation and audit workflows were still able to miss software-detectable defects such as cropped text, hidden controls, unintended overlap, off-canvas interactive elements, broken media, and invisible text. Screenshot review remains useful, but these failure classes need formal browser-side measurements that can fail delivery gates without relying on model vision.

Result: The verifier defaults to critical-only failure for low-noise delivery checks and warning-level reporting for softer risks. It supports explicit route configs, coordinator current-URL smoke checks, AOI/ignore/allow attributes, JSON/Markdown reports, and mandatory visible scrollbar inventory. Existing UI audit prompts now require the verifier whenever a safe web render path exists, and the app-wide Codex instructions require formal web UI verification after material web UI changes.

## 2026-07-03 - Formal web UI verifier recall rework

Decision: Reworked `formal-web-ui-verification` detection so it measures how real applications break, and made recall (must-catch fixtures) a permanent part of its self-test: text candidates now include any element that directly owns rendered text (div-based layouts), clipping detection covers ancestor `overflow` cuts (absolute children, negative offsets, nowrap spill) with containing-block and scroll-path awareness, occlusion reports partial coverage (≥60% critical, ≥2 points warning), broken media checks include images collapsed to ~0x0, complex-artifact exclusion is token-bounded (a `roadmap`/`sitemap` class no longer disables checks), and off-canvas rules cover left/top document-edge cuts and fixed-position viewport cuts. Intentional patterns stay non-critical: own/parent single-line ellipsis, line-clamp, carousel-context cuts, fully hidden closed-state content, skip links, app-shell inner scrollers. Coverage inventories (ellipsis truncations, hidden text-like counts, pending media, per-rule finding caps with a `findings-truncated` marker) keep gaps visible.

Why: User reported the skill "doesn't report problems now in most of the cases". Reproduction confirmed it: 10 of 11 realistic defect fixtures (div text cut by a parent card, absolutely positioned button cut by an overflow-hidden panel, negative-margin top cut, 60% badge/label overlap, collapsed broken image, invisible text in a `roadmap-section` and in a plain div, half-off-canvas button, fixed toolbar cut below the viewport, nowrap div text spilling into a clipping parent) produced zero findings, while only the synthetic self-overflow case was caught. Root cause: detection rules and self-test fixtures both mirrored the implementation (self-overflow on a fixed tag list, all-sample-points occlusion, substring artifact exclusion), so the self-test proved precision only and gave false confidence — a recall gap, not a regression from one bad edit.

Result: All 11 realistic defect fixtures now produce criticals; the prior contract fixtures still pass; the extended self-test fails against the pre-fix verifier at the first new fixture (fail-before/pass-after proven). Noise checks stay clean: a composite modern page (sticky header, ellipsis card titles inside overflow-hidden cards, line-clamp, scrollable table, FAB, sr-only link) yields zero findings at mobile and desktop — this page also caught and now guards a false positive where an element's own ellipsis was re-tested against its parent's clip — and real pages (example.com, news.ycombinator.com) yield zero criticals with plausible warnings only. `scripts/validate.py` passes. Guardrails updated: repo `AGENTS.md` skill-development recall rule, and the generalized detector-recall rule in `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, and the curated mirror `reference/codex-app-wide/AGENTS.md`.

## 2026-07-13 - DevOps Board uses the Build macOS Apps run contract

Decision: DevOps Board now has the repository-level
`script/build_and_run.sh` entrypoint and Codex `Run` action required by the
Build macOS Apps plugin. The entrypoint builds and provenance-packages the
native app before launching it. The user explicitly authorized committing and
pushing this operational workflow and its compile repair directly to `main`.

Why: The first launch attempt reproduced a compiler failure in the selected
project diagnostics view, where stale local names were used instead of the
`ProjectGroup` collections. After that repair compiled, the existing package
gate correctly required the exact source to be committed before it could
produce a launchable provenance-bound bundle.

Result: Diagnostics now derives a stable, deduplicated origin list from the
selected group's servers, containers, and databases. The same plugin entrypoint
is the repeatable build, package, launch, log, telemetry, debug, and process
verification surface.

Follow-up: The first provenance-bound signed package exposed that macOS
`codesign` rewrites the Mach-O executable, while packaged provenance schema 3
incorrectly required its post-sign whole-file hash to equal the pre-sign build
hash. The Python packager test had modeled `codesign` as a no-op and therefore
missed this real signing behavior. Schema 4 records the verified pre-sign build
hash, verifies the copied bytes before signing, uses the bundle signature as the
post-sign integrity boundary, and reports the final executable hash separately.
The deterministic packager test now mutates executable bytes during its fake
signing step and requires signed packaging to preserve both facts; unsigned
packages retain exact whole-file hash verification and tamper rejection.

## 2026-07-13 - Automatic inventory refresh waits after completion

Decision: DevOps Board's default automatic inventory interval is 30 seconds,
and each interval begins only after the preceding inventory load has completed.
Explicit refresh remains immediate, and operators can still configure a custom
validated interval or manual refresh.

Why: A real unscoped coordinator inventory on the user's active source took
2.39 seconds because it includes Docker's `stats --no-stream` observation. The
previous 2.5-second start-to-start schedule left about 0.1 seconds between
loads, keeping the Board's loading badges effectively permanent and repeatedly
spawning expensive inventory work. The UI symptom and high load were therefore
one scheduling defect rather than slow progress that needed more status copy.

Result: A focused native regression models a 900ms inventory load with a
one-second configured interval and proves only two loads begin in 2.25 seconds;
the next poll cannot start until a full idle interval follows completion. The
default cadence now leaves substantial idle time while preserving truthful
live data and manual refresh.

Follow-up: Live post-fix sampling found a second independent cost after each
coordinator command: `performLoadInventory` synchronously rehashed every
discovered database dump on the main actor. The active backup set includes one
7.4 GB artifact and many roughly 500 MB artifacts; a three-second process sample
showed nearly all main-thread time in `DatabaseBackup.verifiedRecord()` and
`fileSHA256`, with a 4.1 GB physical footprint and a 19.9 GB recorded peak.
Inventory now parses manifest evidence without claiming a current checksum,
and verifies only the newest backup for a database when the user selects that
database. Verification runs at utility priority off the main actor, is cached
by source/path/size/mtime/manifest/checksum fingerprint for subsequent
refreshes, and bounds Foundation read allocations with an autorelease pool.
Restore stays disabled until that exact artifact has passed current checksum
verification. Automated recall uses a realistic sparse 8 GiB backup and proves
ordinary inventory completes without reading it; a separate test proves
selection performs the real verification and enables strong evidence.
