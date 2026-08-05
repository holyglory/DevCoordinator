# DC-2026-07-29-REPOSITORY-REPAIR-01 — Supporting record

## Context

A historical repair correctly marked a bogus shared `/tmp` repository missing,
disabled, and startup-fenced, but its older transaction did not reconcile 20
attached startup-policy rows. Broker startup consequently failed the
`disabled_repository_enabled_startup_policy` invariant. The service wrapper
observed a transient systemd active state, cleared maintenance, and published a
false restoration result even though the Unix socket never became stably ready.

## Options considered

- Edit the 20 rows directly. This loses plan, lineage, compare-and-swap, replay,
  and adjacent-row evidence.
- Re-run the original repository disable. Its precondition is an active,
  installed, unfenced repository and cannot truthfully describe the already
  terminal state.
- Set every stored policy disabled regardless of kind. That would invent a
  Docker or supervisor mutation when no native lifecycle evidence exists.
- Treat systemd ActiveState as readiness. This is the exact false positive that
  allowed the crash loop to escape the maintenance fence.
- Restore or clean the contaminated predecessor release. That destroys failure
  evidence and cannot satisfy immutable release verification.
- Resume a forward-only successor from mutable checkout bytes, run its older
  immutable client after discovering its implementation defect, or rewrite its
  static binding generically. The first violates the client identity contract,
  the second repeats the defect, and the third loses exact replay authority.

## Selected contract

The read-only reconciliation planner consumes and digest-checks the original
repository repair plan and result, including legacy documents, then rereads the
same authority inode and exact terminal repository. It enumerates a bounded,
sorted policy set with current and target values, immutable fingerprints,
generations, timestamps, and complete optional restore-state records. It
accepts only logical coordinator/Compose rows; Docker and supervisor rows need
their normal native lifecycle proof.

Apply requires the exact active maintenance deployment, holds its canonical
writer lock together with the broker lifetime lock through commit, rechecks
every plan and root identity, updates every required row through an exact
compare-and-swap, rejects missing, extra, changed, or adjacent rows, advances
schema metadata once, and verifies terminal policy and unchanged restore state
before commit. A sealed result binds both original repair documents, every
before/after policy value, the one revision, and replay identity. Pre-commit
failure rolls back; post-commit retry recognizes only the planned timestamp and
terminal rows.

Repository service recovery now retains maintenance while it starts the exact
recorded broker baseline and proves a stable root-owned socket plus the complete
schema-12 pre-owner-authority invariant set. It then permits normal broker
traffic only for the enrolled owner-scoped inventory canary; failure
immediately republishes the same deployment-bound marker. Terminal service
evidence is published only after the canary, socket identity, broker peer,
database inode/generation, and invariant proof agree. Replay reruns
authenticated readiness without repeating database mutation.

The observed incident had already advanced beyond that ordinary service
recovery: its bridge journal was schema-v3 `restored`, its supervised
crash-loop descendant was stopped, and the policy CAS intentionally made the
live authority a one-revision descendant of the original readiness result.
Generic activation requires the original exact readiness; generic clean
successor admission requires a live `ready` predecessor. Neither may be
weakened. A dedicated restored-policy transaction therefore binds all four
repair/policy plan-result files by raw and sealed digest, the original readiness
and retained backup, the exact restored journal and crash-loop proof, the
post-CAS database SHA/inode/generation/revision and full invariant set, both
stopped-writer locks, the complete owner map, and a distinct clean release with
the predecessor's exact content digest.

That transaction exports and strictly parses a complete owner-bound profile
while the broker remains stopped. It starts the clean candidate with canaries
privately deferred behind the inherited maintenance marker, then proves the
exact systemd invocation/MainPID, socket inode and peer PID, immutable argv and
source root, database, drop-in, profile, and complete schema invariants.
Maintenance is cleared only for current-client owner and collaborator inventory
canaries; the strong proof must remain identical across the clear. Failure
re-arms the same marker before stopping only the candidate journal's invocation
and removing only its drop-in, restores the captured profile, and reproves the
unchanged CAS and historical journal. Unknown cleanup state is never reported
as rollback: it remains sealed `recovery-required` behind maintenance.

A later live replay exposed one narrower inheritance trap: the clean-successor
journal was already forward-only at `predecessor-dropin-remove-intent`, but its
static binding named the older immutable client whose implementation could not
finish replay. A newly staged fixed client is not allowed to replace that
binding implicitly. The successor command accepts the handoff only when the
caller supplies the exact inherited raw and sealed journal digests, every
non-client binding is byte-for-byte equivalent, the old sibling release still
verifies through the current immutable release, and no prior handoff exists.
For a journal carrying the lifecycle `outer_rearm`, the earlier static-client
replay guard performs only a structural admission: an exact-phase,
client-fields-only first request with both digests, or one retained valid
same-target lineage, may reach the existing strict migration validator.
Missing or one-sided digests, non-client drift, an unsafe first-publication
phase, malformed lineage, and a second or different target remain rejected
before mutation.

At `2026-07-29T21:20:59Z`, an executor outside the active agent team advanced
the retained sealed journal one step to `predecessor-retired`: it removed the
exact bound drop-in while the broker and socket remained absent, but left the
old client binding, null candidate, untouched profile and backup, exact
database/readiness evidence, and no client lineage. The retained journal at
that boundary has raw SHA-256
`4b7d01138d5f1153d176860fc7f4d90384766ac8a16a030db8576f8a11a49e32`
and sealed document SHA-256
`5c8a3b31d99ca15bb33a7bad05a9ef1a5dcb60e17a0a898f74862e5bc5c52bb6`.
This immediate phase is independently safe for the same one-hop handoff only
because owner export and every profile/candidate mutation are still ahead of
it. Its intent must seal `predecessor-retired` and an absent drop-in, and the
strict validator rechecks the stopped broker, absent socket/drop-in, untouched
profile and exact backup, database/readiness evidence, null candidate, current
journal hashes, and client-only delta under the maintenance writer lock.
Lineage publication precedes owner export, and the state is revalidated under
the export writer lock. All later first-publication phases remain forbidden.
Using the legacy dual-release shortcut would execute a client absent from the
journal lineage; rewriting the retained journal or its history would erase the
observed transition. Extending the evidence-bound handoff by exactly one
pre-export phase preserves both the original bytes and the externally advanced
state instead.
Under the same maintenance writer lock it proves the marker, null candidate,
unchanged protected profile and backup, stopped broker, absent socket, safe
readiness descendant, exact SQLite main/sidecar bytes, and whether the
predecessor-bound drop-in is still present with its exact identity/digest or
already absent. Its
first durable step is a sealed intent binding that exact precondition, source
journal, and old/new releases, so a crash cannot recapture and bless later
drift. It then retains the original sealed journal bytes in the private
transaction directory and atomically appends one old-to-new client lineage
that references both artifacts while changing only the two client-release
binding fields. Only then may the existing transaction-owned removal path
unlink the exactly bound drop-in. Replay verifies the intent, retained
preimage, and lineage, accepts the safe monotonic bound-present to absent
transition after lineage publication, and rejects a changed, replaced, or
symlinked drop-in or any absent-to-present reappearance;
unsafe phases, further migrations, changed digests, changed
non-client arguments, and tampering fail closed.

## Verification

The focused suite covers a 20-policy incident-shaped fixture, complete
restore-state preservation, legacy plan/result lineage, no-write planning,
per-row generation changes, one revision, adjacent-row protection, target and
lineage tamper, pre/post-commit failure, idempotent replay, missing or
lock-raced maintenance, socket-never-ready, complete-invariant failure,
authenticated-canary failure and maintenance reactivation. It runs under
normal and optimized Python. The broader cutover suite and immutable release
installer suite exercise parser, wrapper, packaging, and release-capability
integration. The restored-policy transaction harness additionally proves the
exact `93369→93370`-shaped revision, raw historical-journal preservation,
cross-release rejection, strict fresh-ready candidate admission, marker-clear
crash replay, authenticated-canary rollback with CAS/database/profile
preservation, and fail-closed cleanup ambiguity in normal and optimized Python.
The clean-successor harness also reproduces the exact immutable-client trap,
proves the old static-binding rejection, and covers handoff creation, replay,
crashes after sealed-intent, retained-preimage, and atomic-lineage publication,
missing/wrong inherited digests, unsafe phase, non-client drift, retained-byte
tampering, sealed-lineage tampering, and profile/database/systemd drift both
before publication and after a handoff-publication crash. It also covers both
legitimate drop-in crash boundaries, durable evidence before removal, and
changed-content, replaced-inode, symlink, and absent-to-present rejection.
The live lifecycle-shaped regression additionally covers matching
`outer_rearm` proofs, first publication with both digests, same-target retained
replay, and rejection of one/missing digests, wrong phase, non-client drift,
malformed lineage, and a second target.
The externally advanced retired-phase regression covers exact sealed-state
admission, absent-drop-in intent/lineage, a crash after lineage publication,
same-target retained replay, lineage-before-owner-export ordering, post-lineage
revalidation, drop-in reappearance before and after publication, and sealed
lineage tampering.
Live acceptance still requires applying the sealed plan to the retained
authority and executing the dedicated clean immutable schema-12 recovery while
preserving the contaminated release and crash journal.
