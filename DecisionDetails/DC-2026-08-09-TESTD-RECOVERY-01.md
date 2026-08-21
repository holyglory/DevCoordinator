# DC-2026-08-09-TESTD-RECOVERY-01 — Durable active attempts survive testd replacement

## Supersession

DC-2026-08-19-ARCHITECTURE-SIMPLIFICATION-02 supersedes this recovery design.
Current replacement imports a complete atomic `result-package.tar` when
present; otherwise it stops, proves the cgroup empty, and cancels the unfinished
exact execution. No durable spool, recovery lease, heartbeat resurrection, or
semantic result-chunk replay remains. The content below records why the former
design existed; it is not current implementation guidance.

## Context

During same-schema delivery, GlobalFinance governed run `run-7ec79d7a602332cd52ebb39dafb1cf2d` remained in its native transient unit while testd was unavailable longer than the ordinary 30-second attempt lease. The replacement daemon reconstructed the exact active spool envelope, but its first ordinary heartbeat rejected the expired lease. The same scheduler turn then reaped the attempt as `running_heartbeat_lost` after 320 seconds with no runner result.

## Decision

The private durable spool is recovery authority only for the exact active attempt identity it already retains. After validating the candidate, lease, attempt state, generation, owner, repository binding, runtime ID, launch identity, and result-chunk sequence, replacement testd grants one bounded recovery lease before its first ordinary heartbeat/reaper turn. Confirmed launches receive the normal short lease; uncertain launches receive only the remaining bounded semantic launch deadline. Subsequent supervision uses the unchanged observation, heartbeat, result-spool, terminalization, and reaping paths.

The recovery transaction requires the persisted attempt to remain `leased` or `running`, with the exact generation and lease owner from the durable envelope. It cannot recreate an attempt, change its generation, issue another launch identity, or revive an already reaped or terminal row.

## Evidence and failure controls

- A running runtime beyond its ordinary lease survives engine reconstruction, is not reaped, and resumes ordinary heartbeat without a second launch.
- Wrong lease owner and terminal/reaped attempts fail closed.
- Existing runtime-exit, pending-launch, spool replay, late-result fencing, heartbeat-loss, and fault-recovery tests remain part of the full delivery cycle.
- Installed acceptance must span a real governed run across same-schema replacement and preserve the original run handle through its truthful terminal result.

The first software-owned delivery of the recovery implementation completed all
24 steps with zero failures and activated immutable release
`bf2d368cd1642b71c07fb29c4c1394976dd1c1bf84fa6c373efd9170897b615e`.
That proves the source, packaging, same-schema switch, health, and installed
acceptance gates; the separate live replacement canary remains required before
the originating bug can close.

The first governed Coordinator canary also exposed a manifest mismatch: the
universal-harness partition inherited `network: none` even though its production
preflight regressions intentionally create private loopback listeners. The
target now requests isolated `loopback` explicitly, consistent with the
confirmed single-developer local-test boundary in `security-assumptions.md`;
run `run-d990015f6d12b3c16ff213834f73e80d` then completed successfully with no
lease-expiry evidence.
