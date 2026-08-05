# Test capacity follows observed host memory

## Confirmed intent

This is one developer's Linux server even though several Unix accounts and agent products use it. Test throughput and short paid wall time matter more than per-account fairness. The user explicitly rejected per-worker CPU, memory, PID, and active-job quotas. CPU saturation is acceptable and desirable. Disposable test history may be reset; the reset discards the isolated Test Store and its exact durable attempt spool together while testd is stopped. User settings and authority data are not part of that reset.

## Selected contract

- Read `/proc/meminfo` immediately before scheduling and use `MemAvailable`, not total memory or manifest declarations.
- Retain one host reserve for the protected control plane and OS. Candidates wait only when their learned memory estimate would cross that reserve.
- Learn memory from retained measured peaks for the same immutable repository and target identity. Bootstrap unknown targets cautiously and replace that fallback as soon as measurements exist.
- For candidates selected in the same scheduling turn, subtract their full learned commitments. For active attempts, subtract only the part of each commitment not yet reflected by its current cgroup memory; if current usage is temporarily unavailable, retain the full commitment until it is observable or the attempt ends.
- Record aggregate cgroup peak memory and CPU time where available, with runner measurements as a fallback. Missing measurements remain unavailable, never zero.
- Keep dependency, exact-live-worktree, and exclusive-resource correctness gates. A launch batch bounds one scheduler turn only; it is not an active-job quota.
- Run attempts in an accounting-only test slice with no CPU, memory, or PID ceiling. Keep timeout, process-group cancellation, cleanup, network policy, and filesystem isolation.
- Persist a structured memory-wait reason and show it only in the affected repository/run detail. Heatmaps remain test-intensity visualizations.

## Rejected alternatives

- Increasing the existing generated 6 GiB budget would only move the mismatch and retain duplicate quota machinery.
- Trusting declared 16/32 GiB requirements is not empirical and causes unnecessary queueing.
- Per-UID or per-repository fairness quotas solve a multi-tenant problem that this confirmed single-developer deployment does not have.
- CPU admission or throttling increases paid wall time and provides no requested benefit.

## Verification

The delivery gate must prove CPU and PID declarations never reject a run, transient units and their containing slice have no CPU/memory/PID limits, memory admission responds to injected `MemAvailable`, measurements survive durable spool replay, learned peak memory changes later admission, wait evidence is repository-local, and the deployed Console completes its browser journeys without capacity warnings in global attention or heatmaps.
