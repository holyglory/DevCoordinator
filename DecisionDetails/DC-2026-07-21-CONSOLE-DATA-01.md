# DC-2026-07-21-CONSOLE-DATA-01 — Console observations drive truthful Docker rows and collection counts

## Context

The Console Docker page retained its CPU / Mem column but every running row rendered an em dash. A live server-wide inventory after an explicit observation contained 18 current physical containers, 14 running containers, and no `stats` objects in the compatibility projection consumed by the Console, even though the normalized store retained hundreds of exact-resource Docker telemetry samples. The normalized migration had correctly made ordinary inventory query-only, but the Console metrics loop continued to perform only cached inventory reads. Current Docker presence therefore also stopped advancing unless another agent or a Telegram bot with an eligible recipient happened to request `HOST_OBSERVE`.

Production journal evidence showed repeated `POST /v1/observe` failures at the generic 15-second Console client timeout. A direct attributed observation completed successfully in 8.7 seconds, confirming Docker sampling is technically available but can approach the old deadline under broker contention.

Separately, the Telegram navigation badge displayed the total number of pending private-chat authorization requests. A user with registered bots and no pending `/start` requests therefore saw `Telegram 0`, while the page's own collection heading correctly counted bots.

## Decision

- The Console's server-side metrics loop is a designated attributed observer. Each non-overlapping tick requests `HOST_OBSERVE` as `devops-console:metrics` for the configured canonical project, then performs a pure inventory read and ingests that committed view.
- Observation failure is unknown current host state, not absence. The sampler still reads and displays the last atomically committed inventory, preserves history, and exposes the observation error. If the inventory read also fails, the structured operator-facing message retains both failures.
- Give `/v1/observe` a 60-second client deadline, matching the existing Docker/inventory class, without widening ordinary control requests.
- Attach compatibility `stats` only when the exact immutable Docker resource is running, belongs to the latest completed Docker-available snapshot for its host, and has a telemetry sample inside that snapshot's start/completion window. Preserve stopped, absent, and older telemetry in normalized history without presenting it as live.
- Keep broker and HTTP API restartable as independent availability boundaries. While an older broker projection is still serving, the Console may fill a missing `stats` value only after its own authenticated `/v1/observe` result proves the exact completed `host-runtime-v2:full-docker` snapshot in the normalized graph, the current immutable resource maps through an available engine to the same host, its normalized observation is running inside that window, and its exact Docker telemetry is also inside the window. Canonical `stats` ownership—including an explicit `null`—always wins, and the cached wire graph remains unchanged.
- Keep current presence defined by that same latest available snapshot. Do not hide stopped-but-present containers and do not use UI status or names to infer physical absence.
- Make the Telegram navigation badge and page heading both count registered bots. Pending users remain visible only in each explicitly labeled bot authorization queue.

## Alternatives rejected

- Removing the Docker CPU / Mem column was rejected because the broker already measures exact running-container CPU and memory; the missing numbers were a projection and observation-scheduling defect.
- Sampling implicitly inside ordinary inventory was rejected because inventory is a query-only API and callers must be able to inspect retained state without host mutation.
- Filtering stopped rows or applying a browser-side `exists` heuristic was rejected because a stopped container can still physically exist and the browser lacks authoritative snapshot membership.
- Reusing the newest retained telemetry sample was rejected because it can belong to a prior physical-presence snapshot and would display stale utilization as live.
- Depending on Telegram polling or another agent to refresh Docker state was rejected because Console truth must not depend on an unrelated integration having eligible recipients.
- Treating any completed snapshot or timestamp overlap as Docker proof was rejected because the normalized wire graph intentionally omits capability and snapshot-membership tables. The authenticated observation result supplies the missing capability identity during a rolling deployment; without a matching proof the Console leaves utilization empty.
- Keeping the Telegram badge as an unlabeled attention count was rejected because its destination and section count promise the bot collection; authorization queues already carry their own labeled counts.

## Guard evidence

Focused coordinator regressions prove that a current running immutable container receives telemetry only from the latest Docker-available snapshot window, a running row with only an older sample receives no live stats, a stopped-but-present row receives no live stats, and retained samples are not deleted. Existing controls continue to prove that absent history is excluded, stopped-but-present resources remain visible, Docker-unavailable observations preserve the last proved presence, and later reappearance restores the exact identity.

Focused Console sampler regressions prove observe-before-inventory ordering and identity, successful telemetry ingestion, last-committed fallback after observation failure, retained history after inventory failure, and preservation of both errors when both boundaries fail. The coordinator-client policy test pins the larger observation deadline without widening ordinary server actions. A real shipped-assets browser regression asserts rendered Docker CPU/memory values and a one-bot/zero-pending Telegram badge and heading of `1`.

Console projection controls additionally prove authoritative filtering against the normalized current-resource set, exact authenticated snapshot/host/engine/running-observation/window matching, rejection of unavailable engines, unproved hosts, stopped observations, stale and newer-untrusted telemetry, preservation of canonical objects and explicit `null`, and non-mutation across cached re-projection.

## Verification

The focused Docker grouping and normalized lifecycle suites pass 46 tests in both normal and optimized Python; the focused inventory-v2 store contract passes. Focused Console coordinator-client and metrics suites pass, including every projection false-positive control. The shipped-assets Chromium regression passes. Formal authenticated Docker-page verification passes at 390×844 and 1440×900 with complete coverage and no critical or warning findings. Repository validation, boundary checks, and whitespace checks pass. In production, an authenticated attributed observation proved the exact full-Docker snapshot and the Console projection returned stats for every currently running authoritative row while stopped rows remained without live stats; `https://console.vr.ae/healthz` returned 200, the replacement supervised Console PID registered exactly to port 443, and its post-restart journal contained no observation timeout, crash, or restart error.
