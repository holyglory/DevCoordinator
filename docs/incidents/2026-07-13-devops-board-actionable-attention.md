# DevOps Board actionable attention incident

## Outcome

Status: fixed

The signed Board no longer treats intentionally stopped managed servers as
broken. When current evidence genuinely requires intervention, the Board names
the affected action or resource, explains the evidence, states the recommended
next step, and provides a contextual Review, View Activity, or Refresh action.
On the user's current three-source inventory there is no unresolved issue, so
the Board is nominal and shows no red attention banner.

## Cause

Class: implementation
Confidence: confirmed
Request: The Board must say exactly what requires attention and what the user
should do, rather than repeat “Action or resource requires attention” and offer
an unrelated Refresh button.
Immediate cause: The health reducer treated every managed server with
`health.ok == false` as unhealthy even when its lifecycle state was stopped or
starting and no health endpoint should answer. It also allowed retained failed
Activity history to keep global health red after the user dismissed the
current action issue. `HealthSummary` retained only an unhealthy count, so the
presentation layer discarded the resource identity, failure reason, and safe
review route. The banner then used one generic title for the entire unhealthy
level, fell back to the same title as its subtitle, and rendered Refresh for
every non-nominal state even when refresh could not resolve it.
Why missed: The canonical neutral fixture already contained a stopped server
with `health.ok == false`, and the dense fixture hard-coded the duplicate
generic attention copy. The native assertions and snapshot verifier measured
geometry and pixels but did not assert that stopped lifecycle state stayed
nominal or that every non-nominal state named an item and exposed a working
route. The signed launch gate proved source, server, and repository counts but
did not publish or validate health semantics. A related layout detector also
counted the banner and Activity strip as variable-body content, so those two
surfaces could conceal a missing primary viewport while its brightness check
still passed.
Evidence: The supplied 824x91 screenshot has SHA-256
`d9c9248ec0ed263b0c623b57b6569ad7f572a6d2110d732f4fc15d98b8576ef0`
and visibly repeats the same generic sentence in the title and summary while
showing only Refresh. Reproduction against the loaded Board state found 19
managed-server records across source contributions 0/16/3. Their current
presentation was stopped; six carried intentional project/coordinator stop
reasons and the remainder were retained dead-process records, yet their failed
readiness values produced the red global state. Dismissing a failed action
issue also left its retained Activity result contributing to that state. The
pre-fix UI could not identify a resource because no resource-level attention
model existed.

## Changes

Product: Implemented lifecycle-aware server attention: explicit
unhealthy/degraded/orphaned states are actionable, and a failed readiness probe
is actionable only for a running server. Stopped and starting servers remain
ordinary lifecycle state. Docker/server failures and repository ownership
conflicts become typed `ResourceAttentionItem` values derived only from
currently loaded source evidence. Each item carries a concrete title, reason,
operator next step, and stable Review server/container/project route.
Action issues take presentation priority and route to Activity; inventory
failures retain Refresh; multiple resource issues expand into individually
reviewable rows. Dismissing the current action issue retains its Activity
evidence without claiming that a historical failure remains unresolved. The
main window and menu-bar UI share those semantics.
Prevention: Added inventory launch telemetry for health, concrete attention
item count, resolution-target count, and whether title/summary copy is
duplicated. The signed readiness gate rejects generic, unexplained,
unactionable, or nominal-with-phantom-attention states. Recall tests model the
reported generic banner, missing item, missing route, stopped/starting failed
probes, stale-only evidence, multi-source physical ownership conflicts, and
retained failed Activity; controls cover genuine unhealthy resources, busy
actions, shared review routes, and nominal stopped resources. The native
layout detector now excludes banner and Activity footprints from its primary
content observation and must reject a production-shaped render where those
surfaces remain but Project Load, filters, tabs, heading, and rows are erased.

## Verification

Original path: Post-fix, clean commit `2096759` was packaged, signed, launched,
and verified through `./script/build_and_run.sh --verify`. The real signed process
PID 31947 loaded all three discovered sources and reported
`managed=19 visible=19 repositories=9 repository_groups=9
unassigned_groups=1 health=nominal attention_items=0 resolution_targets=0
generic_attention=false`. Two subsequent automatic refreshes retained the same
source counts 0/16/3 and the same nominal attention contract. The app remains
running from the provenance-bound bundle; between refresh bursts it returned
to 0.0% CPU with no child helper and approximately 156 MiB RSS.
Checks: All 135 native Swift tests pass with one intentional snapshot-generation
skip. The explicitly enabled snapshot workflow regenerated and verified all
four canonical artifacts, and the public artifact guard found zero findings
across 168 publishable files. Launch-readiness and snapshot-detector self-tests
pass under normal and optimized Python. The full non-macOS repository
validation, repository freshness/current check, diff check, and source/geometry
guardrails pass. A fresh 524x760 action-state capture is SHA-256
`f124df1dfb9be059f7d1375a3d213aa8eda4a09e40a2c06ae734d20450b822af`;
independent raster inspection confirms Project Load, filters, tabs, resource
rows, Activity, toolbar, and status are all populated. The apparent fragmented
preview of that opaque RGBA image was a downstream viewer artifact, not source
geometry; the primary-content detector gap found during that check was fixed
and its must-catch passes.
Residual risk: Freshness is currently modeled at coordinator-source snapshot
granularity, not with an independent sample timestamp for every resource row.
The Board therefore suppresses a conflict unless every participating source is
currently loaded, which is conservative but cannot prove row-level recency
inside a loaded snapshot. A genuine ownership conflict is deliberately
review-only and blocks unsafe lifecycle actions; the Board will not guess which
repository owns a physical process or container. The normalized v2 store and
per-resource provenance proposed in the repository-catalog architecture remain
future work.
