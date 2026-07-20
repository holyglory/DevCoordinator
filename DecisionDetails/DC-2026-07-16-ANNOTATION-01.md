# DC-2026-07-16-ANNOTATION-01 — Console collections keep a bounded mounted surface

## Context

The authenticated production Console had an exceptional mounted resource
surface after the Coordinator became host-wide and its retained Docker
inventory grew. This was initially treated as the cause of a reported Codex
annotation failure. The user's retest proved that causal claim wrong; this
record now owns only the still-valid browser-performance decision. Annotation
compatibility is decided by DC-2026-07-16-ANNOTATION-02.

## Evidence

- The live authenticated default page contained 27,522 elements, 11,931
  rendered elements, 3,729 interactive elements, and 1,588 visible buttons.
- `#sec-projects` alone mounted 12,410 descendants and 489 rows. Hidden Docker
  and Servers sections remained in the same document with another 14,285
  descendants and 572 rows.
- The host inventory contained 474 retained containers (81 running and 393
  stopped), 98 server-page rows, and only three project groups. Projects began
  expanded and all dynamic page bodies were rebuilt on every overview render.
- Captured `pointermove` and `mouseover` events reached ordinary page elements.
- The initial post-change production recount proved the element budget and
  page behavior, but it never exercised Codex annotation hover or selection.
- The deterministic formal UI verifier reported no critical or warning-level
  geometry defect at 1440×900 or 390×844, but its inventory exposed the
  exceptional document size. The runtime self-test passed before that run.
- After the user reported the failure remained, strict-CSP pages reproduced
  the exact white 300×150 default iframe while permissive pages did not. That
  later evidence disproved DOM size as the annotation cause.

## Options considered

1. Remove stopped container history. Rejected because retained historical state
   is an explicit operational requirement and removal would make the UI's count
   and recovery behavior dishonest.
2. Change CSP. Deferred from this performance decision because the initial
   evidence did not establish the needed exception. DC-2026-07-16-ANNOTATION-02
   later selects the narrowly proven style-attribute exception.
3. Only collapse Projects. Rejected because navigating to Docker or expanding a
   large project would recreate the same unbounded candidate set.
4. Virtualize rows. Capable, but it adds scroll measurement, focus restoration,
   and accessibility complexity that is unnecessary for an operational list.
5. Lazy-mount the active page and paginate resource collections. Selected
   because it bounds browser work, preserves deterministic ordering and native
   focus semantics, and keeps every real resource and action reachable.

## Consequences and verification contract

- Hidden hash pages retain no dynamic body.
- Projects begin as the promised repo collection. At most one repo is expanded,
  and its members are paged.
- Servers, Docker, and expanded project members mount no more than 75 resource
  rows. Page indices clamp after inventory shrink or hide operations, and all
  rows remain reachable exactly once across pages.
- Annotation compatibility is not inferred from DOM counts or pointer events.
- Performance readiness requires the deterministic 474-row regression, full
  Console tests, authenticated wide/narrow formal verification, and a
  production DOM recount on Projects, Servers, and Docker.

## Verified performance outcome

- The final production asset is content-addressed as
  `app.js?v=66393d3839da`; the consistency test prevents an immutable-cache
  version from drifting from the CSS/JavaScript content.
- The authenticated Projects page fell from 27,522 total elements and a
  93.5 ms full geometry/style scan to 417 elements and 1.6 ms. It rendered
  seven real project rows, zero member rows until expansion, zero children in
  every inactive dynamic body, and received the captured pointer event.
- Servers rendered 75 of 98 real rows on page 1 and 23 on page 2. Docker
  rendered 75 of 474 real rows and advanced to rows 76–150 with a distinct
  first item. Their production documents contained 2,375 and 2,240 elements.
- Authenticated formal verification checked Projects, Servers, and Docker at
  1440×900 and 390×844 with full target coverage, zero critical findings, and
  no geometry failure in the screenshots. Six warning samples were inspected:
  three were intentional project-name ellipsis whose clipped parent prevents
  visual overlap, and three sampled a row crossing the viewport bottom before
  the verifier's successful full-page scroll.
- The isolated canonical desktop/mobile captures were regenerated with source
  provenance. All 154 Console tests and the complete
  `scripts/validate.py --skip-macos-app` repository gate passed.
- Production health stayed `ok`; the coordinator continued to report the exact
  `devops-console` registration at PID 3209284, project
  `/home/DevCoordinator`, port 443, status `running`. No restart was required
  because the service streams static files from the canonical checkout.
- This outcome did not fix or verify Codex annotation mode. The original
  completion claim was an agent mistake corrected by the prevention and
  reproduction work in DC-2026-07-16-ANNOTATION-02.
