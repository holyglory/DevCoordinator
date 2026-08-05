# Performance stacked-composition selected-design QA

## Comparison target and state

- Source visual truth:
  `apps/DevOpsConsole/Artifacts/Design/performance-stacked-selected-reference.png`,
  1487 × 1058 RGB, SHA-256
  `a769f4e9b6e7ec75223e239428ec3b4290125570069a5e591d6a701e8487b515`.
  Its adjacent provenance sidecar binds the selected image-generation result to
  the captured Console state and design brief.
- Browser-rendered overview:
  `/tmp/devcoordinator-performance-formal-base-final-screens/http_127.0.0.1_43385_performance-desktop-1440.png`,
  1440 × 1183, SHA-256
  `000a7c5de307660b7ce752ec72a7d2aa332093e8126bf91ed4719880492b15ac`.
- Browser-rendered project detail:
  `/tmp/devcoordinator-performance-formal-modal-pass-screens/http_127.0.0.1_43385_performance_project-detail-open-desktop-1440.png`,
  1440 × 1183, SHA-256
  `87315d3337c32be61ab4402a952df2bad97e38986da01100be476b0e614eb686`.
- Route and state: `/#/performance`, dark theme, populated 60-minute history,
  four attributed repositories, whole-host residual visible, and
  GlobalFinance detail open with contributor evidence.

## Combined visual evidence

- The selected reference and normalized implementation detail were placed
  adjacent at equal 1487 × 1058 dimensions in
  `/tmp/devcoordinator-performance-reference-vs-implementation-final.png`,
  2974 × 1058, SHA-256
  `82534ac524b94de59357cd8a19c6adc6bff2869383eb75bc04a8291a4eaae3ac`.
- The combined image and unmodified browser captures were opened and visually
  inspected after the final CSS changes. Dynamic values differ intentionally;
  hierarchy, density, stacked-series composition, legend behavior, and modal
  geometry are the fidelity target.

## Findings and fixes

- The first implementation pass used muted small labels that missed the
  required contrast on the actual Console background. The Performance surface
  now supplies a higher-contrast local muted token without changing the global
  Console palette.
- The phone modal initially let its flex body keep its intrinsic minimum size,
  cutting lower contributors. `min-height: 0` now gives the body an independent
  `overflow-y: auto` path.
- At 320 × 900 and 390 × 900, Playwright proved the modal remains inside the
  viewport, the document has no horizontal overflow, the modal body reaches
  its exact maximum scroll position, and the final contributor row becomes
  completely visible. The formal verifier's remaining `fixed-offscreen-cut`
  signal for those pre-scroll descendants was recorded as a route-scoped false
  positive only after this reachability proof.
- No actionable typography, spacing, color, border, overflow, density, chart,
  legend, or modal mismatch remains at P0, P1, or P2.

## Browser and formal verification

- The focused Playwright regression passed at 320, 390, 768, 981, and 1440 px
  and exercised mouse, keyboard, and touch legend activation, retained modal
  selection across refresh, local modal scrolling, exact chart data, and
  document-overflow guards.
- Formal overview verification checked 15 populated pages/states across the
  five widths with 0 critical findings and complete target coverage. Evidence:
  `/tmp/devcoordinator-performance-formal-base-final.json` and
  `/tmp/devcoordinator-performance-formal-base-final.md`.
- Formal modal verification checked 5 populated pages across the five widths
  with 0 critical findings and complete target coverage. Evidence:
  `/tmp/devcoordinator-performance-formal-modal-final-pass.json` and
  `/tmp/devcoordinator-performance-formal-modal-final-pass.md`.
- Exact values remain available through native labels and the expandable data
  tables; the project legend opens the one selected-project dialog and restores
  focus on close.

final result: passed
