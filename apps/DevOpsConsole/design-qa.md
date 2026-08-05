# Tests fleet selected-design QA

## Comparison target and state

- Source visual truth:
  `apps/DevOpsConsole/Artifacts/Design/tests-fleet-selected-reference.png`,
  SHA-256
  `aac3aa8bb2dcbee323c56cdb410b14601a52e1a2d5182f1d838411f7242a614d`.
  It is the exact 1,555,095-byte image-generation result from session
  `019f624f-69d2-7893-929b-d8f18000e1e8`, generation
  `exec-e567da29-e6b5-4cdd-82f0-051f797f1f37`; its repo-owned provenance
  sidecar records both source-input hashes.
- Browser-rendered implementation:
  `apps/DevOpsConsole/Artifacts/Canonical/tests-detail-desktop.png`, SHA-256
  `63b566f703a95d54f806b037060d77cf39e047d041c8d06d325448002911f6ed`.
  Its provenance sidecar binds the pixels to the current UI, fixture, browser
  test, helper, and locked Playwright files.
- Route and state: `/#/tests`, dark theme, populated 18-repository 24-hour
  fleet, GlobalFinance selected, desktop repository detail open on Overview,
  exact-value fleet tooltip visible, failure/flake trends and top actionable
  regression visible.
- Source pixels: 1487 × 1058 RGB. Implementation pixels and CSS viewport:
  1486 × 1059 at device scale factor 1. For comparison only, the implementation
  was cropped by one bottom pixel and padded by one right pixel to 1487 × 1058;
  the unmodified capture remains the primary implementation evidence.
- Same-size normalized implementation was retained only as local QA evidence
  (not published), SHA-256
  `f061f7fc74219278711c156a7761a18880fb30352cc3085f8b16c09eebc76b00`.

## Combined visual evidence

- Full-view, same-input comparison was retained only as local QA evidence
  (not published), 2974 × 1058, SHA-256
  `3e78bb7d2219bcb031f0c991a00e6560d19a55aa5dd91c6ee475e2a1ce3311d8`.
  The reference and normalized implementation are adjacent at equal size.
- Focused repository-sheet comparison was retained only as local QA evidence
  (not published), 1058 × 1058, SHA-256
  `e2ebaad396fd9ff7f30b5866038c0b5ca011dae62809b244ad79085c840687fb`.
  This focused crop was required because chart labels, fact strips, regression
  evidence, tabs, and persistent actions are too small to judge reliably in
  the doubled full view.
- Both combined images and the unmodified implementation capture were opened
  and visually inspected after the final browser run. The source and
  implementation use different fixture dates and health values, so the review
  judges the same interaction/composition state without treating dynamic copy
  as pixel-identical data.

## Comparison history

### Pass 1 — blocked

- P1 · missing visual truth: the previous audit could not traverse the selected
  image and incorrectly reported it unavailable. The exact bytes were
  recovered, hash-verified against the generation result, copied to a durable
  repo-owned Design artifact, and given a provenance sidecar.
- P1 · desktop composition: the implementation used a 690 px / 46.4% modal
  sheet with a backdrop, obscuring and disabling the fleet. The selected target
  uses an approximately 529 px / 35.6% sheet while the fleet remains live.
- P1 · first-viewport density: the 18-repository fixture pushed fleet capacity
  and Needs attention below the 1058 px viewport.
- P1 · repository evidence: failure/flake trends and structured regression
  evidence, impact, change, and last-observed facts were absent.
- P2 · open-state controls: after the first structural correction, the search
  control collapsed too far when the fleet reflowed beside the sheet.

### Fixes

- Desktop detail now uses non-modal `dialog.show()` while narrow viewports keep
  `showModal()`. The sheet is fixed below the global navigation at
  `min(530px, 35.6vw)`, and the main fleet reflows by the same width.
- The desktop fleet uses 22 px repository rows and compact lower panels, so all
  18 rows, capacity, and Needs attention fit in the first viewport.
- Repository Overview now includes real daily failure/flake trends and
  structured top-regression evidence. Largest dynamics is progressively
  disclosed; individual runs remain on the explicit Runs tab.
- The open-state title/filter/search flex constraints preserve a usable search
  field beside the sheet.
- The canonical browser regression now asserts the selected sheet proportion,
  non-modality, navigation clearance, fleet reflow, first-viewport density,
  tooltip usability with detail open, responsive width, and absence of
  unexpected page/console errors.

### Pass 2 — passed

- The final full-view comparison shows the same major composition: fleet matrix
  first, 18 repositories visible, capacity and attention below it, a narrow
  right sheet, and persistent Run tests access.
- The focused comparison confirms the sheet's hierarchy and evidence: headline
  health facts, throughput/efficiency, failure and flake trends, an actionable
  regression, secondary dynamics disclosure, and persistent View runs/Run
  tests actions.
- No actionable P0, P1, or P2 visual differences remain.

## Required fidelity surfaces

- Fonts and typography: the implementation keeps the Console's existing
  system/monospace families, compact optical weights, hierarchy, wrapping, and
  truncation. Headings, small labels, matrix names, chart labels, and regression
  facts remain readable in the unscaled capture. The generated reference's
  slightly softer antialiasing is an expected raster-generation difference.
- Spacing and layout rhythm: the sheet boundary matches the reference at about
  x=958; the fleet and sheet do not overlap; the global navigation remains
  visible; all required fleet panels fit the first viewport; sheet sections and
  bottom actions retain consistent gutters, borders, and vertical rhythm.
- Colors and visual tokens: both use the established near-black/slate Console
  palette with blue focus/action states and semantic green/amber/red signals.
  The implementation deliberately retains the documented blue → amber → red
  workload scale with separate failure markers; the reference's
  green → amber → red scale was not an explicit selected requirement and would
  conflict with the existing workload contract.
- Image quality and asset fidelity: this data UI has no logo, illustration, or
  product-imagery substitution. The source reference and implementation capture
  are sharp, uncompressed PNGs; no placeholder imagery, CSS art, emoji, or
  handcrafted SVG substitute is used for a target image asset. Existing Console
  icons remain from its registered icon system.
- Copy and content: the fleet and repository labels are concise and
  standalone. The implementation retains Overview / Runs / Setup because Setup
  is the real manifest/isolation workflow; the reference's Insights label and
  alternate global navigation were not explicit selected requirements. Fixture
  timestamps and health values are intentionally current test data rather than
  copied mock values.

## Browser and interaction verification

- `apps/DevOpsConsole/test/unit.tests-ui.test.mjs`: 2 of 2 passed.
- Focused real-browser test
  `Tests loads fleet awareness within one second and reveals repository detail
  on demand`: passed against the isolated HTTPS fixture and current shipped
  `index.html`, `app.css`, and `app.js`.
- Primary interactions exercised: fleet load before heavyweight inventory,
  repository selection, pointer and keyboard exact-value disclosure, detail
  open/close, desktop non-modal reflow, 1440/981/768 desktop and 390/320 mobile
  resizing, mobile full-screen detail, touch-pinned exact values, Escape
  dismissal, and maintenance/error retention.
- The browser emitted no unexpected page or console errors. The guard allows
  only the fixture-declared `404 Not Found` endpoint fallback and
  `503 Service Unavailable` maintenance response.
- Desktop/mobile document-width and matrix/list geometry assertions passed;
  the mobile matrix-to-card substitution and full-screen detail remained
  usable. No separate mobile visual target exists, so mobile evidence verifies
  the written responsive contract rather than claiming pixel identity.

## Findings

No actionable P0, P1, or P2 findings remain. A P3-only visual difference
remains: the reference uses generated, slightly softer chart/text rendering
and denser mock-specific comparison annotations, while the implementation uses
the live Console's exact data vocabulary and rendering.

final result: passed
