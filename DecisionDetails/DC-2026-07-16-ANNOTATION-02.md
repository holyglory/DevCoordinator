# DC-2026-07-16-ANNOTATION-02 — Attr-only annotation compatibility (invalidated)

## Correction

The user's authenticated PRTZN retest on 2026-07-17 invalidated this
decision's renderer model and completion claim. The new screenshot contains a
25×25 hollow white injected square, not the previously claimed exact 300×150
artifact, and annotation still neither hovers nor selects.

The earlier detector exercised outer style attributes only and incorrectly
treated blocked inline style elements as success. A corrected Chromium fixture
models parent style elements and inherited `about:blank`/`srcdoc` child
styles. The deployed attr-only policy produces `style-src-elem` violations and
no viewport pointer coverage; adding the split
`style-src-elem 'self' 'unsafe-inline'` directive restores both while inline
scripts remain blocked. Exact private Codex renderer source is unavailable on
this server, so this is a bounded causal reproduction rather than an invented
renderer contract.

The user explicitly approved the additional style-element risk on 2026-07-17;
[DC-2026-07-17-ANNOTATION-03](DC-2026-07-17-ANNOTATION-03.md) supersedes the
deployed attr-only policy.

## Context

The user reported that Codex annotation mode still did not hover or select on
the live Console after the DOM-budget change. Entering the mode produced a
white, thick-bordered rectangle in the middle of the page. The initial report
also appeared cross-domain, so the investigation used live success and failure
controls before changing the product again.

## Reproduction and cause

- The user confirmed annotation fails on the real `console.vr.ae` and
  `prtzn.vr.ae` applications, but works on `skydive.vr.ae` and on the
  Console-generated `gf.vr.ae` upstream-unavailable page.
- Authenticated live inspection found strict CSP on both failures: Console's
  meta policy fell back from `style-src` to `default-src 'self'`, while PRTZN
  explicitly sent `style-src 'self'`. Both working controls had no CSP.
- The edge streams routed HTML unchanged, preserves end-to-end response policy
  headers, and adds only HSTS. Google authentication, wildcard TLS, and proxy
  body rewriting were therefore excluded.
- Injecting an annotation-shaped iframe under the incident Console policy left
  it at the browser default: 300×150, `position: static`, `2px inset white`
  border, and no effective inset or z-index. The identical probe on Skydive was
  fixed, borderless, viewport-sized, and topmost. This exactly reproduced the
  user's visible rectangle.
- The current Codex manual documents element click and area drag but does not
  publish a CSP integration contract. Remote host logs contain no desktop
  renderer or annotation events, so the page-level Chromium reproduction is
  the available deterministic boundary.

## Prevention before product change

`unit.annotation-csp.test.mjs` was added while the incident policy was still in
place and failed with `inline annotation overlay styles are blocked`. Its
must-catch fixture uses the exact `default-src 'self'` fallback, while controls
reject broader inline style-element and script permissions. The production
index must pass the same style-attribute-only contract.

## Options considered

1. Keep the strict policy and rely on the DOM reduction. Rejected because the
   user's retest and exact iframe reproduction disproved that cause.
2. Remove CSP or make it report-only. Rejected because this is an authenticated
   administrative surface and either option removes preventive enforcement.
3. Add `unsafe-inline` to `script-src`. Rejected because the reproduced failure
   is overlay geometry, not script execution, and enabling injected scripts
   would be a disproportionate XSS regression.
4. Add `unsafe-inline` to all inline styles through `style-src`. Capable, but
   broader than required because it also enables arbitrary inline `<style>`
   blocks.
5. Use a nonce or hash. Rejected for this boundary because the Console cannot
   give its per-response nonce to Codex's third-party runtime, and hashes do not
   authorize dynamic style attributes.
6. Add `style-src-attr 'unsafe-inline'` while retaining `style-src 'self'` and
   `script-src 'self'`. Selected because Chromium proves it restores the exact
   iframe geometry while inline style elements and scripts remain blocked.

## Security and operational consequences

Style attributes may now be applied by injected markup, including the Codex
overlay. Inline `<style>` blocks and inline scripts remain blocked, as do
objects, non-self resources, foreign form actions, and foreign base URLs. This
is a narrower exception than the commonly used `style-src 'unsafe-inline'`.
The Console streams its canonical index directly, so the change does not
require a service restart.

## Verification contract

- The detector must catch the incident policy and reject policies that enable
  inline style elements or inline scripts.
- Chromium must compute the injected overlay as fixed, borderless,
  viewport-sized, and topmost under the selected policy.
- Live Console inspection must prove that same geometry while inline style
  elements and inline scripts remain blocked.
- Final acceptance requires the user's original in-app annotation path to
  hover and select on Console. PRTZN must make the same change in its canonical
  source before its strict-CSP page can pass the same user-visible path.
