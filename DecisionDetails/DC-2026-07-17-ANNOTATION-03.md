# DC-2026-07-17-ANNOTATION-03 — Split inline styles for annotation compatibility

## Decision

Console permits inline style attributes with `style-src-attr 'unsafe-inline'`
and inline style elements with `style-src-elem 'self' 'unsafe-inline'`. The
broad fallback remains `style-src 'self'`, scripts remain `script-src 'self'`,
and no blob/data frame, remote style, inline script, or evaluation source is
added.

The user explicitly approved the style-element directive on 2026-07-17 after
the observed failure, available alternatives, and CSS-injection tradeoff were
explained. This supersedes the invalidated attr-only conclusion in
[DC-2026-07-16-ANNOTATION-02](DC-2026-07-16-ANNOTATION-02.md).

## Evidence and rationale

The authenticated in-app retest under the attr-only policy still showed a
25×25 hollow white renderer square and neither hovered nor selected page
elements. A corrected Chromium fixture covers parent inline style elements and
inherited `about:blank`/`srcdoc` child styles: the attr-only policy records
`style-src-elem` violations and leaves the renderer surfaces at static/default
geometry, while the split element directive restores viewport geometry and
corner pointer coverage. Inline scripts remain blocked in both child paths.

Exact private Codex renderer source is not available on this host, so this is
a bounded causal reproduction, not an invented renderer contract. The final
acceptance boundary remains the user's authenticated in-app annotation path.

## Alternatives and consequences

- Keeping attr-only was rejected because it was tried and failed the original
  user path and the corrected parent/inherited-child guard.
- Removing or reporting-only CSP, broad `style-src 'unsafe-inline'`, and inline
  scripts were rejected as disproportionate reductions of the authenticated
  administrative surface's XSS defenses.
- Nonces and hashes were rejected because Console cannot supply a per-response
  nonce or stable hash to a third-party injected renderer.
- Blob/data frames and remote style origins were excluded because no observed
  violation requires them; adding them would be speculative.

An attacker who already has an HTML-injection primitive can now inject CSS in
style elements as well as attributes, potentially hiding or rearranging UI.
Same-origin external style and script restrictions, blocked inline scripts,
base/form/object restrictions, and the rest of the policy remain enforced.
Reverting the single element directive is operationally simple if Codex gains
a nonce-compatible or isolated renderer boundary.

## Verification contract

- Static guards require both exact split directives and reject broad style or
  inline-script permissions.
- A realistic Chromium must-catch fixture proves the prior attr-only policy
  fails parent and inherited-child style application.
- The production policy must restore viewport geometry and pointer coverage in
  both renderer-shaped child paths while inline scripts remain blocked.
- Console's canonical streamed index and the matching PRTZN response policy
  must be verified before the user retests.
- Completion requires hover and selection in each original authenticated
  in-app browser path; further CSP relaxation requires new violation evidence.

## Verification performed on 2026-07-17 and 2026-07-18

- The focused static detector passed both tests: it accepts the exact split
  directives, rejects broad inline style/script permissions, and retains the
  attr-only policy as a must-catch failure.
- The complete Console suite passed 156/156 tests, including all 21 full-stack
  e2e journeys. The first run's e2e bootstrap correctly rejected the host's
  pre-existing `/tmp/.git` marker as an unsafe backup ancestor; the full rerun
  used verified Git-free `/var/tmp`, preserved the production safety check, and
  had no failures or cancellations.
- Console's static server stats and streams the canonical no-cache HTML on each
  request, so the policy update does not require a process restart. The same
  split policy was built and deployed in PRTZN through Coordinator.
- An authenticated Chromium probe against the live PRTZN listener received the
  exact split CSP at 390×844 and 1440×900. Parent and inherited
  `about:blank`/`srcdoc` child style surfaces were fixed, borderless,
  viewport-sized, and topmost at both corners; inline scripts remained blocked.
- On 2026-07-18, the user's authenticated Codex in-app browser successfully
  entered annotation mode on `https://console.vr.ae/#/servers`, hovered real
  Console content, and selected two project headers for element-bound comments.
  The captured selectors and marker screenshots prove the original Console
  hover-and-selection boundary now works; this is stronger acceptance evidence
  than the earlier renderer-shaped Chromium fixture alone.

The remaining acceptance evidence is limited to hover and element selection on
PRTZN through the user's original authenticated Codex in-app browser. Console
no longer belongs in the open annotation item.
