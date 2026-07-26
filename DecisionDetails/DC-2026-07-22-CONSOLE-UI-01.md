# DC-2026-07-22-CONSOLE-UI-01 — Resource groups disclose locally and responsive rows protect identity

## Context

At 1135×919, the Docker table reserved roughly 1,040px for status, image,
telemetry, ports, actions, and gaps before allocating its flexible name track.
The reported long GlobalFinance container name therefore received about one
character of width and wrapped vertically. The same flat list paged the first
75 host-wide rows, so an 85-container GlobalFinance project displaced every
later project header.

The first responsive correction still left a real 319px defect. Its browser
guard exercised only 1135px, while formal mobile evidence used 390px and an
empty metrics fixture. On a real narrow row, the generated `CPU / Mem` label
became a horizontal child of the flex usage cell; nowrap values plus the fixed
92px SVG sparkline then extended beyond both the card and viewport. The user's
project-header screenshot was also from the earlier direct-header DOM, proving
that the already-open SPA had not loaded the new disclosure assets.

The same fixed-column failure later appeared on Servers at 787×919. Port,
telemetry, status, warning, actions, and gaps consumed the whole one-row grid
before the 719px card breakpoint, reducing `smoke-caddy-http` to one character
per line. The existing guard checked compact project headers but not expanded
server-row geometry at an intermediate width.

The next mobile fallback overcorrected by putting every server field and its
generated label on a separate full-width line. At the user's exact 620×919
viewport, a sparse server row therefore consumed several hundred vertical
pixels and separated port, utilization, status, and actions with empty bands.

The authenticated owner also received “not authorized to read archives.” Live
broker evidence showed that cleanup ACLs were absent while the production
lifecycle migration remains intentionally blocked by unresolved database
terminal-timeout and restore-replay work recorded in `CompletionLedger.md`.

## Decision

- Keep every nonempty Docker project header mounted and collapsed at boot.
  Opening one closes the previous project; disclosure state is transient.
- Mount and page only the open project's visible containers, 75 at a time.
  Lifecycle focus opens the exact owning project and member page.
- Between 720px and 1279px, protect at least 220px for the name and move image,
  utilization, and ports to a second row while actions occupy the upper zone.
- Between 720px and 1023px, protect at least 180px for the server identity;
  keep identity and actions in separate first-row zones, and move port,
  utilization, status, and warning evidence to the bounded second row.
- From 480px through 719px, render server identity/subdomain, secondary facts,
  and actions as three compact bands. Keep port, utilization, and status on one
  summary row and suppress their redundant generated labels.
- Below 480px, use four short server bands and let the row sparkline yield to
  its live values. Docker cards retain their bounded stacked-label treatment,
  with the real inline SVG sparkline allowed to shrink.
- Default `LIFECYCLE_ENABLED` to false. Publish readiness in `/api/session`,
  disable Archived views and archive actions in the browser, and reject list,
  plan, apply, and restore server-side until the whole capability is enabled.

## Alternatives rejected

Cross-project paging and a GlobalFinance-only filter hide valid project
collections. Persisting expansion can hide newly relevant resources. Removing
CPU/memory or other real columns discards available operational data. Granting
only archive-read or inferring cleanup from Google ownership creates partial
authority while destructive plan/apply prerequisites remain unsafe.

Clipping or globally hiding the row sparkline was rejected because it would
conceal a real geometry defect or discard useful history. Keeping a fixed 92px
plot was tried and failed at 319px; keeping every field on its own labeled line
was tried and failed at 620px. A compact summary preserves the values and
actions, while the plot yields only where the phone-width track cannot contain
it.

## Guard evidence

Structural regressions pin empty exclusive disclosure state, native button and
ARIA wiring, group-local paging, and the intermediate grid. A shipped-assets
Chromium journey uses 85 GlobalFinance containers plus XFoil at 1135×919 and
proves both headers remain visible, one group opens, 75 rows mount, the long
name keeps a 220px cell, actions do not overlap ports, and focus survives
keyboard switching. Config, API, and UI tests prove invalid flags fail, disabled
sessions make no archive request, and enabled owner journeys still work.

The same shipped-assets journey now renders real two-point project and Docker
SVG history at both the exact reported 319×1804 viewport and a 390×844 control.
It bounds every visible project-summary part, row usage cell, usage button,
sparkline, ports cell, and action cluster to its disclosure/card; asserts zero
row or project horizontal overflow; and rejects vertically collapsed project
or container names. The must-catch version failed before the CSS correction on
the row sparkline extending past the card.

The shipped-assets journey also reproduces an expanded `smoke-caddy-http`
server at 787×919. It requires a 180px identity track, at most two rendered
name lines, no escaping port/utilization/status/actions, and zero row or project
horizontal overflow. Its must-catch assertion failed on the prior fixed
seven-column grid. A formal verifier fixture using the shipped stylesheet
checked 390×844, 787×919, and 1440×900 with zero critical or warning findings.

The same journey now checks the exact reported 620×919 viewport and a 390×919
adjacent case. It budgets at most 150px and 180px respectively for the whole
server row, requires every secondary generated label to stay suppressed, and
binds identity, port, utilization, status, and actions to both row and project
bounds. The must-catch test failed on the previous one-field-per-line layout.
The formal verifier then checked the expanded shipped-asset fixture at
620×919, 390×844, and 1135×919 with three required pages, zero skipped pages,
and zero critical or warning findings.
