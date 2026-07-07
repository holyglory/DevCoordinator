# Design QA — DevOps Console

source visual truth: no image mockup exists for this app; the visual truth is
the UI contract in `docs/architecture.md` ("UI" section) plus the journey and
affordance requirements in `docs/journeys.md`, audited against
`skills/ui-implementation-audit/SKILL.md`'s ten interaction labels.

implementation screenshot paths (captured by the formal verifier against the
live deployment at `https://console.vr.ae` with real coordinator data — two
running managed servers, two routes, one public):

- Console desktop: `apps/DevOpsConsole/design-qa-console-desktop.png`
- Console mobile: `apps/DevOpsConsole/design-qa-console-mobile.png`
- Login desktop: `apps/DevOpsConsole/design-qa-login-desktop.png`
- Login mobile: `apps/DevOpsConsole/design-qa-login-mobile.png`

viewports: desktop 1440x900, mobile 390x844 (Chromium headless via
formal-web-ui-verification).

state: live production process (systemd `devops-console`, ports 443/80,
self-signed `*.vr.ae` cert pending the DNS-01 cert), real coordinator API on
127.0.0.1:29876, servers `demo-web` (python http.server via coordinator) and
`ws-echo-demo` (WebSocket echo via coordinator), routes `demo.vr.ae` (public)
and `ws-demo.vr.ae` (login-required), Docker honestly reported unavailable
(no docker CLI on this VPS).

commands (exact, reproducible):

- `node --test test/` — 59 pass / 0 fail (two consecutive runs by the
  stabilizer agent; re-run after the ws-echo port-pinning change: green).
- `python3 skills/codex-dev-coordinator/scripts/dev_coordinator.py server start --agent "$USER" --project "$PROJECT_ROOT" --name demo-web --cwd apps/DevOpsConsole/src/ui --cmd 'python3 -m http.server {port} --bind 127.0.0.1' --range 3000-3999` — real managed upstream.
- `curl -sk https://console.vr.ae/healthz` → `ok`; anon `https://console.vr.ae/` → 302 login; anon `https://whatever.vr.ae/` → 302 login (indistinguishable from a protected route); `https://vr.ae/` → 301 console; `http://console.vr.ae/some/path` → 301 https; foreign Host → 421.
- Live route lifecycle over the real domain: POST `/api/routes` (201,
  default `auth:"google"`), authed proxy 200, anon 302, PATCH to `public` →
  anon 200 without restart, PATCH without Origin header → 403.
- Live WebSocket: raw TLS client → `Host: ws-demo.vr.ae` upgrade with session
  cookie → 101 → masked `hello-hmr` frame echoed back; the same upgrade
  without a cookie → `HTTP/1.1 401 Unauthorized`.
- `node skills/formal-web-ui-verification/scripts/formal_web_ui_verify.mjs --url https://console.vr.ae/ --cookie "dc_session=<minted>" --ignore-https-errors --viewport mobile=390x844 --viewport desktop=1440x900 --screenshot-dir <scratch> --fail-on critical` — exit 0.
- Same command for `https://console.vr.ae/auth/login` without the cookie —
  exit 0, no findings.

incident causes found during this pass:

- `guard.wantsHtml` initially required an explicit `text/html` Accept header,
  so plain browser-shaped GETs (and curl smoke checks) got 401 JSON instead
  of the login redirect. Fixed to the contract's discriminator (JSON only for
  `/api/*` or an Accept naming `application/json`).
- `https.createServer` was configured with only `SNICallback`, so clients
  that send no SNI (curl to `https://127.0.0.1`, health probes) failed the
  TLS handshake. Fixed by seeding the default secure context from the cert
  manager and refreshing it on every hot-reload (`server.setSecureContext`).
- `routes.mjs` silently lowercased slugs before validation, so `MyApp`
  created `myapp` instead of being rejected; now invalid input is a 400.
- The coordinator's `api serve --port 0` readiness line reported the
  requested port (0) instead of the bound one; fixed in
  `dev_coordinator.py` (self-test re-run green) to unblock parallel-safe e2e.
- The formal verifier could not reach auth-gated pages or self-signed-TLS
  targets at all; extended the skill with `--cookie` and
  `--ignore-https-errors` plus must-catch self-test fixtures (a cookie-gated
  page whose anonymous variant still reports its critical, and a self-signed
  TLS fixture).

patches made in this pass (UI):

- Segmented-control labels ("Fixed port" / "Managed server") sit under their
  own transparent radio inputs for a whole-label click target; the verifier
  flagged them as occluded (warning). Annotated both spans with
  `data-ui-allow-overlap` and the reason, per the skill's per-selector
  allowance rule. Re-run: no findings.

interaction checklist (ten labels, all implemented in `src/ui/`):

- badge-detail: status dots/badges (route status, server status) open a
  click-positioned popover with health classification, pid, cmd, timestamps.
- row-hit-target: server and docker rows expand from a whole-row click
  target, not just the chevron.
- navigation-cursor: `cursor: pointer` on every interactive row/control;
  route URLs are real anchors.
- transient-disclosure: popovers close on Escape and outside click; renders
  are deferred while a popover is open.
- disclosure-scrollbar: log viewers are dedicated scroll containers with
  styled visible scrollbars, separate from the expand/collapse controls.
- icon-meaning: every icon is paired with text or `aria-label` + `title`
  (delete, copy, expand, status chips).
- stable-expansion-width: expanding a server row changes height only; widths
  are grid-fixed at both viewports.
- hover-copy: copy-URL buttons are visible on hover AND keyboard focus.
- status-summary: the sticky header is a one-line plain-language sentence
  ("All quiet: 2 of 2 dev servers running, 2 routes published (1 public),
  0 containers up, and TLS is valid for 89 more days.").
- message-metadata: log lines show timestamp/source as visually secondary
  metadata beside the message text.

visible scrollbar inventory (expected, per journeys.md): document vertical
scrollbar, log-viewer boxes, popover overflow. No horizontal document scroll
at either viewport (verified formally, scroll pass included).

findings: formal verifier — 0 critical / 0 warning / 0 info on the final run
for both targets and both viewports; earlier runs' findings are all resolved
or allowance-annotated as listed above.

final result: passed.

---

# Design QA pass 2 — 2026-07-06: paged UI, hamburger nav, CPU/mem history charts, lease management

source visual truth: unchanged (`docs/architecture.md` "UI" section +
`docs/journeys.md`, now covering five hash-routed pages, nav, J6 lease
management and J7 performance monitoring).

implementation screenshots (captured against the live deployment at
`https://console.vr.ae`, v1.1.0, real coordinator data — the console's own
managed server running plus three stopped demo servers, one lease):

- Servers page desktop (default): `design-qa-console-desktop.png` — tab nav
  with live counts, per-row CPU/mem numbers + sparkline, subdomain controls.
- Servers page mobile: `design-qa-console-mobile.png` — hamburger closed,
  labelled stacked cards.
- Mobile nav drawer open: `design-qa-nav-drawer-mobile.png` — active page
  highlighted, counts visible, `aria-expanded` verified true.
- Port leases page mobile: `design-qa-ports-mobile.png` — lease form
  (purpose / preferred port / TTL / project) + lease row with countdown and
  Release.
- Performance page desktop: `design-qa-performance-desktop.png` — per-entity
  CPU/memory chart cards (current + peak + window) and per-project usage
  bars with sparklines.
- CPU/mem history popover desktop: `design-qa-usage-popover-desktop.png` —
  charts match the row numbers; sampling-cadence and reset-on-restart note.

viewports: desktop 1440x900, mobile 390x844 (playwright-managed Chromium).

commands (exact, reproducible):

- `node --test test/` — 72 pass / 0 fail (includes new `unit.metrics.test.mjs`
  and e2e tests 11–12: lease lifecycle through the edge with Origin
  enforcement; metrics history fed by a real coordinator-managed server).
- `formal_web_ui_verify.mjs` against all five page hashes
  (`#/servers #/routes #/docker #/ports #/performance`) × both viewports
  with a minted `dc_session` cookie — exit 0, **no findings**.
- Playwright interaction script (19/19 pass): hamburger visible/opens/closes
  (tap, nav-click, Escape), `aria-expanded` toggles, page switch updates
  hash + `aria-current`, unknown hash falls back to Servers, usage popover
  opens with exactly two charts and closes on Escape, lease form present,
  no horizontal scroll at 390px, zero page errors.
- Live API round-trip: lease preferred port 3777 → 201 attributed
  `devops-console:ja@vr.ae` → release without Origin 403 → release 200
  `released` → re-release 400 `matching lease not found` → bad
  `?limit=0` 400.

incident causes found during this pass:

- The coordinator client's cached inventory (5s) could serve pre-mutation
  state immediately after a mutation (released lease still listed). Fixed:
  every non-GET coordinator call except log reads invalidates the
  inventory/servers caches (pinned by a validate.py needle).
- Coordinator 4xx errors surfaced as 502 Bad Gateway; now passed through as
  HTTP 400 with the coordinator's message verbatim.
- `app.js`/`app.css` are served with a 1h immutable cache, so a deploy could
  pair a fresh `index.html` with stale assets; asset URLs now carry
  `?v=<package version>`.
- Mobile `CPU / MEM` label butted against the value because the usage cell's
  flex layout absorbed the label's block flow; fixed with a flex gap.

findings: formal verifier — 0 critical / 0 warning / 0 info across all ten
target×viewport combinations; interaction script 19/19.

final result: passed.

---

# Design QA pass 3 — 2026-07-06: durable port pins (coordinator + console v1.2.0)

Live evidence after deploying durable per-repo port assignments:

- Ports page desktop: `design-qa-pinned-ports-desktop.png` — leases
  (temporary, countdown) and Pinned ports (permanent per server, live server
  status, confirmed Unassign) as separate cards; migration seeded
  devops-console:443, web-demo:3000, ws-echo-demo:3001; demo-web re-pinned to
  3002 after live verification.
- Ports page mobile: `design-qa-pinned-ports-mobile.png` — stacked labelled
  cards, no horizontal scroll.
- Servers page: `design-qa-servers-pin-marker-desktop.png` — dotted pin
  markers on every pinned port with an explanatory tooltip.

verification: live contract proof on production (web-demo restarted exactly
on pin 3000; demo-web refused 3000, landed and pinned 3002; foreign steal of
3000 refused naming the owner; pins survive stops), 14/14 playwright UI
checks, formal verifier 0 findings on #/ports + #/servers at both viewports,
coordinator self-test ok, console 73/73, full validate.py ok. The multi-agent
adversarial review (6 dimensions, 2-skeptic verification) found and led to
fixes for 8 defects before deploy — see DecisionHistory 2026-07-06.

final result: passed.

---

# Design QA pass 4 — 2026-07-07: Projects tree, repo grouping, hide/auto-reveal (v1.3.0)

screenshots (live at https://console.vr.ae):

- Projects tree desktop (new default page):
  `design-qa-projects-tree-desktop.png` — repo nodes with running counts,
  aggregate CPU/mem + sparkline, whole-project Start/Restart/Stop; kind-tagged
  member rows with per-item usage, status badges, per-item actions, and hide
  buttons on stopped rows.
- Projects tree mobile: `design-qa-projects-tree-mobile.png` — stacked rows,
  no horizontal scroll.

verification (all against production):

- 17/17 playwright checks, including the full auto-reveal contract executed
  live: hide stopped `web-demo` in the tree → reveal toggle shows/conceals it
  dimmed with an unhide control → `server start` via the coordinator CLI (as
  an agent would) → the row reappears without operator action within one
  poll and the pref key is removed server-side.
- Prefs deltas verified live: two sequential hides MERGE (no lost update),
  unhide removes exactly the named keys, on-disk `state/ui-prefs.json`
  matches; `/api/projects/action` with an untracked path → 404.
- Formal verifier: 0 findings on `#/projects` at 1440×900 and 390×844.
- Suites: console 79/79 twice (new: unit.prefs durability-from-disk, e2e 14
  delta semantics, e2e 15 project runtime lifecycle), coordinator self-test
  ok, full validate.py ok.
- Deployment incident found and fixed during this pass: earlier deploys ran
  `pkill -f 'dev_coordinator.py api serve'` whose pattern matched the
  deploying shell itself, killing it before `systemctl restart` ran — the
  live console had silently stayed on v1.1.0 while serving newer static
  assets. The coordinator runs inside the unit cgroup, so a plain
  `systemctl restart devops-console` replaces both processes; deploys must
  not pkill by that pattern.

adversarial review: 5 dimensions, 21 confirmed findings, all fixed or
honestly documented (one filed as follow-up: display-vs-runtime project
membership unification) — see DecisionHistory 2026-07-07.

final result: passed.

---

# Design QA pass 5 — 2026-07-07: Projects tree alignment + dense list layout (v1.3.3)

User-reported: ragged badge/button columns on desktop; per-character word
wrapping at tablet widths (720–1099px fell between the desktop grid and the
719px mobile rules); sparse stacked cards on phones.

Changes: one shared fixed-column grid for the project header AND item rows
(kind 84px | name+detail flexible with ellipsis | usage 190px right-aligned |
status 118px | actions 248px right-aligned) with an invisible ghost slot
where the hide icon would sit, so action groups are equal width on every
row; URL/image detail merged into the name cell and truncated, never
wrapped; below 1100px the table becomes a dense wrapping flex LIST (tag,
name, usage, status, actions — no per-cell stacking, no field labels), and
below 600px a fixed two-line form (tag + name + status over usage + actions,
sparklines dropped, numbers kept).

evidence: `design-qa-projects-tree-desktop.png` (aligned columns),
`design-qa-projects-tree-tablet.png` (900px list, no character wrap),
`design-qa-projects-tree-mobile.png` (390px two-line dense list).
verification: 15/15 measured layout checks live (status badges share one x
coordinate; action and usage columns share one right edge; every name is a
single 16px line at all three widths; rows 37–45px desktop/tablet, ~73px
phone; zero horizontal scroll; zero page errors), formal verifier 0 findings
at 1440/900/390, console suite 79/79, validate.py ok.

final result: passed.
