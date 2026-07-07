# DevOps Console — User Journeys

Journey documentation for the control panel at `https://console.vr.ae/`
(`src/ui/`). Structured after
`skills/user-journey-docs-audit/references/journey_doc_template.md` so it can
feed `user-journey-docs-audit` and `ui-implementation-audit` directly.

## App Idea

- Product promise: **One private page where the VPS operator sees every dev
  server, container, port lease and public subdomain on `vr.ae`, and can
  expose, restart, inspect or retract any of them in a couple of clicks.**
- Primary users: the machine's operator (owner of the allowlisted Google
  accounts). Single-tenant; no anonymous or multi-role UI.
- Primary value: replaces SSH + `dev_coordinator.py` CLI + editing proxy
  config with a phone-friendly control panel; makes "share this dev build at
  a URL" a 15-second task instead of a config change.
- Non-goals: multi-user roles/permissions, editing coordinator state files,
  arbitrary shell access, container creation, certificate issuance (certs are
  provisioned out-of-band and only *observed* here), durable metrics storage
  (CPU/memory history is in-process only and resets with the console — the
  UI says so).
- Main devices/contexts: desktop browser (~1440px) at a workstation during
  active development; phone (~390px) for quick "is it up / flip access /
  restart it" checks away from the desk. Dark environments — dark theme only.

## User Contexts

| User type | Expertise | Frequency | Environment | Stress/urgency | Mistake cost |
| --- | --- | --- | --- | --- | --- |
| VPS operator (desktop) | Expert dev/ops; knows ports, Docker, OIDC | Many times/day while developing | Workstation, big screen, keyboard | Low–medium | Medium: wrong toggle exposes a dev app publicly; deleting a route breaks a shared link |
| VPS operator (phone) | Same person, reduced attention | Few times/week | Mobile, one-handed, flaky network | Medium–high (usually reacting to "the link you sent me is down") | Same as above, plus mistaps — destructive actions need confirmation |
| Invited viewer (client/teammate) | Non-technical | Rare | Opens a shared `<slug>.vr.ae` link | Low | None — they never see the console UI; they only benefit from routes being correct |

The invited viewer never uses this page (unknown/protected slugs bounce them
to Google login or a styled 404); they are listed because their experience is
the *output* of journeys 2 and 4.

## Journey Inventory

Prioritized: top rows are the most frequent and most important.

| Journey | User | Frequency | Importance | Risk if broken | Entry point | Success state |
| --- | --- | ---: | ---: | ---: | --- | --- |
| J1 Status triage: "is everything up?" | Operator | Daily+ | 1 | High | Open `console.vr.ae` | One glance answers healthy/not; problems name themselves |
| J2 Expose a dev server at a subdomain | Operator | Weekly+ | 2 | High | Routes form | `https://<slug>.vr.ae` serves the app with intended access |
| J3 Fix a broken subdomain / server (logs, restart) | Operator | Weekly | 3 | High | Red status dot / unhealthy badge | Route resolves again; server healthy |
| J4 Flip route access (public ⇄ login) | Operator | Weekly | 4 | Medium (accidental public exposure) | Route row toggle | Access changed, confirmed for the public direction |
| J5 Manage Docker service containers | Operator | Monthly | 5 | Medium | Docker page | Container started/stopped; logs inspected |
| J6 Housekeeping: leases, TLS runway | Operator | Monthly | 6 | Low–medium | Port leases page, TLS chip | Stale leases released; new port leased without collisions; TLS renewal not overdue |
| J7 Watch performance: who is eating CPU/RAM? | Operator | Weekly | 7 | Low–medium | CPU/mem cells on rows; Performance page | Hog identified with numbers + history; act via restart/stop |
| J8 Run a whole project; keep the console tidy | Operator | Daily | 2 | Medium | Projects page (default) | A repo's full stack up/down in one action; idle noise hidden but self-revealing |

## Journey Detail

### J1 — Status triage: "is everything up?"

- User: operator (desktop or phone; phone is the stress case).
- Goal: within ~5 seconds, know whether anything needs action, and what.
- Trigger: habitual check; a message that "the link is down"; after a deploy
  or reboot.
- Preconditions: valid allowlisted session (the page never renders without
  one; an expired session reloads into Google login).
- Entry point: `https://console.vr.ae/` — the sticky status summary bar,
  present on every page.
- Route/screen sequence: hash-routed pages (`#/servers` default, `#/routes`,
  `#/docker`, `#/ports`, `#/performance`) behind one sticky header (summary
  bar + section nav with live counts; hamburger drawer on phones); summary
  bar → whichever page the summary implicates.
- Primary decisions: *act now, drill in, or close the tab*; if acting —
  *which section and which row*.
- Required information per step: one plain-language summary sentence
  (coordinator health, servers running/total, route count + public count,
  containers up, TLS runway); per-section counts; per-row status colors with
  text labels.
- Warning/flag conditions: coordinator unreachable (degrades servers /
  docker / leases / usage sections but must NOT blank the page); any server
  `unhealthy` / `wrong-listener`; any route not resolving; TLS < 14 days
  (amber) or expired (red); `url_is_current === false` on a server; overview
  fetch failing (banner + "data is stale as of HH:MM:SS" note).
- Primary actions: read; click a chip/badge/dot for its detail popover.
- Secondary/rare actions: retry from the error banner; sign out.
- Conditional or rare details: coordinator autostart state, last error and
  last-OK time — only inside the coordinator chip popover; TLS
  subject/issuer/exact expiry — only inside the TLS chip popover.
- Interaction targets and feedback: chips, badges and dots are click targets
  that open popovers (hover restyle + `aria-haspopup`/`aria-expanded`);
  nothing important is hover-only.
- Message metadata relevance: "updated HH:MM:SS" is passive metadata — dim,
  unselectable, never part of the decision sentence.
- Unresolved UI assumptions: none — single-operator product; the summary
  sentence wording is implementation-defined as long as it is plain language,
  not raw counts.
- Empty/loading/error/permission states: first paint shows skeleton rows in
  every section; failed first load replaces skeletons with a one-line error
  and the banner's Retry; 401 anywhere reloads into login.
- Recovery and undo: banner Retry refetches; coordinator degraded panels have
  their own "Try again".
- Device/context constraints: summary must be readable on 390px without
  horizontal document scroll; the sentence may wrap but stays a single
  sentence.
- Accessibility expectations: summary is a `<p>` read in DOM order; status is
  never conveyed by color alone (every dot/badge carries a text label);
  focus-visible outlines on every control.
- Acceptance criteria:
  - With everything healthy the bar reads a single "All quiet: …" sentence
    naming servers running, routes (public count), containers, TLS days.
  - Kill the coordinator: within one poll (≤6s + timeout) the bar switches to
    an "Attention…" sentence, the four coordinator-fed sections show the
    degraded panel with the coordinator's error verbatim, and Routes still
    renders.
  - Set system TLS cert to expire in <14 days: chip turns amber and the
    sentence mentions renewal.
- Analytics/support signals: none (single user); server-side logs suffice.

### J2 — Expose a dev server at a subdomain

- User: operator, almost always desktop.
- Goal: make `https://<slug>.vr.ae` serve a local dev server, with the right
  access mode, and hand the URL to someone.
- Trigger: a dev server just started (via coordinator or manually on a fixed
  port) and needs a shareable URL.
- Preconditions: session; for the "managed server" target, coordinator
  reachable with at least one server registered; for the "container" target,
  docker reachable with at least one running container publishing a
  loopback-reachable TCP port.
- Entry point: Routes section create form (always visible at the top of the
  section — it is the section's primary data-entry surface).
- Route/screen sequence: form → new row appears in the routes table →
  (optionally) click the row's URL to verify → copy URL.
- Primary decisions: slug name; target kind (fixed port vs. coordinator
  server vs. docker container — server-linked routes follow port changes
  across restarts, container routes follow the published host port across
  restarts, fixed ports do not); access mode (default **login required**;
  public is an explicit, confirmed choice).
- Required information per step: live slug preview (`https://<slug>.vr.ae`)
  with inline validity/reserved/duplicate feedback *before* submit; the
  server dropdown must show name, project, port and status so the right
  instance is pickable; the container dropdown shows one option per
  (container, published port) pair with project and host port; the access
  switch must state its current meaning in words ("Google sign-in required" /
  "Public — no sign-in").
- Warning/flag conditions: invalid/reserved/duplicate slug (inline, live);
  choosing public (confirm dialog spelling out "anyone on the internet");
  coordinator down (server/container dropdowns disabled with reason;
  fixed-port routes still creatable); docker down (container dropdown
  disabled with reason); server-side 400/409 (verbatim message inline +
  banner).
- Primary actions: fill form, submit, copy resulting URL.
- Secondary/rare actions: add an optional human title; pick a stopped server
  (options listed but disabled — routes point at running things).
- Conditional or rare details: none at creation time; everything else lives
  on the row after creation.
- Interaction targets and feedback: submit disables and reads "Creating…"
  while in flight; success clears slug/title and announces via the live
  region; the new row appears on the immediate post-mutation refetch.
- Message metadata relevance: `createdAt`/`updatedAt` are popover detail,
  never table columns.
- Unresolved UI assumptions: none.
- Empty/loading/error/permission states: empty routes table shows one-line
  guidance pointing at the form; failed create keeps every field intact.
- Recovery and undo: undo = delete the route (J4's confirm applies); a wrong
  target is fixed by delete + recreate (PATCH exists in the API; the UI keeps
  create simple by design).
- Device/context constraints: form fields stack on 390px; switching target
  kind must not shift layout (both inputs occupy the same slot).
- Accessibility expectations: every field labelled; preview wired via
  `aria-describedby` + `aria-live`; the access control is a real
  `role="switch"` with words, not an unlabeled toggle.
- Acceptance criteria:
  - Typing `My_App` shows the invalid-character message before submit;
    typing `api` shows "reserved"; an existing slug shows "already routed".
  - Creating `demo` → port 3000 yields a row whose link opens
    `https://demo.vr.ae` and whose copy button puts exactly that URL on the
    clipboard.
  - Creating with "Public" requires an explicit confirm naming the host.
  - A 409 from the API surfaces the server's message verbatim.

### J3 — Fix a broken subdomain / server

- User: operator; desktop preferred, phone must work.
- Goal: from "this URL is down" to "serving again" without SSH.
- Trigger: red `down` dot on a route; `unhealthy` badge; someone reports a
  dead link.
- Preconditions: session; coordinator reachable for actions (stop/restart);
  logs come through the coordinator too.
- Entry point: the failing route's status dot, or the Servers section badge.
- Route/screen sequence: route dot popover (names the reason: `server
  stopped` / `server not found` / nothing on fixed port) → Servers section →
  expand the server row (whole row is the click target) → read log tail →
  Restart (or Stop) → watch badge return to `running` on the next poll →
  re-check the route dot.
- Primary decisions: *is it the server, the route target, or the machine?*;
  restart vs. stop vs. repoint the route; whether logs show a crash loop
  (restart won't help — needs a code fix).
- Required information per step: route `resolved` reason verbatim; server
  health classification (`healthy/starting/unhealthy/wrong-listener/
  stopped`), pid, port, exact command, stop reason and timestamps (badge
  popover); last ~200 log lines, monospace, newest at the bottom.
- Warning/flag conditions: `wrong-listener` / `url_is_current === false`
  (another process owns the port — restart may bind elsewhere);
  `missing_command` (registered without a command — Restart is disabled with
  the reason in its tooltip); action 400s from the coordinator (verbatim in
  banner, retryable).
- Primary actions: expand row; refresh logs; Restart.
- Secondary/rare actions: Stop (leaving it down deliberately); deleting the
  route instead; consulting the docker section when the failure is a
  dependency (database container down).
- Conditional or rare details: full `cwd`, `log_path`, health-check detail —
  in the expanded panel / badge popover only.
- Interaction targets and feedback: whole row toggles expansion
  (`cursor: pointer`), chevron mirrors state (`aria-expanded`); buttons show
  busy text ("Working…") and disable during the action; logs auto-fetch on
  first expand and keep scroll position across the 6s refresh.
- Message metadata relevance: leading timestamps in log lines are dimmed
  secondary metadata; the log *message* is the content. "fetched HH:MM:SS"
  next to the Refresh button is passive (unselectable).
- Unresolved UI assumptions: log viewer is pull-based (Refresh), not
  streaming — acceptable for tail-style triage; revisit only if the operator
  asks for follow mode.
- Empty/loading/error/permission states: "Loading log…", "Log is empty.",
  and a verbatim error line inside the log box; restart failure leaves the
  row intact with the banner explaining why.
- Recovery and undo: stop → start is the undo for restart-gone-wrong;
  coordinator never kills foreign-project PIDs (safety is server-side, the
  UI surfaces the resulting `wrong-listener`/stale states honestly).
- Device/context constraints: log box is height-capped with its own visible
  scrollbar on both desktop and phone; expansion never changes the card's
  width (no layout jump, no horizontal document scroll).
- Accessibility expectations: chevron is a real button with
  `aria-expanded`/`aria-controls`; log region is keyboard-focusable
  (`tabindex=0`, `role=region`, labelled).
- Acceptance criteria:
  - Stopping a route's linked server flips the route dot to `down` within
    one poll; the dot popover says `server stopped` and points at Servers.
  - Restart on a healthy fixture server returns the badge to `running` and
    the route dot to `live` without a page reload.
  - A server registered without `cmd` shows Restart disabled with the
    explanation in its tooltip/`title`.
- Analytics/support signals: coordinator history records every action with
  `agent: devops-console:<email>`.

### J4 — Flip route access (public ⇄ login)

- User: operator, frequently on phone ("make it public for the client call,
  lock it after").
- Goal: change who can open `https://<slug>.vr.ae` — allowlisted Google
  accounts vs. anyone.
- Trigger: a demo/call starts or ends; a link needs sharing with someone not
  on the allowlist.
- Preconditions: session; route exists. Coordinator is NOT required.
- Entry point: the access switch on the route row.
- Route/screen sequence: single interaction on the row; confirm dialog only
  when going public.
- Primary decisions: is exposing this app to the whole internet acceptable
  right now?
- Required information per step: current mode in words on the switch
  ("Public"/"Login"), the exact host in the confirm text.
- Warning/flag conditions: going public always confirms with plain-language
  consequences; going private never needs a confirm (safe direction).
- Primary actions: toggle; also copy URL to send (hover/focus-revealed copy
  button next to the link).
- Secondary/rare actions: delete route (trash icon, confirmed, names the
  host, states that the dev server itself keeps running).
- Conditional or rare details: none.
- Interaction targets and feedback: switch is `role="switch"` with
  `aria-checked`; busy state shows "Saving…" and disables; optimistic-then-
  refetch — failure reverts visually on the refetch and explains in the
  banner.
- Message metadata relevance: n/a.
- Unresolved UI assumptions: none.
- Empty/loading/error/permission states: PATCH/DELETE failures show the
  server's message verbatim with Retry.
- Recovery and undo: the toggle is its own undo; deleted routes are recreated
  in seconds via J2 (state is only slug+target+mode).
- Device/context constraints: switch and delete are comfortably tappable on
  390px (coarse-pointer sizing bump); confirm dialogs are native and
  therefore phone-safe.
- Accessibility expectations: switch announces host and current mode via
  `aria-label`; delete is icon-only but carries `aria-label` + `title`.
- Acceptance criteria:
  - Making a route public requires a confirm that names the host; cancel
    changes nothing.
  - After toggling, an incognito request to the slug host redirects to login
    (private) or serves the app (public) — verified end-to-end in tests.
  - Delete asks for confirmation and the row disappears after the refetch.

### J5 — Manage Docker service containers

- User: operator, desktop mostly.
- Goal: keep service dependencies (databases, caches) of dev servers running;
  check why one is misbehaving.
- Trigger: a dev server fails because its database is down; routine check.
- Preconditions: session; coordinator reachable; Docker available on host.
- Entry point: Docker section.
- Route/screen sequence: scan rows (running first) → row click opens the log
  panel → start/stop/restart as needed.
- Primary decisions: which container is the broken dependency; restart vs.
  cold start; is it safe to stop (is anything using it)?
- Required information per step: name, image, raw status string, published
  ports; logs on demand; CPU/mem sample in the detail popover when stats
  exist.
- Warning/flag conditions: stopping anything confirms (dependencies may
  break — Postgres especially; destructive DB operations additionally go
  through the `$postgres-docker-backup` path *outside* this UI, per repo
  policy); Docker daemon unavailable shows the error inline, not a blank
  section.
- Primary actions: logs, restart, start.
- Secondary/rare actions: stop; reading compose/project metadata in the
  popover.
- Conditional or rare details: stats, labels, metadata source — popover only.
- Interaction targets and feedback: same row/chevron/busy conventions as
  Servers; the status dot carries hidden text plus a visible "up/stopped"
  word by the name.
- Message metadata relevance: same log-timestamp rule as J3.
- Unresolved UI assumptions: no container creation/compose-up in the UI —
  deliberate scope cut (compose belongs to the repo's runtime declarations).
- Empty/loading/error/permission states: "No containers found" guidance;
  docker errors verbatim.
- Recovery and undo: start undoes stop; coordinator records every action.
- Device/context constraints: image/ports strings wrap inside their cells on
  phone; no horizontal document scroll.
- Accessibility expectations: as Servers.
- Acceptance criteria: stopping a running fixture container asks to confirm,
  the row's actions swap to Start after the refetch, and its logs remain
  viewable.

### J6 — Housekeeping: leases, TLS runway

- User: operator, desktop, low frequency.
- Goal: spot leaked port leases, release them, reserve a port for upcoming
  work, and keep TLS renewal on track.
- Trigger: monthly hygiene; port exhaustion suspicion ("no free port in
  3000-3999"); about to start a tool that needs a stable port.
- Preconditions: session; coordinator reachable (the page degrades
  gracefully otherwise).
- Entry point: Port leases page (`#/ports`); TLS chip in the summary bar.
- Primary decisions: is a lease legitimate (linked to a live server) or
  leaked → release it? Which port/TTL to lease for a new tool? Is TLS
  renewal on track?
- Required information per step: per lease — port, purpose
  (`server:<name>`/manual), project, live expiry countdown ("never" is
  explicit); lease form — preferred port validity, TTL options in plain
  words; TLS — days left, exact expiry in the chip popover.
- Warning/flag conditions: countdown under 15 minutes turns amber, expired
  turns red (the coordinator prunes lazily — the UI mirrors, it does not
  act); TLS thresholds as J1.
- Primary actions: lease a port (purpose, optional preferred port, TTL,
  optional project path); release a lease (confirmed — the confirm says the
  process keeps running and only the reservation goes away).
- Secondary/rare actions: cross-check a lease's project on the Servers page;
  TLS renewal is the documented certbot runbook, not a UI action.
- Conditional or rare details: lease ids, exact ISO expiry, leasing agent —
  title attributes.
- Message metadata relevance: countdowns are content (they drive the
  decision); "never expires" is dim passive metadata.
- Unresolved UI assumptions: coordinator-attributed leases created here carry
  `agent: devops-console:<email>` — attribution is the console user, not a
  repo agent.
- Failure/recovery: coordinator errors ("no free port available in …",
  "matching lease not found") surface verbatim in the form error/banner.
- Device/context constraints: form stacks at 390px; rows become labelled
  cards.
- Accessibility expectations: release buttons carry explicit per-port labels;
  countdown color changes are paired with the ticking text itself.
- Acceptance criteria: leasing with a preferred port yields exactly that port
  (or a verbatim coordinator error); the new lease appears without a manual
  reload; releasing it removes the row after the confirm; a lease with a TTL
  shows a ticking countdown that turns amber under 15 minutes; a no-TTL
  lease reads "never expires".

### J7 — Watch performance: who is eating CPU/RAM?

- User: operator; desktop when investigating, phone when reacting to "the
  box feels slow".
- Goal: see, in numbers and shape-over-time, what every running dev server
  and container costs, and identify the hog worth restarting/stopping.
- Trigger: machine feels slow; after starting something heavy; idle
  curiosity during J1 triage.
- Preconditions: session; coordinator reachable; the console has been up
  long enough to have sampled (charts state that history is in-process and
  resets on console restart).
- Entry point: CPU/mem numbers + sparkline on every Servers/Docker row; the
  Performance page (`#/performance`) for the full picture.
- Route/screen sequence: row sparkline → click → popover with full CPU and
  memory charts → (optionally) Performance page for every entity side by
  side plus per-project usage bars.
- Primary decisions: is the load real and sustained (chart shape) or a
  blip? Which entity/project owns it? Restart, stop, or leave it?
- Required information per step: per row — live CPU % and memory as numbers
  (never color-only or chart-only); per chart — current value, peak value,
  covered time window; per project — CPU %, memory, entity counts.
- Warning/flag conditions: sampling failures surface as a visible note with
  the coordinator's error ("charts show the last collected history") — stale
  charts must not masquerade as live.
- Primary actions: open a row's history popover; open the Performance page;
  act via the row's stop/restart controls (J3/J5).
- Secondary/rare actions: tune `METRICS_INTERVAL_MS`; correlate with
  project usage bars.
- Conditional or rare details: sampling cadence and reset-on-restart note —
  in the popover hint; stopped entities keep their recent history visible
  (dimmed, "not running — recent history") until it ages out.
- Message metadata relevance: current numbers are content; "peak … · last
  N min" and the sampling note are passive metadata.
- Unresolved UI assumptions: CPU sparkline/chart normalizes to the observed
  peak (shape-reading aid), not to machine capacity — the numbers beside it
  carry the magnitude; accepted because dev-server CPU rarely maps to whole
  cores.
- Failure/recovery: metrics fetch failures leave the last charts (they go
  stale quietly — the overview banner owns hard failures); a coordinator
  outage stops sampling but keeps history.
- Device/context constraints: sparklines have fixed 92px width in the row
  (no layout shift as data accrues); charts scale to card width; the
  Performance grid is single-column on phones.
- Accessibility expectations: sparklines and charts are `aria-hidden`
  decoration; the accessible content is the numeric text (row numbers, chart
  "current/peak" labels); the sparkline button has a full aria-label naming
  CPU and memory values.
- Acceptance criteria: a running coordinator server shows non-zero memory
  and a growing sparkline within ~30s of starting; clicking it opens CPU +
  Memory charts whose current values match the row numbers; the Performance
  page lists every sampled running server/container as a chart card sorted
  running-first then by CPU; stopping a server dims its card rather than
  deleting history instantly.

### J8 — Run a whole project; keep the console tidy

- User: operator; the default landing page on every device.
- Goal: see every repo with everything that belongs to it (web servers,
  databases, containers), act on single items or the whole repo, and keep
  idle clutter out of sight without losing it.
- Trigger: starting a day's work on a repo; "bring the whole stack up/down";
  the lists have accumulated stopped one-offs.
- Preconditions: session; coordinator reachable (page degrades otherwise).
- Entry point: `#/projects` (default page).
- Route/screen sequence: tree of repos, each node: header (name, n of m
  running, project CPU/mem numbers + sparkline, Start/Restart/Stop for the
  whole project, collapse) → children (kind-tagged server / database /
  container rows with status, CPU/mem + sparkline, per-item
  Start/Stop/Restart, hide).
- Primary decisions: act on one item or the whole repo; hide an idle item or
  project; drill into Servers/Docker pages for logs and details.
- Required information per step: grouping must be the coordinator's own
  attribution (`project_usage` membership), not name guessing; per-node
  running counts; project aggregate CPU/mem next to per-item numbers.
- Warning/flag conditions: project actions disabled (with reason) for groups
  without a repo path; coordinator errors from `project start` (missing
  runtime declaration, compose policy) surface verbatim.
- Primary actions: whole-project start/restart/stop (stop/restart confirmed —
  the confirm names the blast radius); per-item start/stop/restart; hide.
- Secondary/rare actions: collapse a project node; reveal hidden items;
  unhide manually.
- Hiding contract (also on Servers/Docker pages): only non-running items and
  idle projects can be hidden; hidden state persists server-side across
  devices; **anything the coordinator reports as running is auto-unhidden on
  the next poll** — an agent starting a hidden server makes it reappear
  without operator action; a "Show N hidden items" toggle reveals hidden rows
  dimmed with an unhide control, so nothing is ever unrecoverable.
- Message metadata relevance: "n of m running" and pin/port details are
  content; sampling notes stay passive.
- Failure/recovery: hide/unhide failures show the banner with Retry; prefs
  unreachable at boot degrades to session-only hiding.
- Device/context constraints: tree indents collapse on phones; project
  actions wrap under the header; no horizontal scroll at 390px.
- Accessibility expectations: hide/unhide buttons carry explicit labels
  ("Hide X until it runs again"); collapse chevrons are buttons with
  aria-expanded; kind tags are text, not color-only.
- Acceptance criteria: a repo with a declared runtime starts fully from the
  project Start button and every member shows running with live CPU/mem; a
  hidden stopped server reappears automatically after `server start` from any
  agent; hiding is reflected on both the Projects and Servers pages; the
  reveal toggle shows hidden rows dimmed with working unhide buttons.

## Journey Decision Model

| Surface | Primary user goal | Primary decision | Required facts | Warning/flag conditions | Frequent actions | Secondary/rare actions | Unresolved assumptions |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Status summary bar | Know instantly if action is needed | Act, drill in, or leave | One-sentence health summary; coordinator/TLS/user chips | Coordinator down; TLS <14d/expired; stale data note | Read; open chip popovers | Sign out | None |
| Section nav (tabs / hamburger drawer) | Reach the right page fast | Which page answers my question | Page names + live counts; active page marked | None | Switch page | Open/close drawer on phone | Counts hidden while coordinator down (no number is honest) |
| Routes section | Publish and control subdomain exposure | Create/keep/repoint/expose/retract a route | Slug preview validity; target (port or server+project); resolved state + reason; access mode in words | Route not resolving; going public (confirm); reserved/duplicate slug | Create route; copy URL; toggle access | Delete route; add title | None |
| Servers section | Keep dev servers healthy | Restart, stop, or dig into logs | Name, project, port, health classification, pid, cmd, timestamps, log tail | unhealthy / wrong-listener / stale URL flag; missing_command disables restart | Expand row; refresh logs; restart | Stop; read popover forensics | Pull-based logs (no streaming) |
| Docker section | Keep service dependencies alive | Start/stop/restart a container | Name, image, status string, ports, logs | Stop confirmations; docker daemon unavailable | Open logs; restart | Stop; read stats popover | No compose-up in UI (by design) |
| Port leases page | Keep the port pool clean | Lease, release, or leave a lease | Port, purpose, project, countdown; lease-form validity | Countdown amber <15m; expired; "no free port" errors verbatim | Lease a port; release (confirmed) | Pick preferred port/TTL/project | Lease attribution is the console user |
| Pinned ports card | Know each server's permanent port | Keep or unassign a pin | Port, server name, project, live server status ("not registered" = record pruned, pin still holds) | Unassign confirm explains the port may change on next start | Read; unassign (confirmed) | Cross-check on Servers page (dotted pin marker on the port) | Pins are coordinator-wide policy, not console state |
| Servers/Docker usage cells | Spot a hog in place | Is this row's load normal? | Live CPU % + memory numbers; sparkline shape | Sampling failure note | Click for history charts | — | CPU normalized to observed peak, numbers absolute |
| Performance page | Find resource hogs with history | Which entity/project to act on | Per-entity CPU/mem charts (current, peak, window); per-project bars | Sampler error note; stale (not running) cards dimmed | Read; navigate to the row to act | Cross-reference project bars | History is in-process, resets with console |

## Information Relevance Inventory

| Journey | Surface | Item | Relevance | Why it matters | Condition/frequency | Expected access |
| --- | --- | --- | --- | --- | --- | --- |
| J1 | Summary bar | Plain-language health sentence | critical-always | The whole triage decision | Always | Inline |
| J1 | Summary bar | Coordinator ok/degraded chip | critical-always | Gates every mutation | Always | Inline; detail in click popover |
| J1 | Summary bar | TLS days remaining | primary-frequent | Expiry breaks every host at once | Always; amber <14d | Inline chip; exact dates in popover |
| J1 | Summary bar | User email + sign out | secondary-occasional | Session sanity | Always visible, rarely used | Inline chip |
| J1 | Summary bar | "updated HH:MM:SS" | debug | Staleness check | Always | Passive metadata (dim, unselectable) |
| J2 | Routes form | Slug preview + validity | critical-always (during entry) | Prevents bad submits | While typing | Inline, live |
| J2 | Routes form | Access mode wording | critical-always | Security-relevant default | Always | Inline on the switch |
| J2/J4 | Route row | https URL | critical-always | The deliverable | Always | Inline link + hover/focus copy |
| J2/J3 | Route row | Resolved state + reason | primary-frequent | "Will the link work?" | Always; reason on failure | Dot inline; reason in click popover |
| J2 | Route row | Target description | primary-frequent | What the URL serves | Always | Inline |
| J2 | Route row | title, createdAt/updatedAt | rare-under-5-percent | Bookkeeping | On demand | Title inline dim; dates popover |
| J3 | Server row | Health classification | critical-always | Restart decision | Always | Badge inline; forensics in popover |
| J3 | Server row | name/project/port | primary-frequent | Identify the row | Always | Inline |
| J3 | Server panel | Log tail | primary-frequent (once expanded) | Crash diagnosis | On expand | Row expansion, own scrollbar |
| J3 | Server popover | pid, cmd, cwd, timestamps, health-check detail | secondary-occasional | Forensics | On demand | Click popover / expanded panel |
| J3 | Server row | url_is_current warning | conditional | Stale-port trap | Only when false | Inline icon + text explanation |
| J3 | Server row | missing_command restart block | conditional | Explains disabled button | Only when true | Disabled control + title reason |
| J5 | Docker row | name/image/status/ports | primary-frequent | Pick the dependency | Always | Inline |
| J5 | Docker popover | stats, labels, metadata source | expert-only | Deep checks | On demand | Click popover |
| J6 | Lease row | port/purpose/project/countdown | secondary-occasional | Leak spotting | Always on page | Inline row + release action |
| J6 | Lease form | preferred-port validity, TTL wording | critical-always (during entry) | Prevents bad leases | While leasing | Inline, live |
| J7 | Server/Docker row | live CPU % + memory numbers | primary-frequent | Hog spotting without leaving the row | While running | Inline numbers + sparkline |
| J7 | Usage popover / Performance page | CPU & memory history charts | secondary-occasional | Sustained-vs-blip judgment | On demand | Click popover; Performance page |
| J7 | Usage row | cpu/mem per project | secondary-occasional | Hog spotting | Always on Performance page | Inline bars + numbers |
| All | Error banner | Server error message verbatim | conditional | Exact failure text is the fix hint | On any failed fetch | Banner, dismissible, with Retry |

## Interaction And Metadata Model

Binding affordance rules — these are the ten `ui-implementation-audit`
labels, made concrete for this app:

| Label | Rule in this app |
| --- | --- |
| badge-detail | Every status signal (coordinator chip, TLS chip, route dot, server badge, container dot) is a real `<button>` that opens a **click** popover with the underlying facts (classification, pid, cmd, timestamps, reasons). Hover only restyles; no information is hover-only. Triggers carry `aria-haspopup="dialog"` and live `aria-expanded`. |
| row-hit-target | Server and container rows expand from a click anywhere on the row (`cursor: pointer` on the whole row); inner buttons/links stop the row action. The chevron is the keyboard-accessible equivalent, never the only target. |
| navigation-cursor | The only true navigations are route URLs (new tab, `title` names the destination) and Sign out; both are real anchors with pointer cursor and predictable destinations. Nothing else fakes navigation. |
| transient-disclosure | One popover exists at a time; it closes on Escape, outside pointer-down, scroll, resize, or clicking its trigger/close button, and focus returns to the trigger. Row expansions are persistent-until-toggled by design (log reading takes time) — that lifecycle is intentional, not an oversight. |
| disclosure-scrollbar | Log boxes and the popover own visible, styled scrollbars (`scrollbar-width: thin` + WebKit styling, `scrollbar-gutter: stable`). Expand chevrons sit on the row's left edge — never adjacent to a scrollbar. |
| icon-meaning | Icon-only controls (copy, delete, dismiss, chevron, warning flag) always pair the icon with `aria-label` **and** `title`; status icons additionally carry visible text ("live/down", "running/stopped", badge words). No bare mystery glyphs. |
| stable-expansion-width | The popover has a fixed width (`min(360px, 100vw − 24px)`) regardless of content; expanded panels span the full card width so expanding/collapsing never shifts horizontal layout; switching the create-form target kind swaps inputs inside one fixed slot. |
| hover-copy | URL copy buttons occupy a permanent layout slot and fade in on row hover **and** on any focus within the row (`:focus-within`), so the pointer never chases a moving control; on touch (`hover: none`) they are always visible. Feedback: icon swaps to a check + `aria-live` announcement. |
| status-summary | The summary bar leads with one plain-language sentence ("All quiet: …" / "Attention — …") that interprets the counts; raw numbers appear as section count pills, never as the only summary. Popovers avoid repeating badge text — they add facts. |
| message-metadata | Log lines render a leading timestamp/bracket prefix as dimmed secondary metadata with the message as primary content; UI chrome metadata ("updated 12:00:05", "fetched 12:00:05", "never expires", popover field labels) is dim and `user-select: none` so copying content never drags chrome along. Log text itself stays fully selectable. |

## UI Handoff Constraints

| Surface | Decisions the UI must support | Required evidence for UI audit | States to verify | Mockups/screenshots/assets | Unconfirmed assumptions |
| --- | --- | --- | --- | --- | --- |
| Summary bar | Triage (J1) | Desktop + 390px screenshots healthy vs. coordinator-down vs. TLS-warning | loading, healthy, degraded, stale-data | none — this doc + contract are the target | None |
| Routes | J2, J4 | Screenshots: empty state, populated table, create-form validation error, public-confirm flow; clipboard check | empty, invalid slug, in-flight, 409 error, public confirm, delete confirm, unresolved dot | none | None |
| Servers | J3 | Screenshots: collapsed list, expanded row with logs, badge popover, busy buttons; scroll-position retention across a poll | skeleton, empty, degraded, expanded+logs, log error, busy, missing_command-disabled | none | Pull-based logs accepted |
| Docker | J5 | Screenshots: list, log panel, unavailable-daemon state | empty, unavailable, busy, stop-confirm | none | No compose-up in UI |
| Port leases | J6 | Screenshots: form + populated table incl. countdown warning; lease→release round trip | empty, degraded, ticking countdown, form error, release confirm | none | Attribution = console user |
| Performance | J7 | Screenshots: populated chart cards (running + dimmed stale), usage bars; row sparkline popover | collecting (no history yet), populated, sampler-error note, degraded | none | CPU normalized to observed peak |
| Nav | All | Screenshots: desktop tabs with counts + active state; mobile drawer open/closed | drawer open/closed, active page marked, counts hidden when unknown | none | None |
| Global | All | `formal-web-ui-verification` at 1440px and 390px per page: no horizontal document scroll, no clipped text, visible scrollbar inventory (expected: document vertical + log boxes + popover when open); the ten labels above each marked pass with evidence | error banner, 401 reload, reduced-motion, focus-visible pass | none | None |

Do not turn this table into a fixed layout recipe: grouping, exact widgets and
visual treatments stay with the implementation, provided every decision above
is supported and every relevance tier keeps its documented access path
(inline vs. popover vs. expansion vs. title attribute).

## Screen Requirements

Five hash-routed pages behind one sticky header (summary bar + nav; the
header is identical on every page):

| Screen area | Journey | Critical info | Primary actions | Secondary actions | Rare details | Device/context constraints |
| --- | --- | --- | --- | --- | --- | --- |
| Projects page (`#/projects`, default) | J8, J7 | Repo tree: per-node running counts, project + item CPU/mem, kind tags; subdomain chip on web-serving containers | Whole-project start/stop/restart; per-item start/stop/restart; hide idle; assign/edit container subdomain | Collapse nodes; reveal hidden; unhide | Repo path (title); pin markers | Tree stacks on phone; actions wrap |
| Sticky summary bar | J1 | Health sentence; coordinator/TLS chips | Open chip popovers | Sign out | Coordinator error text; cert dates | One-line sentence, wraps on phone; sticky top |
| Section nav | All | Page names, live counts, active page | Switch page | Hamburger open/close (phone) | — | Tabs ≥720px; drawer with ≥40px targets below |
| Servers page (`#/servers`, default) | J2, J3, J7 | Health badge, name, port, subdomain, CPU/mem numbers; docker-hosted web servers as first-class rows (kind tag, container status, published host ports) | Expand; restart; refresh logs; assign/edit subdomain (containers too, with a port picker when several are published); open history charts | Stop; start (stopped containers) | pid/cmd/cwd/health detail; container image/ports detail | Log box height-capped, own scrollbar; sparkline fixed-width |
| Routes page (`#/routes`) | J2, J4 | URL, resolved dot, access mode; targets: fixed port, managed server, docker container | Create; copy; toggle access | Delete; title; "view server" link | Timestamps | Form stacks at 390px; table rows become labelled cards |
| Docker page (`#/docker`) | J5, J7 | Status, name, image, ports, CPU/mem numbers; subdomain chip on web-serving containers | Logs; restart; start; open history charts; assign/edit subdomain | Stop | stats/labels | Same card pattern |
| Port leases page (`#/ports`) | J6 | Port, purpose, countdown; lease form; pinned ports (port permanently owned per server, with server status) | Lease; release (confirmed); unassign pin (confirmed) | Preferred port/TTL/project | Lease id, ISO expiry, agent, pin provenance (title) | Form stacks at 390px |
| Performance page (`#/performance`) | J7 | Per-entity CPU/mem charts; per-project bars | Read; jump to rows to act | — | Sampling cadence note | Chart grid single-column on phone |

## QA And Acceptance

- Happy-path scenarios: J1 healthy glance; J2 create fixed-port route → open
  URL → copy; J3 expand → logs → restart → healthy; J4 public toggle with
  confirm then revert; J5 container stop/start with logs; J6 lease with a
  preferred port → row appears → release → row gone, countdown ticks; J7
  running server shows live CPU/mem numbers, sparkline, and popover charts;
  page switching via tabs and via the mobile hamburger drawer.
- Edge cases: reserved/duplicate/invalid slugs; server without command
  (restart disabled); `url_is_current=false` flag; docker daemon down; empty
  every section; lease without TTL; released/nonexistent lease ("matching
  lease not found" verbatim, HTTP 400); deep link to an unknown page hash
  (falls back to Servers); metrics history empty right after console
  restart; coordinator error strings with quotes
  (`"'matching server not found'"`) shown verbatim.
- Failure/recovery scenarios: coordinator killed mid-session (degraded panels
  + Attention sentence, Routes still usable); overview fetch failing (banner
  + stale note, Retry works); mutation 400/409/502 (verbatim banner, state
  reverts on refetch); 401 (silent reload into login).
- Mobile scenarios: 390px — no horizontal document scroll, rows read as
  labelled cards, touch targets ≥34px on coarse pointers, copy buttons
  always visible, confirms still native dialogs.
- Accessibility checks: keyboard-only pass over every control (chevrons,
  switches, popovers, log regions); focus-visible outlines; popover Escape +
  focus return; icons labelled; status never color-only;
  `prefers-reduced-motion` disables shimmer/transitions.
- Test data or fixture mode: run the real stack per `docs/architecture.md`
  test fixtures — real coordinator on an ephemeral home
  (`CODEX_AGENT_COORDINATOR_HOME=<tmp>`), fixture upstream/WS servers, dev
  certs from `certs/dev/`, `DEV_HTTP=1` for browser-driver runs. No mocked
  API layer: the UI must be exercised against the actual `/api/*` surface.
