# Decision History

## Direction

Confirmed product direction: one canonical Git worktree is one project, temporary worktrees remain children of their original repository, and immutable Coordinator identities determine every resource relationship. Python publishes one root-repository → temporary-repository → resource tree; Board and Console render it without ownership heuristics and keep current, actionable content compact. See [DC-2026-07-25-RUNTIME-01](DecisionDetails/DC-2026-07-25-RUNTIME-01.md) and [DC-2026-07-21-CONSOLE-DATA-01](DecisionDetails/DC-2026-07-21-CONSOLE-DATA-01.md).

Confirmed authority and lifecycle direction: one peer-authenticated service authority owns host state, authorization, observation, runtime/test admission, and mutation. Calls are attributed, exact-ID based, evidence-carrying, and fail closed; short-lived Docker work is authorized and durably attributed before creation, temporary work expires durably, archive and permanent removal remain distinct, removed identities cannot silently return, and supervised workers retain crash evidence and require explicit repair after a crash-loop breaker trips. See [DC-2026-07-15-HOST-01](DecisionDetails/DC-2026-07-15-HOST-01.md) and [DC-2026-07-25-RUNTIME-01](DecisionDetails/DC-2026-07-25-RUNTIME-01.md).

Confirmed access direction: verified identity is not authorization. Console and route grants are exact and owner-controlled; private upstream credentials remain server-side; attributable protected routes may use narrowly bound short-lived signed identity assertions; project notifications use separately authorized user-owned bots; and Codex annotation compatibility permits only the approved split inline-style exception while keeping inline scripts blocked. See [DC-2026-07-18-INVITES-01](DecisionDetails/DC-2026-07-18-INVITES-01.md) and [DC-2026-07-17-ANNOTATION-03](DecisionDetails/DC-2026-07-17-ANNOTATION-03.md).

Confirmed operational direction: the public Console, authenticated API, and broker are independently supervised availability boundaries with exact readiness and migration gates; the metrics loop is the sole periodic observer and backs off after completion; long-lived protected-profile readers reload through their own supervisor after stable profile replacement. DevCoordinator is the independent source of its apps, skills, deployment assets, and validation; releases require fetched ancestry, preserved dirty work, fresh-clone and standalone-package proof, production-shaped interface evidence, and the Build macOS Apps workflow for native delivery. See [DC-2026-07-20-CONSOLE-RESILIENCE-01](DecisionDetails/DC-2026-07-20-CONSOLE-RESILIENCE-01.md), [DC-2026-07-21-CONSOLE-DATA-01](DecisionDetails/DC-2026-07-21-CONSOLE-DATA-01.md), and [DC-2026-07-11-20](DecisionDetails/DC-2026-07-11-20.md).

## DC-2026-07-25-RUNTIME-01 — Python owns repository-family runtime coordination

ID: DC-2026-07-25-RUNTIME-01 · Details: [supporting record](DecisionDetails/DC-2026-07-25-RUNTIME-01.md)

Decision: Keep one typed Python API as the lifecycle authority for services, Docker resources, local database stacks, short-lived containers, and repository-scoped test records. Every runtime call identifies the agent, canonical root repository, explicit temporary repository or null, immutable target, purpose, TTL, and KillAfterRun policy; durable state owns stable ports, exact membership, repository-family reporting, cleanup, Archive/Restore/Remove, and no-resurrection tombstones. Routine actions use schema-derived flags, new ephemeral Docker work commits exact authorization and cleanup before creation, test subprocesses run under the enrolled user, and Keep Alive workers record every crash with a default ten-crashes-in-five-minutes non-expiring breaker and explicit re-arm.

Why: Direct shell or Docker admission, broker-side arbitrary commands, repository-local test stores, hand-authored request variants, name or port matching, and UI-side grouping repeatedly produced duplicate projects, unattributed resources, unsafe mutations, lost cleanup, or fragmented history. One durable normalized producer costs broker and schema work but uniquely preserves attribution across agents and accounts, survives caller failure, returns compact complete evidence, and gives every interface the same truthful hierarchy and test history.

## DC-2026-07-21-CONSOLE-DATA-01 — Observations and interfaces stay truthful and bounded

ID: DC-2026-07-21-CONSOLE-DATA-01 · Details: [supporting record](DecisionDetails/DC-2026-07-21-CONSOLE-DATA-01.md)

Decision: Let one attributed metrics loop coalesce and commit current host and Docker snapshots before pure inventory reads, back off after completion on failure, and never let another periodic consumer multiply observation work. Join live state and telemetry only by immutable identity within the latest completed available snapshot; retain history without presenting absent resources as current; exclude control-only server definitions until concrete lifecycle evidence exists; prefer a live replacement over historical same-name records; and forward public TLS routes only to an explicitly selected HTTP listener. Board and Console consume the Coordinator tree, keep cached content during refresh, poll only while visible, sort by stable fields, bound mounted collections and disclosures, and show global attention only with current evidence and a safe action route.

Why: Pure reads without observation left removed containers visible; concurrent polling caused high CPU and permanent Updating badges; control definitions appeared as phantom servers; protocol guessing broke routed applications; stale samples and name-derived grouping invented current membership; and unbounded or jitter-sorted collections disrupted operator focus. Snapshot-bound projection, one completion-anchored observer, explicit route protocol, and bounded presentation preserve history and responsiveness without inventing ownership, availability, health, or urgency.

## DC-2026-07-20-CONSOLE-RESILIENCE-01 — Listener availability and upgrades fail independently

ID: DC-2026-07-20-CONSOLE-RESILIENCE-01 · Details: [supporting record](DecisionDetails/DC-2026-07-20-CONSOLE-RESILIENCE-01.md)

Decision: Keep the public Console, authenticated loopback API, and server-wide broker as separately supervised availability boundaries connected by soft ordering dependencies. Unexpected clean or failed exits restart with durable journal evidence, explicit stops remain authoritative, authorization/schema migrations reconcile before restart, a stable protected-profile replacement causes only its long-lived loopback reader to exit for supervised reload, and startup, rollback, and deployment readiness require bounded convergence of exact process, listener, authentication, registration, assignment, and lease identities.

Why: Hard dependency chains turned broker or API maintenance into a public outage, stale strict readers kept returning authenticated failures after atomic profile publication, while process creation, fixed sleeps, or listener-only checks declared services ready before authenticated Coordinator registration existed. Independent supervision, exact profile identity reload, and exact convergence preserve intentional maintenance control without hiding partial startup, rollback, or migration failure.

## DC-2026-07-18-INVITES-01 — Protected access is exact and owner-controlled

ID: DC-2026-07-18-INVITES-01 · Details: [supporting record](DecisionDetails/DC-2026-07-18-INVITES-01.md)

Decision: Retain verified Google identity while denying protected HTTP and WebSocket resources until an owner approves the exact Console or domain request. Store per-account grants privately and reauthorize every request; strip caller authorization and inject any route-scoped upstream credential only server-side; distinguish missing browser identity from a rejected private credential; and, only where attributable controls require it, issue a short-lived asymmetric assertion bound to issuer, public host, exact route grant, HTTP method, normalized user, and one-time replay identity. Keep the trusted TLS edge and automated DNS renewal explicit. Let each authorized account manage only its own Telegram bots, bind subscriptions to immutable repository IDs, approve each private-chat user separately, and deliver durable Coordinator events through a restart-safe cursor and outbox.

Why: Global allowlists, automatic grants, browser-visible or shared upstream secrets, forgeable identity headers, shared bots, display-name bindings, and UI-only notification hooks broaden access or lose attribution and events. Exact server-derived grants, private credential translation with honest configuration failures, narrowly signed human identity, user-owned bots, and durable delivery preserve one sign-in and least privilege without weakening upstream or audit boundaries.

## DC-2026-07-17-ANNOTATION-03 — Annotation compatibility permits styles, never scripts

ID: DC-2026-07-17-ANNOTATION-03 · Details: [supporting record](DecisionDetails/DC-2026-07-17-ANNOTATION-03.md)

Decision: Permit annotation renderer style attributes and elements only through separate `style-src-attr 'unsafe-inline'` and `style-src-elem 'self' 'unsafe-inline'` directives, retain strict `style-src 'self'` and `script-src 'self'` fallbacks, and add no speculative frame or resource sources. Verify both parent and inherited child documents through the authenticated browser path.

Why: Attribute-only permission was tried and left the real renderer unusable, while broad style permission, inline scripts, disabled CSP, and speculative blob or data sources exceeded the approved compatibility need. The split exception is the narrowest policy proven to support annotations without expanding executable content.

## DC-2026-07-15-HOST-01 — One peer-authenticated authority owns each managed host

ID: DC-2026-07-15-HOST-01 · Details: [supporting record](DecisionDetails/DC-2026-07-15-HOST-01.md)

Decision: Use one service-owned database and peer-authenticated broker socket as the default authority for all enrolled accounts and agents on a host; clients never open that database. The broker rechecks peer UID, protected enrollment profiles, exact repository/resource membership, live action grants, descriptor-anchored ownership and symlink safety, native mutation-capable ACLs, and narrowly scoped OS capabilities before observing or mutating; unrecognized authority models and profile/database drift fail closed. Authorization upgrades migrate and reconcile offline before service restart, while per-user files remain non-authoritative launch, log, migration, or recovery evidence.

Why: Per-account authorities and cross-user writable stores disagreed about projects, ports, resources, and permissions, while mode bits alone missed ACL grants and broad root execution weakened isolation. One authenticated authority with native proof and versioned enrollment costs deployment machinery but uniquely provides host-wide arbitration without trusting names, client state, remapped home directories, or unsupported filesystem semantics.

## DC-2026-07-11-20 — DevCoordinator owns its source and publication gate

ID: DC-2026-07-11-20 · Details: [supporting record](DecisionDetails/DC-2026-07-11-20.md)

Decision: Keep DevCoordinator independent of holyskills and make this repository the only writable source for its Coordinator skill, PostgreSQL protection skill, Board, Console, deployment assets, and validation. Keep agent-facing skills runtime-neutral and install canonical source through verified managed links. Before broad work, fetch and classify remote ancestry while preserving dirty work; before publication, validate a fresh clone of the exact commit, copied standalone skills, repository boundaries, generated provenance, production-view snapshots, and native packages through the Build macOS Apps workflow.

Why: Embedded or copied sources drifted, stale-base work risked overwriting remote or local changes, dirty checkouts supplied undeclared artifacts, and ad-hoc native builds bypassed signing and launch evidence. Independent ownership plus reproducible source-current gates makes failures reviewable and proves that published artifacts do not depend on one developer machine.
