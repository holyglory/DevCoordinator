# DC-2026-08-03-BROWSER-LIFECYCLE-01 — Supporting record

## Confirmed context

The host is one developer using several Unix accounts for attribution and crash containment. Those accounts are not hostile tenants, and local cross-account metadata is not sensitive. Accidental runaway processes and cross-project interference are credible; public authentication and network boundaries remain unchanged. These assumptions are recorded in `security-assumptions.md` under the confirmed users/operators, trust-boundary, credible-misuse, necessary-control, unnecessary-gate and acceptable-risk sections.

Read-only host evidence on 2026-08-03 found roughly 91 Chrome renderer processes plus eight agent-browser controllers consuming about 33.6 GiB inside two developer login scopes. The installed Coordinator exposed no browser resource and could neither attribute nor clean those trees. Repository-owned Playwright tools already close their own browsers in `finally`, making abandoned external agent-browser sessions the dominant observed leak.

Linux exposes start identity and cumulative activity counters, not an authoritative historical “last used” timestamp. The product therefore records `last observed work`: the most recent observation window in which CPU, I/O or process membership changed. It never presents that value as exact historical use.

## Selected lifecycle

- Select only explicit headless/automation Chrome, Chromium, headless-shell and agent-browser trees. An executable name without an automation/headless marker is insufficient.
- Bind each observed process to PID plus kernel start ticks and revalidate before signalling, so PID reuse cannot redirect cleanup.
- Aggregate measured CPU, resident working memory, process count and bounded activity for each browser root.
- Exclude project-contained trees from the separate Agent-browser total, because project accounting already owns them. Display governed test trees only as protected lifecycle detail when observed; their transient runner remains the cleanup owner.
- Reap eligible developer-session trees after fifteen minutes without observed work. Send TERM to the exact tree, wait a bounded grace period, then KILL surviving exact identities; retain a bounded cleanup summary.
- Immediately before the first capable release activates, remove every currently observed explicit server-side headless automation tree and require a clean rescan. This is a one-time user-approved baseline action, not a recurring deployment habit.
- Publish the measured aggregate and bounded session detail with retained inventory. Performance subtracts it before computing the estimated system/unclassified residual and opens Agent-browser detail from the chart legend.

## Alternatives and tradeoffs

Agent-only cleanup is cheaper to build but fails when an agent crashes or loses its task. Killing every process named Chrome is unsafe because it can select an interactive browser. Treating all browser memory as a project double counts project-contained processes. Adding cryptographic leases or cross-account permission proofs conflicts with the confirmed same-developer trust model and adds no useful protection here. A Coordinator-owned observed lifecycle is the narrowest durable solution: it needs bounded process scanning and state, but does not require a database migration or change public authentication.

## Verification

Unit verification covers detection precision, activity transitions, PID reuse, cgroup ownership, idle timing, TERM/KILL escalation, respawn, bounded persistence and one-time release replay. Software-owned delivery performs the complete repository/package/deployment/browser cycle. Production acceptance proves the pre-activation cleanup, a managed visible Agent-browser sample, last-observed-work update, idle cleanup, residual reconciliation, modal keyboard/touch behavior, and responsive geometry at 320, 390, 768, 981 and 1440 px.
