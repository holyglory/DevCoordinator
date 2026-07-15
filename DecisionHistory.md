# Decision History

## Direction

Confirmed user intent: one canonical local worktree is one project; removal is a reversible, data-retaining decommission rather than cosmetic hiding; coordinator state and actions must be real, attributable, and fail closed; ports remain stable; background UI work stays bounded; and protected Console access is explicit per account and domain. See [DC-2026-07-14-STATE-01](DecisionDetails/DC-2026-07-14-STATE-01.md), [DC-2026-07-13-01](DecisionDetails/DC-2026-07-13-01.md), [DC-2026-07-10-03](DecisionDetails/DC-2026-07-10-03.md), [DC-2026-07-06-01](DecisionDetails/DC-2026-07-06-01.md), [DC-2026-07-13-05](DecisionDetails/DC-2026-07-13-05.md), and [DC-2026-07-14-ACCESS-01](DecisionDetails/DC-2026-07-14-ACCESS-01.md).

Confirmed operational direction: all enrolled users and agents on one host use one service-owned Coordinator authority through peer-authenticated authorization; clients do not open the authority database; native work follows the Build macOS Apps workflow; and releases require remote-fresh, production-shaped evidence. See [DC-2026-07-15-HOST-01](DecisionDetails/DC-2026-07-15-HOST-01.md), [DC-2026-07-10-07](DecisionDetails/DC-2026-07-10-07.md), and [DC-2026-07-11-19](DecisionDetails/DC-2026-07-11-19.md).

Inferred direction: the owner prefers compact, actionable status over persistent generic warnings and favors durable safety boundaries over UI-only or denormalized shortcuts. See [DC-2026-07-13-08](DecisionDetails/DC-2026-07-13-08.md), [DC-2026-07-07-01](DecisionDetails/DC-2026-07-07-01.md), and [DC-2026-07-14-STATE-01](DecisionDetails/DC-2026-07-14-STATE-01.md); revisit this inference if later explicit direction conflicts.

## DC-2026-07-15-HOST-01 — The host coordinator is one peer-authenticated system authority

ID: DC-2026-07-15-HOST-01 · Details: [supporting record](DecisionDetails/DC-2026-07-15-HOST-01.md)

Decision: Make the service-owned database at `/var/lib/devcoordinator/coordinator.sqlite3` and peer-authenticated socket at `/run/devcoordinator/broker.sock` the default, single host authority for every enrolled OS account and agent. Keep per-user files only as non-authoritative migration, launch-log, or reconciliation evidence; use direct canonical symlinks for code discovery, never as a permission bypass.

Why: The private-account default let `holygloryTT` start a healthy `prtzn-vpn` server that the `holyglory` Console authority could not see. Cross-user writable SQLite through symlinks loses ownership and authentication, while UI-side inventory merging retains conflicting writers. One system broker uniquely provides one inventory and reservation authority without recurring elevation prompts.

## DC-2026-07-14-ACCESS-01 — Per-account domain grants with configured owners

ID: DC-2026-07-14-ACCESS-01 · Details: [supporting record](DecisionDetails/DC-2026-07-14-ACCESS-01.md)

Decision: Keep configured Google accounts as non-UI owners, and store invited accounts plus explicit Console or routed-domain grants in a private atomic policy file that is checked on every HTTP and WebSocket request.

Why: A global allowlist cannot express per-domain access, while letting every Console user administer grants violates least privilege. Configured owners plus local grants preserve the verified OIDC and recovery path without adding an external identity control plane.

## DC-2026-07-14-STATE-01 — Repository removal is a reversible decommission backed by the normalized coordinator store

ID: DC-2026-07-14-STATE-01 · Details: [supporting record](DecisionDetails/DC-2026-07-14-STATE-01.md)

Decision: Use a private normalized SQLite/WAL authority per effective account, transactional same-UID legacy import, one observer per host-resource domain, and a peer-authenticated broker for cross-UID ports and Docker. Repository removal fences starts, disables captured auto-start policy, stops and verifies exact resources, releases leases and assignments, then hides the repository while retaining data and history.

Why: Board-only hiding plus Stop could lie when another source or restart policy revived a project, while per-home JSON tombstones still allowed authorities to disagree. The normalized store and broker cost more but uniquely provide one repository identity, durable decommission, controlled reinstall, and honest host-wide arbitration.

## DC-2026-07-13-01 — DevOps Board project identity is one canonical worktree, never one coordinator source

ID: DC-2026-07-13-01 · Details: [supporting record](DecisionDetails/DC-2026-07-13-01.md)

Decision: Treat one canonical local Git worktree root as exactly one Board project. Keep source and native identities as observation/control provenance, reconcile physical resources once, place unresolved evidence in one Unassigned Resources group, and fail closed when no single binding covers a mutation.

Why: Source-scoped grouping tripled Nevod and name-derived grouping invented projects and double-counted metrics. Canonical-root identity preserves distinct worktrees while retaining source identity only where safe action routing needs it.

## DC-2026-07-13-02 — DevOps Board source ownership is anchored to the login account

ID: DC-2026-07-13-02 · Details: [supporting record](DecisionDetails/DC-2026-07-13-02.md)

Decision: Resolve the default coordinator home from the effective POSIX login account rather than a host application's remapped HOME. Same-UID applications share one authority; different UIDs retain private stores and use either disjoint ranges or the authenticated host broker.

Why: Parall remapped HOME and made the Board select a valid but empty store. A cross-UID writable store would weaken isolation, while independent homes cannot guarantee host-wide uniqueness; account ownership plus a broker preserves both boundaries.

## DC-2026-07-11-01 — The final legacy-cgroup gate is a handoff, not a second quiescence window

ID: DC-2026-07-11-01 · Details: [supporting record](DecisionDetails/DC-2026-07-11-01.md)

Decision: Keep the initial five-second exact-cgroup proof, then use a 250-millisecond exact handoff immediately before stop and a bounded post-stop identity, cgroup, and listener drain before any writer-free state copy.

Why: A second five-second idle window repeatedly rejected legitimate short-lived Git and Docker children. The short handoff plus strict post-stop drain retains foreign-writer protection while avoiding that production false abort.

## DC-2026-07-11-02 — Retired checkout assignments require an explicit migration disposition

ID: DC-2026-07-11-02 · Details: [supporting record](DecisionDetails/DC-2026-07-11-02.md)

Decision: Enumerate every durable assignment owned by a retiring checkout and bind each to an explicit, checksummed migrate-or-unassign disposition before the service-stop boundary.

Why: Blindly retaining assignments leaves stale checkout ownership, while deleting them all can break features that moved. Explicit dispositions let the cutover relocate proven live functionality and remove only proven stopped residue.

## DC-2026-07-11-03 — Legacy rollback readiness includes coordinator registration

ID: DC-2026-07-11-03 · Details: [supporting record](DecisionDetails/DC-2026-07-11-03.md)

Decision: Require rollback readiness to prove the restored Console's exact coordinator registration graph in addition to systemd, process, listener, and public TLS identity.

Why: The legacy Console can continue serving HTTPS after a failed coordinator registration. Listener and TLS checks alone could therefore declare rollback healthy while operational control remained absent.

## DC-2026-07-11-04 — Private cutover helpers have a tracked executable CLI contract

ID: DC-2026-07-11-04 · Details: [supporting record](DecisionDetails/DC-2026-07-11-04.md)

Decision: Exercise every repository helper and exact argument combination used by the private cutover as a real subprocess CLI in normal and optimized Python before service mutation.

Why: Source review, shell syntax, and direct-function tests cannot prove argparse boundaries. The executable matrix catches missing flags or subcommands before the legacy service is stopped.

## DC-2026-07-11-05 — Executable validation follows Git semantics across safe umasks

ID: DC-2026-07-11-05 · Details: [supporting record](DecisionDetails/DC-2026-07-11-05.md)

Decision: Validate all three executable bits and reject world-writable helpers while accepting both ordinary 0755 and safe group-shared 0775 materializations.

Why: Exact 0755 comparison rejected a legitimate Git executable in a 0002-umask checkout. Executable-bit semantics preserve the security contract without confusing host checkout policy with source provenance.

## DC-2026-07-11-06 — Console readiness is the registered MainPID graph, not process creation

ID: DC-2026-07-11-06 · Details: [supporting record](DecisionDetails/DC-2026-07-11-06.md)

Decision: Keep Console startup in its systemd transaction until an ExecStartPost probe proves stable MainPID/cgroup identity, listener ownership, health, registration, assignment, and lease linkage.

Why: Type=simple proves only process creation; the listener and coordinator registration happen later. A fixed sleep or later cutover verifier makes ordinary boot correctness timing-dependent.

## DC-2026-07-11-07 — Split-service and rollback readiness require proven convergence

ID: DC-2026-07-11-07 · Details: [supporting record](DecisionDetails/DC-2026-07-11-07.md)

Decision: Make coordinator startup and rollback probes share bounded monotonic convergence checks for health, authentication, exact process/listener identity, and registered control state.

Why: One-shot checks raced both new and restored services during their startup intervals. Bounded convergence tolerates explicit startup states while immediately rejecting permanent identity or credential failures.

## DC-2026-07-11-08 — Cutover helper interfaces are executable contracts

ID: DC-2026-07-11-08 · Details: [supporting record](DecisionDetails/DC-2026-07-11-08.md)

Decision: Treat every durable cutover phase name and helper flag as a public executable interface and cover the complete phase lifecycle through the real command parser.

Why: A syntax-valid private script used phase strings that the deployed helper rejected. Direct function coverage had hidden the mismatch; real CLI coverage prevents a post-stop discovery.

## DC-2026-07-11-09 — Cutover readiness is a bounded observed-clean window, not lucky point samples

ID: DC-2026-07-11-09 · Details: [supporting record](DecisionDetails/DC-2026-07-11-09.md)

Decision: Superseded by DC-2026-07-11-01. Replace sparse point samples with a bounded, transition-recording observed-clean cgroup window; use the later short final handoff rather than this entry's second five-second window.

Why: Point samples could either land on legitimate transient children or miss a shorter unsafe interval. Continuous bounded observation improved evidence, and production behavior later showed the redundant final long window was too strict.

## DC-2026-07-11-10 — Split-service listener discovery must capability-match without capability propagation

ID: DC-2026-07-11-10 · Details: [supporting record](DecisionDetails/DC-2026-07-11-10.md)

Decision: Give the coordinator only the observer capability needed to inspect the capability-bearing Console, then clear ambient and inheritable capability sets before it can exec managed children.

Why: Same UID did not make procfs listener evidence readable across asymmetric capabilities. Matching the observer capability fixes discovery, while clearing inheritance prevents managed children from receiving that privilege.

## DC-2026-07-11-11 — Loaded-unit checks model omitted undefined properties narrowly

ID: DC-2026-07-11-11 · Details: [supporting record](DecisionDetails/DC-2026-07-11-11.md)

Decision: Treat omitted systemd properties as empty only for an explicit per-unit allowlist backed by real target-version output, and reject non-empty overrides for those properties.

Why: systemd omitted two undefined properties that a synthetic fixture printed as empty. Global missing-as-empty normalization would hide security-relevant overrides; narrow normalization matches reality without weakening other checks.

## DC-2026-07-11-12 — Authentication tamper fixtures change decoded bytes

ID: DC-2026-07-11-12 · Details: [supporting record](DecisionDetails/DC-2026-07-11-12.md)

Decision: Mutate a decoded signature byte and re-encode it in authentication tamper tests, or explicitly prove that an encoded edit changes decoded bytes.

Why: Editing a trailing base64url character can alter only unused padding bits or reproduce the original token. Byte-level mutation makes the rejection fixture deterministic across runtimes.

## DC-2026-07-11-13 — System units pin the service account home

ID: DC-2026-07-11-13 · Details: [supporting record](DecisionDetails/DC-2026-07-11-13.md)

Decision: Pin the intended non-root account home in system-level unit paths and reject active use of systemd's percent-h home expansion for those services.

Why: The system manager expanded the home specifier in root context before changing User, redirecting private coordinator paths to /root. Explicit paths avoid that manager-context ambiguity.

## DC-2026-07-11-14 — Cutover preconditions are sampled and revalidated after legacy stop

ID: DC-2026-07-11-14 · Details: [supporting record](DecisionDetails/DC-2026-07-11-14.md)

Decision: Superseded by DC-2026-07-11-09 and DC-2026-07-11-01. Preserve exact identity evidence across a bounded observed-clean window, then revalidate the writer-free boundary after stop before copying state.

Why: Early point samples and chmod operations were invalidated by later legacy writes. The replacement decisions retain continuous evidence and tighten the final handoff and post-stop boundary.

## DC-2026-07-11-15 — Every macOS HTTP fixture uses the fast-bind server

ID: DC-2026-07-11-15 · Details: [supporting record](DecisionDetails/DC-2026-07-11-15.md)

Decision: Ban bare python-module http.server test argv and require the repository's fast-bind socketserver fixture, with AST recall and false-positive controls.

Why: Python's inherited HTTPServer bind path can block on macOS reverse DNS before listen. The fast-bind fixture removes host-dependent startup behavior without weakening production checks.

## DC-2026-07-11-16 — Concurrency fixtures isolate pre-lock capabilities

ID: DC-2026-07-11-16 · Details: [supporting record](DecisionDetails/DC-2026-07-11-16.md)

Decision: Stub every prerequisite before a concurrency test's intended lock boundary, prove the worker reached that boundary, and include worker errors in timeout failures.

Why: A Docker serialization test failed capability discovery before reaching its fake subprocess on macOS. Deterministic prerequisites separate lock evidence from environment availability.

## DC-2026-07-11-17 — CI fixtures must prove canonical paths and usable database readiness

ID: DC-2026-07-11-17 · Details: [supporting record](DecisionDetails/DC-2026-07-11-17.md)

Decision: Canonicalize only test-owned temporary roots while keeping production symlink rejection strict, and prove PostgreSQL readiness with SELECT 1 against the exact application database.

Why: macOS temporary paths may traverse a system alias, and an accepting PostgreSQL listener does not prove the requested database is usable. The paired checks remove fixture contamination without weakening real safety.

## DC-2026-07-11-18 — Cleanup and rollback failures are transaction evidence

ID: DC-2026-07-11-18 · Details: [supporting record](DecisionDetails/DC-2026-07-11-18.md)

Decision: Preserve every operator-relevant body, cleanup, rollback, restoration, and diagnostic failure in the top-level redacted structured error while still attempting independent cleanup.

Why: Exception notes and causes disappeared at CLI serialization, hiding secondary failures that affected recovery. A combined visible error retains the real transaction state without discarding the primary cause.

## DC-2026-07-11-19 — Fresh-clone validation is a publication gate, not a duplicate smoke test

ID: DC-2026-07-11-19 · Details: [supporting record](DecisionDetails/DC-2026-07-11-19.md)

Decision: Validate every public candidate from a fresh clone of the exact commit, including standalone skills, generated/package provenance, and repository boundaries, before publication.

Why: A dirty developer checkout can supply ignored files, local links, or generated leftovers that make validation pass. Fresh-clone evidence proves the committed artifact is self-contained.

## DC-2026-07-11-20 — DevCoordinator became the independent owner of operations tooling

ID: DC-2026-07-11-20 · Details: [supporting record](DecisionDetails/DC-2026-07-11-20.md)

Decision: Make DevCoordinator the canonical independent repository for its two skills, DevOps Board, DevOps Console, deployment assets, and validation, with no dependency on holyskills.

Why: Keeping operations tooling embedded in a broader skills repository blurred ownership and publication boundaries. An independent source retains history while making runtime, release, and security responsibilities explicit.

## DC-2026-07-11-21 — Stale-base work was recovered by a remote-first semantic merge

ID: DC-2026-07-11-21 · Details: [supporting record](DecisionDetails/DC-2026-07-11-21.md)

Decision: Preserve stale-base dirty work on a branch, start from the fetched remote default, and reconcile with an evidence-backed semantic merge rather than resetting or overwriting either side.

Why: Resetting would lose valuable local work, while pushing the stale base would discard remote changes. Remote-first three-way reconciliation preserves both histories and makes conflicts reviewable.

## DC-2026-07-11-22 — Repository-wide work requires a fetched remote-ancestry preflight

ID: DC-2026-07-11-22 · Details: [supporting record](DecisionDetails/DC-2026-07-11-22.md)

Decision: Run the repository freshness checker before broad audits, refactors, migrations, history changes, or splits, and treat remote-unavailable as unknown.

Why: Local status alone cannot reveal a stale remote baseline. Fetched ancestry distinguishes safe current/ahead work from behind, diverged, or dirty-on-stale-base states before consequential changes.

## DC-2026-07-10-01 — GUI runtime actions preflight dependencies and bind delivered binaries

ID: DC-2026-07-10-01 · Details: [supporting record](DecisionDetails/DC-2026-07-10-01.md)

Decision: Build a deterministic GUI subprocess environment, preflight Docker/Compose before any partial mutation, refresh after every result, and bind packaged executable and helper bytes to exact source provenance.

Why: A minimal launchd PATH made a project stop processes before Docker failed, and a stale bare Swift process obscured the delivered build. Preflight plus provenance prevents partial actions and unverifiable binaries.

## DC-2026-07-10-02 — Canonical direct-link skill installation

ID: DC-2026-07-10-02 · Details: [supporting record](DecisionDetails/DC-2026-07-10-02.md)

Decision: Install the two repository-owned skills only as verified direct absolute symlinks managed transactionally by scripts/manage_skill_links.py.

Why: Hand-edited or copied runtime skills drift from canonical source and hide which version an agent reads. Direct links preserve one writable authority while rollback transactions protect intentional local changes.

## DC-2026-07-10-03 — Truthful, fail-closed skill and Board contracts

ID: DC-2026-07-10-03 · Details: [supporting record](DecisionDetails/DC-2026-07-10-03.md)

Decision: Make unavailable dependencies, unknown ownership, unsafe actions, and partial results explicit; no control may imply an action or health state that the coordinator cannot prove.

Why: Optimistic fallbacks and cosmetic availability made the Board look functional while actions failed or targeted ambiguous resources. Fail-closed, evidence-carrying contracts keep the interface honest.

## DC-2026-07-10-04 — Approved Board hierarchy and structured exact-lease starts

ID: DC-2026-07-10-04 · Details: [supporting record](DecisionDetails/DC-2026-07-10-04.md)

Decision: Use the approved three-pane Board hierarchy and require structured argv plus exact lease identity when starting a managed server from an existing lease.

Why: A flat action surface obscured project context, while shell strings and port-only reuse could attach the wrong capability. Hierarchy improves navigation and exact structured starts preserve identity and injection safety.

## DC-2026-07-10-05 — Production-view, source-bound snapshot evidence

ID: DC-2026-07-10-05 · Details: [supporting record](DecisionDetails/DC-2026-07-10-05.md)

Decision: Render canonical snapshots through production views and bind each artifact to exact renderer inputs and source hashes, with realistic detector recall and false-positive controls.

Why: Hand-built lookalike fixtures and unbound PNGs can pass while production UI differs. Source-bound production rendering makes visual evidence attributable and current.

## DC-2026-07-10-06 — Attributed lease lifecycle and target-wide action isolation

ID: DC-2026-07-10-06 · Details: [supporting record](DecisionDetails/DC-2026-07-10-06.md)

Decision: Bind leases, assignments, operations, and lifecycle actions to exact agent, canonical project, server, and immutable target identities across every mutation family.

Why: Port or display-name matching can collide across projects and allow one action to affect another target. Full attribution preserves stable leases and enforces target-wide isolation.

## DC-2026-07-10-07 — Build macOS Apps is mandatory for native validation

ID: DC-2026-07-10-07 · Details: [supporting record](DecisionDetails/DC-2026-07-10-07.md)

Decision: Build, test, snapshot, package, launch, debug, and automate DevOps Board only through the Build macOS Apps workflow.

Why: Direct Swift, Xcode, open, or ad-hoc UI control bypasses the required source identity, signing, packaging, and launch evidence. The plugin supplies one auditable native gate.

## DC-2026-07-07-01 — DevOps Console: single-row header with a needs-attention badge; uniform color-coded actions (v1.5.1)

ID: DC-2026-07-07-01 · Details: [supporting record](DecisionDetails/DC-2026-07-07-01.md)

Decision: Keep the Console header compact, show a needs-attention badge only for actionable evidence, and apply one consistent semantic color system to lifecycle actions.

Why: Persistent generic warning chrome competed with primary content, while inconsistent action colors obscured meaning. A compact evidence-driven badge and uniform colors improve scanability without hiding real failures.

## DC-2026-07-07-02 — DevOps Console: stable ordering contract — live metrics are never a sort key (v1.4.1)

ID: DC-2026-07-07-02 · Details: [supporting record](DecisionDetails/DC-2026-07-07-02.md)

Decision: Sort Console collections by stable identity and lifecycle fields, never by rapidly changing CPU or memory samples.

Why: Metric-based ordering makes rows jump during observation and breaks operator focus. Stable ordering preserves spatial memory while metrics remain visible as values.

## DC-2026-07-07-03 — DevOps Console: docker-hosted web servers are first-class servers (v1.4.0)

ID: DC-2026-07-07-03 · Details: [supporting record](DecisionDetails/DC-2026-07-07-03.md)

Decision: Represent attributed Docker-hosted HTTP services as first-class servers with their real container, port, health, routing, and lifecycle evidence.

Why: Treating them only as generic containers hid the server journey and split related controls. First-class server projection improves management without inventing ownership from names.

## DC-2026-07-07-04 — CI on macOS: never use bare `python3 -m http.server` as a test fixture

ID: DC-2026-07-07-04 · Details: [supporting record](DecisionDetails/DC-2026-07-07-04.md)

Decision: Use the repository fast-bind HTTP fixture for macOS-capable tests and reject literal bare module-server argv through an AST guard.

Why: Bare http.server can block on reverse DNS after bind and before listen on macOS. The controlled socketserver fixture removes that nondeterminism.

## DC-2026-07-07-05 — validate.py de-staled: needles pin code and call sites, not comments and definitions

ID: DC-2026-07-07-05 · Details: [supporting record](DecisionDetails/DC-2026-07-07-05.md)

Decision: Make source guards identify executable call sites and scoped invariants rather than accepting matching comments, helper definitions, or ambiguous duplicate text.

Why: Broad text needles passed after behavior moved or disappeared. Scoped executable pins retain cheap static coverage without mistaking documentation for implementation.

## DC-2026-07-07-06 — DevOpsBoard: project grouping consumes coordinator membership instead of re-deriving it

ID: DC-2026-07-07-06 · Details: [supporting record](DecisionDetails/DC-2026-07-07-06.md)

Decision: Build Board groups from coordinator-supplied resource membership and usage identity, keeping unclaimed resources visible separately and removing client-side name/path heuristics.

Why: Re-derived grouping could display a container under a project whose whole-project action would not touch it. Consuming authoritative membership aligns presentation and action scope.

## DC-2026-07-07-07 — Coordinator: one container-membership model for display grouping and whole-project actions

ID: DC-2026-07-07-07 · Details: [supporting record](DecisionDetails/DC-2026-07-07-07.md)

Decision: Use one attributed container-membership model for inventory grouping and whole-project lifecycle actions, with unresolved containers explicitly unassigned.

Why: Separate display and action matchers disagreed for name-like containers. One model prevents resources from appearing owned in the UI while being omitted from or wrongly included in actions.

## DC-2026-07-07-08 — DevOps Console: Projects tree, repo grouping everywhere, hideable items that self-reveal

ID: DC-2026-07-07-08 · Details: [supporting record](DecisionDetails/DC-2026-07-07-08.md)

Decision: Make Projects the Console's primary tree, group servers/containers/databases by repository throughout, and let users hide items only until new activity or health evidence makes them relevant again.

Why: Separate resource pages obscured project context, while permanent hiding could conceal a returning problem. Project-centric grouping and evidence-triggered reveal balance focus with operational truth.

## DC-2026-07-06-01 — Coordinator: durable per-repo port assignments (ports never drift across restarts)

ID: DC-2026-07-06-01 · Details: [supporting record](DecisionDetails/DC-2026-07-06-01.md)

Decision: Persist a unique port assignment per canonical repository and server name across stops, lease expiry, and restarts; changing it requires an explicit reassignment or allowed relocation.

Why: Ephemeral lease-only allocation lets endpoints drift and breaks agents, routes, and bookmarks. Durable assignments keep ports stable while active leases still represent current use.

## DC-2026-07-06-02 — DevOps Console: paged UI with hamburger nav, CPU/mem history charts, lease management

ID: DC-2026-07-06-02 · Details: [supporting record](DecisionDetails/DC-2026-07-06-02.md)

Decision: Split the Console into focused routed pages with responsive navigation, bounded CPU/memory history, and direct lease-management surfaces.

Why: One long dashboard buried primary collections and degraded narrow layouts. Paged journeys keep named content first while retaining operational history and port control.

## DC-2026-07-06-03 — DevOps Console: Google OAuth live, Docker installed, per-server subdomains, HSTS

ID: DC-2026-07-06-03 · Details: [supporting record](DecisionDetails/DC-2026-07-06-03.md)

Decision: Run the Console with the verified Google OAuth client, actual Docker capability, direct per-server subdomain assignment, and HSTS on the trusted TLS edge.

Why: Degraded authentication, missing Docker, indirect routing controls, and stale insecure browser state each made the live product misleading. Explicit verified dependencies and HTTPS policy align UI claims with deployment reality.

## DC-2026-07-05-01 — DevOps Console: automated wildcard renewal via 101domain API

ID: DC-2026-07-05-01 · Details: [supporting record](DecisionDetails/DC-2026-07-05-01.md)

Decision: Automate wildcard DNS-01 certificate renewal through the private 101domain API credential and the certbot renewal timer.

Why: Manual TXT updates every certificate cycle create a standing outage risk. API-driven DNS-01 preserves wildcard coverage without recurring operator intervention.

## DC-2026-07-05-02 — DevOps Console: *.vr.ae wildcard cert via manual DNS-01

ID: DC-2026-07-05-02 · Details: [supporting record](DecisionDetails/DC-2026-07-05-02.md)

Decision: Superseded operationally by DC-2026-07-05-01. Initially issue the wildcard and apex certificate through a carefully held manual DNS-01 challenge because no registrar API credential was available.

Why: Wildcards require DNS-01, while HTTP-01 can cover only named hosts. Manual publication was the safe available bridge until the owner later supplied API access for unattended renewal.

## DC-2026-07-05-03 — DevOps Console: real Let's Encrypt cert via in-app ACME HTTP-01

ID: DC-2026-07-05-03 · Details: [supporting record](DecisionDetails/DC-2026-07-05-03.md)

Decision: Superseded for wildcard coverage by DC-2026-07-05-02. Initially serve ACME HTTP-01 in the running app to obtain trusted named-host TLS without stopping the edge.

Why: DNS API access was unavailable and the self-signed fallback was not browser-trusted. In-app HTTP-01 used the reachable port 80 path without renewal downtime, but could not issue arbitrary wildcard hosts.

## DC-2026-07-05-04 — DevOps Console web app: TLS edge + subdomain reverse proxy on vr.ae

ID: DC-2026-07-05-04 · Details: [supporting record](DecisionDetails/DC-2026-07-05-04.md)

Decision: Use a zero-third-party-dependency Node 20 service as the vr.ae TLS edge, authenticated Console, and HTTP/WebSocket subdomain reverse proxy, routing all operational mutations through DevCoordinator.

Why: A separate proxy plus control app would add another state and dependency boundary. One auditable edge with the coordinator as control authority preserves routing flexibility without duplicating lifecycle logic.

## DC-2026-07-05-05 — Codex Ops Console renamed to DevOps Board; idle CPU eliminated

ID: DC-2026-07-05-05 · Details: [supporting record](DecisionDetails/DC-2026-07-05-05.md)

Decision: Rename the native app to DevOps Board while preserving its bundle identity, and run automatic inventory only while a Board surface is visible with coalesced refresh work.

Why: The old name no longer matched the product and unconditional 2.5-second inventory polling consumed CPU while hidden. Preserving bundle identity keeps settings, while visibility gating removes idle work.

## DC-2026-07-03-01 — Functional hardening pass across all skills

ID: DC-2026-07-03-01 · Details: [supporting record](DecisionDetails/DC-2026-07-03-01.md)

Decision: Move critical audit/interaction requirements from prose-only instructions into shared deterministic validation with exact canonical labels and scalable synthesis inputs.

Why: Honor-system requirements, mismatched labels, and brittle synthesis could let incomplete audits pass or fail unpredictably. Executable shared contracts make functional expectations repeatable.

## DC-2026-07-02-01 — Dual-runtime skills and mirrored global policy (Codex + Claude Code)

ID: DC-2026-07-02-01 · Details: [supporting record](DecisionDetails/DC-2026-07-02-01.md)

Decision: Keep the operations skills runtime-neutral for Codex and Claude Code, install the same canonical source into both, and mirror shared global safety policy.

Why: Both runtimes act on the same repositories, ports, Docker resources, and databases. Divergent skill copies or policies would defeat coordination and create inconsistent safety boundaries.

## DC-2026-07-02-02 — Coordinator project resource telemetry

ID: DC-2026-07-02-02 · Details: [supporting record](DecisionDetails/DC-2026-07-02-02.md)

Decision: Collect real bounded process-tree CPU/RSS telemetry for managed servers and aggregate it by canonical repository for the Board.

Why: Launcher-only metrics hide the child process that owns a listener or consumes resources. Process-tree evidence makes project load useful without synthetic estimates.

## DC-2026-07-02-03 — Formal Web UI DOM verification

ID: DC-2026-07-02-03 · Details: [supporting record](DecisionDetails/DC-2026-07-02-03.md)

Decision: Add deterministic browser-side geometry, visibility, text-fit, occlusion, media, and overflow checks to complement screenshot review.

Why: Model or human screenshot inspection can miss measurable clipping and hidden controls. DOM evidence can fail these defect classes consistently while visual review handles appearance.

## DC-2026-07-03-02 — Formal web UI verifier recall rework

ID: DC-2026-07-03-02 · Details: [supporting record](DecisionDetails/DC-2026-07-03-02.md)

Decision: Rework the formal verifier around realistic application failures and make must-catch recall plus intentional-pattern false-positive controls part of its self-test.

Why: The prior detector missed most supplied clipping, overlap, off-canvas, broken-media, and invisible-text fixtures. Production-shaped recall controls prevent another implementation-shaped false confidence.

## DC-2026-07-13-03 — DevOps Board uses the Build macOS Apps run contract

ID: DC-2026-07-13-03 · Details: [supporting record](DecisionDetails/DC-2026-07-13-03.md)

Decision: Provide script/build_and_run.sh and the Codex Run action required by Build macOS Apps, with build and provenance packaging before launch.

Why: The app lacked the plugin's operational entrypoint and a stale compile error blocked launch. A repository-owned run contract makes native execution repeatable and attributable.

## DC-2026-07-13-04 — Automatic inventory refresh waits after completion

ID: DC-2026-07-13-04 · Details: [supporting record](DecisionDetails/DC-2026-07-13-04.md)

Decision: Schedule the default 30-second automatic interval only after the preceding load completes; keep explicit refresh immediate and allow a validated custom interval or manual mode.

Why: A real inventory took about 2.39 seconds, so the old 2.5-second start-to-start cadence left almost no idle time and made loading badges permanent. Completion-based scheduling prevents overlap and restores idle periods.

## DC-2026-07-13-05 — Background inventory refresh stays cached and edge-triggered

ID: DC-2026-07-13-05 · Details: [supporting record](DecisionDetails/DC-2026-07-13-05.md)

Decision: Keep cached content visible during scheduled refresh, start/stop polling only on the aggregate surface-visibility edge, avoid refresh-on-menu-open, and coalesce equivalent work.

Why: Duplicate visibility callbacks, popover refreshes, and replacing healthy state with loading caused constant Updating UI. Edge-triggering and retained snapshots keep periodic external reconciliation without disruptive churn.

## DC-2026-07-13-06 — Board inventory transport is bounded, compact, and launch-verified

ID: DC-2026-07-13-06 · Details: [supporting record](DecisionDetails/DC-2026-07-13-06.md)

Decision: Give inventory a dedicated bounded 16 MiB transport, request compact JSON with at most 30 newest history samples per container, decode off the main actor, and verify production launch markers.

Why: Valid multi-megabyte inventory exceeded the ordinary 1 MiB command cap and was truncated into a misleading unavailable state. A bounded inventory-specific path handles real scale without unbounded output or UI blocking.

## DC-2026-07-13-07 — Canonical Board snapshots use an isolated SwiftPM gate

ID: DC-2026-07-13-07 · Details: [supporting record](DecisionDetails/DC-2026-07-13-07.md)

Decision: Keep production free of fixtures and compile canonical Board/menu renderers only in an explicitly gated snapshot target whose provenance binds every renderer input.

Why: Out-of-package renderers and stale sidecars could not prove that committed PNGs represented current production views. An isolated target preserves production purity and source-current evidence.

## DC-2026-07-13-08 — Global attention must identify current evidence and a safe route

ID: DC-2026-07-13-08 · Details: [supporting record](DecisionDetails/DC-2026-07-13-08.md)

Decision: Show global non-nominal status only when current evidence names an actionable resource, failed action, inventory problem, or in-progress operation, and always provide the matching safe route.

Why: Intentionally stopped historical servers triggered a generic attention banner with Refresh even though nothing required intervention. Evidence-specific wording and routes make the status useful and suppress false alarms.
