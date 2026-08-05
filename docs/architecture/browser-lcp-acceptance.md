# Release-bound browser LCP acceptance

Browser performance is a cutover acceptance input, not a claim inferred from
the HTTP continuity probe. The continuity probe proves availability and TTFB;
this contract separately proves native Chromium Largest Contentful Paint for
the authenticated Console and retained Tests projection.

The immutable producer is `devcoordinator-browser-lcp`. It has four commands:

- `runtime-lock` records the exact Node executable, Playwright and
  Playwright-core trees, package lock, and real browser executable with their
  versions and SHA-256 digests. It does not launch Playwright.
- `produce` checks the immutable release and live HTTPS `/healthz` identity,
  launches the locked browser driver, validates ten samples, HMAC-seals the
  result, and publishes one root-private mode-0600 file atomically.
- `verify` revalidates the release, runtime, signature, TTL, samples, and the
  still-live edge release and generation.
- `consume` performs the same checks and creates one atomic consumption marker.
  A second use is a replay failure.

The required samples are the Console shell and `/#/tests` at widths 320, 390,
768, 981 and 1440. Every sample must be authenticated, retain its exact URL,
have a successful navigation, contain a native LCP entry below 1000 ms, and—on
Tests—render a nonempty `delivery.state=retained` fleet projection without a
loading or failure placeholder.

Authentication storage state and the signing key remain separate root-private
inputs. Neither their paths nor their contents, cookies, session identity,
response bodies, page text, browser logs, or arbitrary error strings enter the
attestation. The evidence contains only fixed state labels, timings, release
and runtime identities, and digests.

## Immutable release packaging hook

`scripts/install_availability_release.py` must make these exact additions in
the same release transaction as the rest of the availability graph:

1. Add `apps/DevOpsConsole/Tools/browser-lcp-producer.mjs` and
   `scripts/browser_lcp_acceptance.py` to `SOURCE_FILES`. Do not package the
   unrelated canonical-artifact tools.
2. Add wrapper `devcoordinator-browser-lcp` with kind `python`, target
   `scripts/browser_lcp_acceptance.py`, and no prefix arguments.
3. Add the `browser_lcp_acceptance` release capability, requiring all of:
   `bin/devcoordinator-browser-lcp`, `scripts/browser_lcp_acceptance.py`, and
   `apps/DevOpsConsole/Tools/browser-lcp-producer.mjs`.
4. Include `scripts/self_test_browser_lcp_acceptance.py` in repository
   validation, but not in the production release.

The validator intentionally refuses a release without that capability and
requires wrapper mode 0555 plus source and driver mode 0444.

The separate root-only immutable `devcoordinator-browser-runtime` transaction
copies the exact pre-populated package tree, Node executable, and complete real
browser directory bundle into a root-owned, non-writable, content-addressed
runtime. It never
runs npm, downloads a browser, or accesses the network. The source tree must
already contain the exact `package.json`, lockfile, `playwright` tree and
`playwright-core` tree. The browser root must contain its executable and every
runtime library/resource it needs. All inputs must be root-owned and
non-writable by group/other.

```bash
sudo /opt/devcoordinator/releases/<release-digest>/bin/devcoordinator-browser-runtime plan \
  --package-root /root/staged-playwright \
  --node /root/staged-node/bin/node \
  --browser-root /root/staged-chromium/chrome-linux \
  --browser-executable-relative chrome \
  --output /var/lib/devcoordinator/browser/runtime-plan.json
sudo /opt/devcoordinator/releases/<release-digest>/bin/devcoordinator-browser-runtime stage \
  --plan /var/lib/devcoordinator/browser/runtime-plan.json \
  --runtime-lock /var/lib/devcoordinator/browser/runtime-lock.json \
  --attestation /var/lib/devcoordinator/browser/runtime-stage.json
sudo /opt/devcoordinator/releases/<release-digest>/bin/devcoordinator-browser-runtime verify \
  --plan /var/lib/devcoordinator/browser/runtime-plan.json \
  --runtime-lock /var/lib/devcoordinator/browser/runtime-lock.json \
  --attestation /var/lib/devcoordinator/browser/runtime-stage.json
```

`plan` seals every source inode/metadata identity, every package and browser
bundle file, the total byte count, and the destination content digest. `stage`
copies and hashes each source through the same open file descriptor, fsyncs
files/directories and the atomic rename, safely removes only recognized private
stale partials, and refuses to replace a corrupt published digest. `verify`
enumerates the complete final tree and re-runs the browser runtime-lock
verifier. The destination is fixed at
`/opt/devcoordinator-browser-runtimes`, with a root:root-only contract; there is
no runtime-root or authority-GID override. The runtime lock names the copied
Node and browser executables rather than mutable launcher shims. This
runtime remains outside the application release so browser package updates are
an explicit administrator-controlled input with their own digest.

## Cutover hook

Browser evidence can only be produced after the candidate release is live, so
it gates activation completion rather than the publication switch itself. The
activation transaction should perform this order:

1. Switch publication and keep the existing uninterrupted HTTP/WebSocket
   continuity collector running.
2. Verify candidate health and the post-v13 owner-scoped inventory gate.
3. Run the immutable `devcoordinator-browser-lcp produce` with the cutover UUID
   as its operation ID and fixed root-private runtime-lock, storage-state,
   signing-key and output paths.
4. Call `consume_attestation` from `scripts/browser_lcp_acceptance.py` with the
   same release, cutover UUID and exact Console URLs. The consumption path must
   be deterministic inside the cutover evidence directory, not caller-chosen.
5. Add `browser_lcp_attestation_sha256` and
   `browser_lcp_consumption_sha256` to `ACTIVATION_FIELDS`; seal and record the
   activation only after both files are durable. Recovery observes a matching
   existing consumption marker and advances the pending journal phase; it must
   never call `consume` a second time.
6. Copy the same two digests into the live rollback rehearsal. The rehearsal
   must preserve them while it advances the expected edge generation through
   rollback and reactivation.
7. Require those two exact digests again before retention. Retention rechecks
   the signed attestation, runtime lock, one-shot consumption marker, current
   release, and the reactivated publication generation. A stale, partial,
   forged, wrong-release, wrong-generation, runtime-drifted or replayed proof
   leaves the cutover unretained and fail closed.

`bind_browser_lcp_acceptance` owns a cutover-bound journal with
`produce_intent`, `attestation_verified`, `consumption_intent`, and `complete`
phases. Evidence filenames are derived from the cutover UUID. Recovery of an
uncertain consume reply validates the existing marker and never calls the
one-shot consumer again. A browser failure does not roll project traffic back
automatically; the candidate remains live and observable while activation,
live-rehearsal completion, and retention remain fail closed.

No browser run was performed while adding this contract. Live production of
the attestation still requires the user's explicit Playwright permission.
