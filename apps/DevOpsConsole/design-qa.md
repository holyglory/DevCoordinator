# Design QA — DevOps Console

The source visual truth is the implemented UI contract in
`docs/architecture.md` and the journeys in `docs/journeys.md`. There is no
separate image mockup for this application.

## Canonical evidence

Only deterministic isolated-test-fixture captures are publishable. The
canonical set is intentionally small:

- `Artifacts/Canonical/login-desktop.png` — 1440×900
- `Artifacts/Canonical/login-mobile.png` — 390×844
- `Artifacts/Canonical/projects-desktop.png` — 1440×900
- `Artifacts/Canonical/projects-mobile.png` — 390×844

The login pages come from the real Console authentication surface. The
Projects pages come from the real Console UI running in its hermetic e2e stack,
with a real fixture OIDC session and explicitly isolated, fixed `/api/*`
responses from `Tools/canonical-api-fixtures.mjs`. Fixture records use only
portable `/fixtures` paths and `example.test` identities. They are test
evidence, never deployment inventory or product data.

Every PNG has an adjacent `.provenance.json` sidecar containing its exact
SHA-256, dimensions, viewport, fixture identifier, generator, and hashes for
the UI, fixture, capture, stack, and locked Playwright sources. The repository
artifact guard rejects missing, forged, or mismatched provenance and PNG
metadata.

## Reproduction

Install the repository-locked browser runtime and capture through the isolated
stack:

```sh
npm ci --ignore-scripts --prefix ci/playwright
ci/playwright/node_modules/.bin/playwright install chromium
NODE_PATH="$PWD/ci/playwright/node_modules" \
  node apps/DevOpsConsole/Tools/capture-canonical-artifacts.mjs
```

Validate the capture contract and the complete Console suite:

```sh
node --test apps/DevOpsConsole/test/unit.canonical-artifacts.test.mjs
python3 scripts/self_test_public_artifact_guard.py
python3 scripts/public_artifact_guard.py --repo .
npm test --prefix apps/DevOpsConsole
```

Do not commit screenshots from a live Console, coordinator home, deployment,
or developer browser session. Live production verification belongs in private
runtime evidence; it must not become a public inventory image.
