# DevOps Board

DevOps Board is a native macOS SwiftUI board for truthful local inventory
and actions across coordinator homes, managed dev servers, Docker containers,
port leases, and PostgreSQL protection. The confirmed product and journey
contract is in `PRODUCT.md`; committed visual fixtures and their provenance are
documented in `design-qa.md`.

## Agent workflow

Coding agents must load and follow the Build macOS Apps plugin before building,
testing, packaging, launching, debugging, or automating this app. They must not
take over the user's desktop or replace that workflow with direct Swift/Xcode,
`open`, XCUI, mouse, or keyboard commands. If the plugin is unavailable, the
native validation path remains explicitly pending. The commands below are
developer references, not authorization for an agent to bypass the plugin.

The user-approved Board and menu-bar redesign is implemented in the current
source. Native compilation, XCTest, rendering, accessibility inspection,
packaging, and launch acceptance remain pending until the Build macOS Apps
workflow is available; static or non-native checks do not establish those
results.

## Snapshot evidence

The snapshot tools render the production `BoardView` and `MenuBarRuntimeView`
against deterministic fixture inventory. Accepted canonical provenance must
bind both the PNG and the exact renderer inputs through `source_files` and
`source_sha256`. The unflagged snapshot verifier is therefore the
current-source acceptance gate. Its `--skip-source-freshness` mode is useful
for non-native pixel and geometry diagnostics only and must not be used to
claim that an artifact depicts the current UI. See `design-qa.md` for the
canonical artifact workflow and current pending boundary.

## Build and test

Use the Build macOS Apps plugin's build and test actions. Do not run Swift or
Xcode commands directly from an agent session. The plugin must report the
compiled source identity and XCTest result used by the package/launch gate.

The app requires macOS 14 or newer. Runtime actions also require Python 3 and,
for Docker/PostgreSQL surfaces, a working local Docker CLI. Missing dependencies
are shown as unavailable; they are not replaced by fixture data.

## Package a launchable app

SwiftPM builds a bare executable. The packaging tool creates a standard,
ad-hoc-signed `.app`, validates its plist and signature, and bundles exact
copies of the coordinator and PostgreSQL helper scripts so the app does not
depend on a developer-specific repository path. It also records the verified
pre-sign build-executable SHA-256 together with the exact `Package.swift`, optional
`Package.resolved`, and production `Sources/**/*.swift` paths and hashes. The
runtime provenance also records the DevCoordinator commit/tree and whether
that checkout had tracked changes, binding both bundled skills to one source:

Run `Tools/package_app.py --configuration release --force --json` only inside
that plugin workflow, against the binary the plugin just built and identified.

Default output:

```text
.build/app/DevOpsBoard.app
```

A successful normal build writes a local build sidecar under
`.build/devcoordinator-packaging/<configuration>.json`. `--skip-build` never asks
Swift for a binary path: it reuses only the executable named by that sidecar,
and rejects missing provenance, changed source inputs, or changed executable
bytes. There is deliberately no unprovenanced override. Run once without
`--skip-build` after any production source or package-manifest change.

Launch the packaged app through the plugin and verify that the running
executable path/hash matches the package provenance. Do not launch the bare
SwiftPM executable or use `open` directly from an agent session.

Run the packaging regression test from this directory:

```bash
python3 Tools/self_test_package_app.py
```

That regression suite is Python-only. It uses isolated fake source trees and
binaries, forbids external process launch, and covers missing provenance,
stale source, tampered build and packaged executables, helper tampering,
metadata-only source touches, and safe output-path handling. Native build,
signature, package, and launch acceptance still require the Build macOS Apps
plugin workflow.

The `.app` is a local unsigned-distribution build with an ad-hoc signature. It
is not notarized, sandboxed, or suitable for distribution outside a trusted
development machine without a real signing/notarization pipeline.
