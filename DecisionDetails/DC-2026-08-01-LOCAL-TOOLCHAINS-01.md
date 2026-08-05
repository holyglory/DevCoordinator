# Tests may read lock-bound local dependencies and toolchains

## Confirmed assumptions

This decision applies the user-confirmed [single-developer security assumptions](../security-assumptions.md): local Unix accounts are attribution and crash domains for one developer, not mutually hostile tenants; other local accounts are not credible adversaries; non-secret same-host coordination needs no local-account authorization gate; credentials and external identity assertions remain secret; and path escape, unintended writes, runaway processes, and cross-project interference remain credible failures.

## Selected contract

- A transient test still runs as the repository's attributed UID/GID and in its repository-specific accounting slice.
- Immutable source remains limited to tracked, staged, unstaged, and bounded non-ignored untracked repository content. Ignored dependency installations are not vendored into that source.
- For a target that uses a standard repository Python environment or working-directory Node installation, the Coordinator derives the dependency root itself. It accepts no repository-authored host mount path, requires the applicable dependency-lock digest to equal the selected snapshot, records a bounded installation-manifest identity, and maps the exact root read-only to the same relative path in the private attempt materialization.
- For locked .NET targets, the Coordinator deterministically selects one complete server-local NuGet cache containing the exact locked package IDs and versions. The repository owner's cache is preferred, but another enrolled local developer account's complete cache is valid because the confirmed host trust model treats those accounts as one developer. Only the selected cache is exposed read-only at a private attempt path.
- Homes remain hidden wholesale. When the declared executable resolves through a package-manager alias into a versioned toolchain below another trusted local home, only the exact versioned package-manager directory required by the recorded interpreter identity is bind-mounted read-only. The runtime supplies the local developer groups needed to read an exact exposed root; group membership is not an admission or authorization gate.
- Only the authority-bound execution root, attempt output, the exact resolved toolchain, and explicitly provisioned fixture or credential paths receive the access required by the runner. Existing process, network, TTL, lifecycle, generation, and cleanup boundaries remain.
- The dependency-lock identity already participates in immutable source provenance and plan/run deduplication. The resolved descriptor also binds the selected installation manifest, source identity, and external interpreter identity; launch revalidates them against original and materialized source immediately before exposing the ignored installation.
- .NET receives a runner-owned writable CLI home and deterministic first-use/workload-update settings. SDK/workload readiness is checked within the caller-selected execution deadline before project execution, readiness output is bounded while fully drained, and a process-bootstrap failure or pre-test exit without a reporter publishes bounded infrastructure evidence rather than an invented test assertion failure.
- A systemd `deactivating` unit remains supervised until genuinely terminal evidence exists.

## Rejected alternatives

- Hiding `/home` with no exact toolchain exception breaks ordinary uv-created interpreter links in this deployment.
- Recreating each Python, Node, and .NET dependency environment for every attempt repeats expensive work, blocks offline attempts, and races active agents.
- Copying ignored environments into immutable source makes snapshots large and falsely treats generated dependencies as authored source.
- Falling back from a declared repository environment to `/usr/bin` can launch a different dependency graph and therefore is not valid evidence.
- Making home trees visible or writable is unnecessary; dependency roots and resolved toolchains need read/execute access, not broad home access or mutation authority.

## Verification

Inspect the transient unit contract for `ProtectHome=tmpfs`, exact source-to-materialization read-only mappings for the derived dependency roots, narrow local-developer supplementary groups, one exact external toolchain bind, no whole-home bind or broad `/home` write path, and the existing exact execution/output write paths. Execute real immutable Python and Node targets that load dependencies from ignored roots under the attributed repository UID. Change, remove, escape, substitute, or retarget each root, installation manifest, interpreter identity, or source lock and require bounded pre-project infrastructure evidence. Add an unrelated package to a shared cache and prove it does not invalidate the selected repository dependency identity. Exercise a clean-home .NET target with a complete selected cache, matching SDK/workload readiness, caller-selected deadline, and TRX; then exercise missing locked packages, unavailable SDK/workload, and excessive readiness output and require bounded infrastructure evidence without an ordinary test-failure claim. Observe `deactivating` before final inactive/failed state and prove the harness neither cleans up nor terminalizes early.
