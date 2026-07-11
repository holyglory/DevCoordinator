# DevOps Board visual QA

The committed screenshots are test artifacts, not production inventory
captures. Both snapshot tools render the production `BoardView` or
`MenuBarRuntimeView` with deterministic, isolated fixture records under
`/fixtures` and live loading disabled. They do not call the coordinator,
Docker, PostgreSQL, or any project-local service while generating the images.

## Canonical artifacts

The small canonical set lives in `Artifacts/Canonical/`:

- `dev-servers.png` — desktop board, Dev Servers tab, 1440 × 1024.
- `docker-board.png` — desktop board, Docker tab, 1440 × 1024.
- `databases.png` — desktop board, Databases tab, 1440 × 1024.
- `menu-action-error.png` — menu-bar error state, 430 × 600.

Every PNG has an adjacent `.provenance.json` file. For acceptance as current,
the sidecar must identify the fixture and generator; record the PNG dimensions
and SHA-256 digest; and name and hash the exact portable renderer inputs as
`source_files` and `source_sha256`. `scripts/public_artifact_guard.py` rejects a
publishable PNG with sensitive metadata, missing provenance, or provenance that
does not match the bytes and dimensions. `scripts/verify_snapshot_artifacts.py`
additionally rejects a missing or stale renderer-source binding, transparency,
mostly blank renders, or missing content in required header, sidebar, table,
inspector, and footer regions.

The guard cannot OCR arbitrary pixels. The stronger prevention boundary is therefore at generation time: the snapshot executables receive only checked-in neutral fixture strings, strip text/time/EXIF PNG chunks, and never load live inventory. Reviewers should still inspect newly generated images before accepting them.

## Regenerate

Agents regenerate the native fixtures only through the Build macOS Apps plugin.
The plugin workflow must compile the checked-in snapshot tools, render the
`servers`, `docker`, `databases`, and menu `error` fixture states into the four
canonical paths above, and inspect the results without taking over the user's
desktop. Direct `swift`, `swiftc`, `xcodebuild`, `open`, XCUI, mouse, or keyboard
substitutes are not an accepted agent workflow. If the plugin is unavailable,
regeneration remains pending rather than being approximated through another
surface.

Generated working images belong under `.build/qa/` unless they replace one of the four reviewed canonical artifacts. Do not commit screenshots made from a developer's live coordinator state, local project names, home directory, logs, secrets, or databases.

## Verify

From the repository root:

```sh
python3 scripts/self_test_public_artifact_guard.py
python3 scripts/self_test_snapshot_artifacts.py
python3 scripts/public_artifact_guard.py
python3 scripts/verify_snapshot_artifacts.py --skip-source-freshness

# Current-source acceptance, after native regeneration:
python3 scripts/verify_snapshot_artifacts.py
```

The `--skip-source-freshness` invocation is a structural pixel/geometry check;
it explicitly does not claim that the PNGs match current SwiftUI source. The
unflagged invocation is the current-source acceptance gate. At this closeout,
the four committed PNGs pass the structural check, but their sidecars predate
the exact renderer-source binding and the unflagged verifier rejects all four.
Native regeneration through Build macOS Apps remains pending.

The complete `scripts/validate.py` gate includes native Swift work and agents
must therefore run that complete gate through the Build macOS Apps workflow.
The Python commands above are safe non-native artifact checks, but they do not
replace the plugin's build, XCTest, render, inspection, packaging, and launch
evidence.

Also inspect each regenerated canonical image at its native dimensions. Confirm that the intended tab/error state is visible, primary content is not clipped, controls do not overlap, and all displayed records are clearly neutral fixture records.

## Artifact retention policy

The previous iterative screenshot series was removed because it mixed redundant intermediate states with captures derived from live local inventory. Git history is intentionally left unchanged; this policy applies to the current tree and future commits. Keep only the minimal reviewed canonical set above, replacing files in place when visual behavior changes.
