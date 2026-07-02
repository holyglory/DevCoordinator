# Decision History

## 2026-07-02 - Coordinator project resource telemetry

Decision: The Codex dev coordinator inventory emits real per-server process-tree CPU/RSS telemetry and project-level resource rollups, and CodexOpsConsole displays those rollups by repo.

Why: Managed dev servers often launch child processes that own the actual listener and resource usage. A launcher PID alone can hide runaway Next/Vite/node child processes, especially across multiple Codex/Parall coordinator homes.

Result: Inventory now includes `process_usage` per server and `project_usage` per repo. The console discovers coordinator homes, merges read-only inventory, shows project load, and flags high-load projects in the status bar.

## 2026-07-02 - Formal Web UI DOM verification

Decision: Holy Skills now includes `formal-web-ui-verification`, a Playwright-driven skill that injects deterministic JavaScript into rendered web pages to measure DOM geometry, computed styles, text fit, occlusion, media health, area-of-interest boundaries, document overflow, and visible scrollbars.

Why: UI implementation and audit workflows were still able to miss software-detectable defects such as cropped text, hidden controls, unintended overlap, off-canvas interactive elements, broken media, and invisible text. Screenshot review remains useful, but these failure classes need formal browser-side measurements that can fail delivery gates without relying on model vision.

Result: The verifier defaults to critical-only failure for low-noise delivery checks and warning-level reporting for softer risks. It supports explicit route configs, coordinator current-URL smoke checks, AOI/ignore/allow attributes, JSON/Markdown reports, and mandatory visible scrollbar inventory. Existing UI audit prompts now require the verifier whenever a safe web render path exists, and the app-wide Codex instructions require formal web UI verification after material web UI changes.
