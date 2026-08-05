import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

const UI_ROOT = new URL('../src/ui/', import.meta.url);

async function uiSources() {
  const [app, css, html] = await Promise.all([
    fsp.readFile(new URL('app.js', UI_ROOT), 'utf8'),
    fsp.readFile(new URL('app.css', UI_ROOT), 'utf8'),
    fsp.readFile(new URL('index.html', UI_ROOT), 'utf8'),
  ]);
  return { app, css, html };
}

function extractFunction(source, header) {
  const start = source.indexOf(header);
  assert.notEqual(start, -1, `app.js no longer contains "${header}"`);
  const bodyStart = source.indexOf('{', start + header.length);
  let depth = 0;
  for (let index = bodyStart; index < source.length; index += 1) {
    if (source[index] === '{') depth += 1;
    if (source[index] === '}') depth -= 1;
    if (depth === 0) return source.slice(start, index + 1);
  }
  assert.fail(`unbalanced braces extracting ${header}`);
}

test('Performance owns one reconciled dashboard instead of repeated resource cards', async () => {
  const { app, css, html } = await uiSources();

  assert.match(app, /class:\s*['`]performance-dashboard['`]/,
    'Performance must render one whole-server composition root');
  for (const id of ['perf-summary', 'perf-memory-panel', 'perf-memory-chart',
    'perf-cpu-panel', 'perf-cpu-chart', 'perf-legend']) {
    assert.match(app, new RegExp(`['\"]${id}['\"]`), `${id} must be rendered`);
  }
  assert.doesNotMatch(app, /perf-accounting-note|function performanceAccountingNote\s*\(/,
    'accounting methodology must not return as a standalone warning-style block');
  assert.doesNotMatch(css, /\.perf-accounting-note/,
    'removed accounting-note presentation must not linger in responsive CSS');
  assert.match(css,
    /#perf-residual-diagnostics:not\(\[open\]\)\s*>\s*:not\(summary\)\s*\{\s*display:\s*none;/,
    'closed residual diagnostics must remove non-summary descendants from layout geometry');
  assert.match(app, /['"]data-performance-segment['"]\s*:/,
    'every stacked rectangle must expose a stable semantic segment hook');
  assert.match(app, /role:\s*['"]img['"]/,
    'composition charts must retain an accessible SVG image contract');

  assert.doesNotMatch(app, /function perfCard\s*\(/,
    'the redesign must not retain one full chart card per server/container');
  assert.doesNotMatch(css, /\.perf-grid\s*\{/,
    'the removed per-resource card grid must not remain the responsive structure');
  assert.doesNotMatch(html, /id="sec-usage"|id="usage-body"/,
    'project details belong behind the legend, not in a second long collection');
});

test('Performance exposes the required accounting and residual semantics', async () => {
  const { app } = await uiSources();

  assert.match(app, /Host used[\s\S]{0,50}not immediately available/,
    'whole-host used memory must be labelled as not immediately available');
  for (const copy of [
    'Accounting coverage',
    'Sample skew',
    'Attributed working set',
    'Estimated System & unattributed',
    'Available',
    'Project runtimes',
    'Coordinator control plane',
    'Coordinator background / scheduler',
    'Active test attempts',
    'Developer-account sessions',
  ]) {
    assert.match(app, new RegExp(copy.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      `Performance must explain ${copy}`);
  }
  assert.match(app, /Coordinator \/ control|control-plane \/ other|Control \/ other/i,
    'measured control-plane/other work must remain an explicit reconciliation category');

  assert.match(app, /\.stackMemoryBytes/,
    'the memory stack must use the backend-reconciled value, not an incompatible raw sum');
  assert.match(app, /\.stackCpuPercent/,
    'the CPU stack must use the host-normalized reconciled value');
  assert.match(app, /\.observedMemoryBytes|\.memoryBytes/,
    'observed project memory remains available for coverage and detail');
  assert.match(app, /\.observedCpuPercent|\.cpuPercent/,
    'observed project CPU remains available for coverage and detail');
});

test('host accounting distinguishes additive roots from bounded overlapping drilldowns', async () => {
  const { app } = await uiSources();
  const composition = extractFunction(app, 'function performanceCompositionPanel(model, metric)');
  const diagnostics = extractFunction(app, 'function performanceResidualDiagnostics(model)');
  const diagnosticNames = extractFunction(app, 'function perfDiagnosticCgroupName(group)');
  const diagnosticValues = extractFunction(app, 'function perfDiagnosticValues(group)');
  const chart = extractFunction(app, 'function performanceStackedChart(model, metric, id)');

  assert.match(composition, /memory\s*\?\s*performanceResidualDiagnostics\(model\)\s*:\s*null/,
    'residual evidence must stay locally discoverable from the memory composition');
  assert.match(diagnostics, /id:\s*['"]perf-residual-diagnostics['"]/);
  assert.match(diagnostics, /Host accounting detail/);
  assert.match(diagnostics,
    /Stack categories are added once\.[\s\S]*drilldowns overlap a parent total and add nothing\./,
    'diagnostics must state the additive and non-additive relationships explicitly');
  assert.match(diagnostics, /perf-residual-diagnostics-note/);
  assert.match(diagnostics, /perf-residual-diagnostic/);
  assert.match(diagnostics, /['"]data-performance-diagnostic['"]\s*:/);
  for (const copy of [
    'Project runtimes',
    'Coordinator control plane',
    'Coordinator background / scheduler',
    'Active test attempts',
    'Developer-account sessions',
    'System services',
  ]) {
    assert.match(diagnosticNames, new RegExp(copy.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.match(diagnosticNames, /developer|user session/i,
    'dominant developer/user-session evidence must have a human label');
  assert.match(diagnostics, /shared memory|shmem/i,
    'dominant shared-memory evidence must be discoverable');
  assert.match(diagnostics, /PSS is not inferred/,
    'the UI must not relabel cgroup counters as unavailable PSS telemetry');
  assert.match(diagnosticValues, /['"]Anonymous['"]/);
  assert.match(diagnosticValues, /['"]Kernel['"]/);
  assert.match(diagnosticValues, /['"]Processes['"]/);

  assert.match(chart, /segment\.additive !== false/,
    'the stack must be restricted to explicitly additive categories');
  assert.doesNotMatch(chart, /workingBytes|working_bytes|anonBytes|anon_bytes|shmemBytes|shmem_bytes/,
    'diagnostic counters must never be read directly by the chart');
});

test('project colors are deterministic, collision-free and separated from reconciliation colors', async () => {
  const { app } = await uiSources();
  const paletteMatch = app.match(/const PERFORMANCE_PROJECT_COLORS = \[([\s\S]*?)\];/);
  assert.ok(paletteMatch, 'the repository palette must remain explicit and reviewable');
  const projectColors = paletteMatch[1].match(/#[0-9a-f]{6}/gi) || [];
  assert.ok(projectColors.length >= 12, 'the supported fleet needs at least twelve distinct colors');
  assert.equal(new Set(projectColors.map((color) => color.toLowerCase())).size,
    projectColors.length, 'project palette entries must be unique');

  const rgb = (color) => [1, 3, 5].map((offset) => Number.parseInt(color.slice(offset, offset + 2), 16));
  const distance = (left, right) => Math.hypot(...rgb(left).map((value, index) => value - rgb(right)[index]));
  for (let left = 0; left < projectColors.length; left += 1) {
    for (let right = left + 1; right < projectColors.length; right += 1) {
      assert.ok(distance(projectColors[left], projectColors[right]) >= 50,
        `${projectColors[left]} and ${projectColors[right]} are too similar`);
    }
  }

  for (const fixed of [
    '#16d39a', '#2f81f7', '#b56cff', '#ff8a2a', '#e8eef6',
    '#8bd5ff', '#8056b3', '#68717d', '#27313d',
  ]) {
    assert.match(app, new RegExp(fixed, 'i'), `${fixed} fixed reconciliation color must remain stable`);
    assert.equal(projectColors.some((color) => color.toLowerCase() === fixed), false,
      `${fixed} must not be reused by a repository series`);
  }
  assert.match(app, /function assignPerformanceProjectColors\(segments\)/);
  assert.match(app, /used\.has\(PERFORMANCE_PROJECT_COLORS/,
    'deterministic assignment must resolve key-hash collisions within the visible fleet');
});

test('actionable legend hover and focus emphasize only its exact series', async () => {
  const { app, css } = await uiSources();
  const render = extractFunction(app, 'function renderPerformanceSeriesEmphasis(model, metric)');
  const emphasis = extractFunction(app,
    'function setPerformanceSeriesEmphasis(model, metric, key, source, active)');
  const overlay = extractFunction(app,
    'function renderPerformanceDrilldownOverlay(chart, model, metric, key)');

  assert.match(app, /onpointerenter:\s*\(event\)[\s\S]{0,180}event\.pointerType !== ['"]touch['"]/,
    'touch pointer entry must not create sticky hover emphasis');
  assert.match(app, /const emphasisKey = segment\.key/,
    'every actionable drilldown must retain its exact semantic series key');
  assert.doesNotMatch(app,
    /emphasisKey\s*=\s*['"](?:project-runtimes|developer-sessions)['"]/,
    'a drilldown must never borrow an additive parent series');
  assert.match(app, /['"]data-performance-emphasis-key['"]\s*:\s*emphasisKey/);
  assert.match(app, /setPerformanceSeriesEmphasis\(model, metric, emphasisKey, ['"]hover['"], true\)/);
  assert.match(app, /setPerformanceSeriesEmphasis\(model, metric, emphasisKey, ['"]hover['"], false\)/);
  assert.match(app, /setPerformanceSeriesEmphasis\(model, metric, emphasisKey, ['"]focus['"], true\)/);
  assert.match(app, /setPerformanceSeriesEmphasis\(model, metric, emphasisKey, ['"]focus['"], false\)/);
  assert.match(app, /clearPerformanceSeriesEmphasis\(model, metric\);[\s\S]{0,100}openPerformanceProject/,
    'modal activation must clear transient hover/focus emphasis first');
  assert.match(extractFunction(app, 'function buildPerf(o)'),
    /performanceSeriesEmphasis\.clear\(\)/,
    'section replacement must discard hover state whose DOM may vanish without pointerleave');
  assert.match(emphasis, /emphasis\[source\]/,
    'hover and focus need independent state so one leaving does not clear the other');
  assert.match(render, /state\?\.hover \|\| state\?\.focus/,
    'hover takes temporary precedence while focus remains available as a fallback');
  assert.match(render, /drilldown && !hasDrilldownSeries \? null : requestedKey/,
    'an all-zero drilldown must not dim or falsely highlight the host stack');
  assert.match(render, /querySelectorAll\(['"]\[data-performance-segment\]['"]\)/,
    'emphasis must dim the complete nonmatching stack so tiny projects remain visible');
  assert.match(render, /dataset\.performanceSegment === key/,
    'the selected bars must match through the stable semantic segment key');
  assert.match(render, /is-series-highlighted/);
  assert.match(render, /is-series-dimmed/);
  assert.match(overlay, /observedValue/,
    'non-additive overlays must use retained observed values, never zero stack contributions');
  assert.match(overlay, /data-performance-series-role['"]:\s*['"]drilldown['"]/);
  assert.match(overlay, /data-performance-value['"]:\s*String\(observed\)/);
  assert.match(overlay, /const rectHeight = visibleValue \/ total \* height/,
    'overlay geometry must use the same host-total scale as its legend value');
  assert.match(css, /\.perf-stack-segment\.is-series-highlighted/);
  assert.match(css, /\.perf-drilldown-segment\.is-series-highlighted/);
  assert.match(css, /\.perf-stack-segment\.is-series-dimmed/);
});

test('each composition chart has semantic exact-value data and unambiguous mobile peak labels', async () => {
  const { app, css } = await uiSources();

  assert.match(app, /perf-chart-data/);
  assert.match(app, /['"]data-performance-data-table['"]\s*:/);
  assert.match(app, /['"]data-section-disclosure['"]\s*:/,
    'open chart data must survive ordinary Performance rerenders');
  assert.match(app, /Exact memory sample data/);
  assert.match(app, /Exact CPU sample data/);
  assert.match(app, /perf-chart-data-scroll/,
    'wide exact-value tables need a bounded local scroll container');
  assert.match(app, /perf-chart-data-table/);
  assert.match(app, /['"]data-performance-sample['"]\s*:/);
  assert.match(app, /['"]data-performance-table-segment['"]\s*:/,
    'each exact sample must expose the matching semantic segment identity');
  assert.match(app, /h\(['"]time['"][\s\S]{0,160}datetime/,
    'sample time must use semantic machine-readable local-time markup');

  assert.match(app, /perf-legend-peak/);
  assert.match(app, /perf-legend-mobile-label/);
  assert.match(app, /['"]Peak ['"]/,
    'mobile peak values need visible in-row copy rather than color or position alone');
  assert.match(css, /\.perf-legend-mobile-label\s*\{[^}]*display:\s*none;/s,
    'the compact in-row label must not duplicate the desktop table heading');
  assert.match(css,
    /@media \(max-width: 479px\) \{[\s\S]*?\.perf-legend-mobile-label\s*\{[^}]*display:\s*inline/s,
    'the peak label must become visible at both supported phone widths');
});

test('project and agent-browser legend controls own one stable native dialog and restore focus', async () => {
  const { app, css, html } = await uiSources();
  const open = extractFunction(app, 'function openPerformanceProject(key, trigger)');
  const close = extractFunction(app, 'function closePerformanceProject({ restoreFocus = true } = {})');

  assert.match(html,
    /<dialog id="perf-project-dialog"[^>]*aria-labelledby="perf-project-dialog-title"/,
    'project history must use one labelled native dialog');
  assert.match(html, /id="perf-project-dialog-title"/);
  assert.match(html, /id="perf-project-dialog-body"/);
  assert.match(html,
    /id="perf-project-dialog-close"[^>]*aria-label="Close performance details"/);

  assert.match(app, /performanceProjectKey:\s*null/,
    'selected project identity must live outside the refresh-replaced DOM');
  assert.match(app, /performanceReturnFocus:\s*null/,
    'the exact invoking legend control must be retained for focus restoration');
  assert.match(app, /function openPerformanceProject\(key, trigger\)/);
  assert.match(app, /function renderPerformanceProjectDialog\(\)/);
  assert.match(app, /function closePerformanceProject\(\{ restoreFocus = true \} = \{\}\)/);
  assert.match(open, /\.showModal\(\)/,
    'legend activation must enter a real modal interaction mode');
  assert.match(close, /performanceReturnFocus/);
  assert.match(close, /\.focus\(/,
    'closing the dialog must return focus to the invoking legend control');
  assert.match(app,
    /#perf-project-dialog['"]\)\.addEventListener\(['"]cancel['"][\s\S]{0,180}closePerformanceProject/,
    'Escape must use the same close and focus-restoration path');
  assert.match(app, /perf-legend-button/);
  assert.match(app, /['"]data-performance-key['"]\s*:/);
  assert.match(app, /['"]aria-haspopup['"]:\s*['"]dialog['"]/);
  assert.match(app, /candidate\.project \|\| candidate\.kind === ['"]agent-browsers['"]/,
    'the shared modal must admit the measured non-project browser category');
  assert.match(app, /Last observed work/,
    'browser sessions must use the truthful observation label, never imply human use');
  assert.match(app, /\.slice\(0, 8\)/,
    'browser session rows must stay bounded inside the reusable detail dialog');
  assert.match(app, /Recent cleanup/);
  assert.match(app, /Idle cleanup after/);
  assert.match(css, /\.perf-agent-sessions\s*>\s*ol/);
  assert.match(css,
    /@media \(max-width: 719px\)[\s\S]*?\.perf-agent-sessions\s*>\s*ol\s*\{[^}]*grid-template-columns:\s*minmax\(0, 1fr\)/,
    'session cards must collapse to one bounded column on narrow screens');

  assert.match(css, /#perf-project-dialog\s*\{/,
    'the modal needs an explicit bounded desktop surface');
  assert.match(css, /@media\s*\(max-width:[^)]+\)[\s\S]*\.perf-/,
    'Performance must define a narrow-screen structural adaptation');
});
