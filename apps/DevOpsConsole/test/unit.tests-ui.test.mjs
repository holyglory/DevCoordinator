import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

const UI = new URL('../src/ui/', import.meta.url);

test('Tests destination leads with fleet awareness and opens repository detail on demand', async () => {
  const [html, js, css] = await Promise.all([
    fsp.readFile(new URL('index.html', UI), 'utf8'),
    fsp.readFile(new URL('app.js', UI), 'utf8'),
    fsp.readFile(new URL('app.css', UI), 'utf8'),
  ]);
  assert.match(html, /data-nav="tests">Tests/);
  const assetVersion = createHash('sha256')
    .update(css)
    .update('\0')
    .update(js)
    .digest('hex')
    .slice(0, 12);
  assert.match(html, new RegExp(`/app\\.css\\?v=${assetVersion}`));
  assert.match(html, new RegExp(`/app\\.js\\?v=${assetVersion}`));
  assert.match(html, /data-page="performance"[\s\S]*href="#\/tests">Test dashboards<\/a>/,
    'Performance must disclose where test-run dashboards live');
  assert.match(html, /data-page="tests"/);
  assert.ok(html.indexOf('id="tests-h"') < html.indexOf('id="tests-body"'));
  assert.match(html, /Fleet-wide test coverage, freshness and efficiency/);
  assert.match(html, /id="tests-search"/);
  assert.match(html, /id="test-detail-dialog"/);
  assert.match(html, /role="tablist" aria-label="Repository test information"/);
  assert.match(html, /data-test-detail-tab="overview"/);
  assert.match(html, /data-test-detail-tab="runs"/);
  assert.match(html, /data-test-detail-tab="setup"/);
  assert.match(html, /id="test-detail-body"[^>]*role="tabpanel"[^>]*aria-labelledby="test-detail-tab-overview"/,
    'repository test tabs must label one explicit tab panel');
  assert.match(html, /id="test-detail-tab-runs"[^>]*tabindex="-1"/);
  assert.match(html, /id="test-run-dialog"/);
  assert.match(html, /id="test-run-source"/);
  assert.match(html, /id="test-run-target-field"/);
  assert.match(html, /id="test-run-targets"/);
  assert.match(html, /id="tests-body" class="sec-body" aria-live="off"/,
    'fleet polling must not repeatedly announce thousands of ordinary test updates');
  assert.doesNotMatch(`${html}\n${js}`, /Waiting for test telemetry/,
    'initial loading must stay visual and must not announce non-actionable status copy');
  assert.match(js, /function loadTests\(/);
  assert.match(js, /function loadTestDetail\(/);
  assert.match(js, /function loadTestRuns\(/);
  assert.match(js, /function loadTestSetup\(/);
  assert.match(js, /function loadTestRunEvidence\(/);
  assert.match(js, /testRunEvidenceContent[\s\S]*?\]\.filter\(Boolean\)/,
    'optional evidence nodes must be removed before replaceChildren can stringify them');
  assert.match(js, /function testRunMemoryWait\(/);
  assert.match(js, /function testRunMemoryWaitLabel\(/);
  assert.match(js, /Waiting for memory/);
  assert.match(js, /testRunEvidenceFact\('Peak memory', peakMemory\)/);
  assert.match(js, /testRunEvidenceFact\('CPU time', cpuTime\)/);
  assert.match(js, /testRunEvidenceFact\('Measurements', testRunMeasurementCoverage\(usage\)\)/,
    'empirical resource evidence must remain behind the expanded run disclosure');
  assert.doesNotMatch(js, /summary\.aggregate_test_seconds \?\? run\.aggregate_test_seconds \?\? 0/,
    'missing test-time evidence must not be rendered as a measured zero');
  assert.match(js, /function loadTestRepositories\(/);
  assert.match(js, /\/api\/tests\/repositories/);
  assert.match(js, /\/api\/tests\/fleet\?hours=/);
  assert.match(js, /metricTestRepositories/);
  assert.match(js, /\/api\/tests\?project=/);
  for (const promisedView of [
    'Testing time by repository', 'Fleet load & queue', 'Needs attention',
    'Throughput & efficiency', 'Failure & flake trend', 'Largest dynamics',
    'Top actionable regression',
  ]) {
    assert.ok(js.includes(promisedView), promisedView);
  }
  assert.match(js, /function testHeatColor\(seconds\)/);
  assert.match(js, /minutes <= 60/);
  assert.match(js, /minutes <= 120/);
  assert.match(js, /Aggregate test time may exceed 60m when tests run in parallel/);
  assert.match(js, /More than 60 test-minutes in one hour means tests ran in parallel/);
  assert.match(js, /function testFleetMatrix\(/);
  assert.match(js, /function testFleetLocalHourSlots\(/);
  assert.match(js, /hourStartsByLocalHour\[date\.getHours\(\)\]\.push\(hourStart\)/,
    'UTC fleet buckets must be assigned to the browser-local clock hour');
  assert.match(js, /function testFleetLocalCell\(/);
  assert.match(js, /combined\.test_seconds \+= Number\(cell\.test_seconds \|\| 0\)/,
    'duplicate local hours at a daylight-saving transition must be combined');
  const fleetMatrixSource = js.slice(js.indexOf('function testFleetMatrix('), js.indexOf('function testFleetMobileList('));
  assert.doesNotMatch(fleetMatrixSource, /has-(?:failure|test-failure|infrastructure)|icon\('warn'\)/,
    'fleet cells must encode only test intensity, not individual error signals');
  assert.doesNotMatch(fleetMatrixSource, /host_memory|Waiting for memory|testRunMemoryWait/,
    'scheduler waits must not alter heatmap intensity encoding');
  assert.match(fleetMatrixSource, /'data-test-failures': failures/);
  assert.match(fleetMatrixSource, /'data-test-infrastructure': infrastructureFailures/,
    'the on-demand tooltip must retain diagnostics without marking the heatmap');
  const repositoryHeatmapSource = js.slice(js.indexOf('function testHeatmap('), js.indexOf('function testSeries('));
  assert.doesNotMatch(repositoryHeatmapSource, /has-failure|icon\('x'\)/,
    'repository heatmap cells must also remain an intensity-only encoding');
  assert.match(js, /function testHeatTooltipFact\(label, value\)/);
  assert.match(js, /testHeatTooltipFact\('Tests'/);
  assert.match(js, /testHeatTooltipFact\('Test failures'/);
  assert.match(js, /testHeatTooltipFact\('Infrastructure'/,
    'exact test diagnostics belong in the hover, focus and touch popup');
  assert.match(js, /Aggregate test-minutes by local hour/);
  assert.match(js, /from 00:00 through 23:00/);
  assert.match(js, /'data-test-local-hour': localHour/);
  assert.match(js, /const period = testFleetLocalPeriod\(\{ hourStarts: \[hourStart\] \}\)/,
    'fleet capacity exact values must use the same browser-local timestamp formatter');
  assert.match(js, /bar\.dataset\.testSourceHour = hourStart/);
  assert.match(js, /\['Hour \(local\)', 'Test time', 'Tests', 'Test failures', 'Infrastructure failures', 'Queue P95'\]/,
    'fleet exact-value disclosures must keep assertion and infrastructure failures separate');
  assert.match(js, /testFleetLocalHourSlots\(state\.testsFleet\)\.map\(\(slot\) =>/,
    'repository day detail must use the ordered local-hour slots');
  assert.match(js, /Repository test activity by local hour, from 00:00 through 23:00/);
  assert.match(js, /function testFleetMobileList\(/);
  assert.match(js, /function openTestRepository\(/);
  assert.match(js, /if \(testDetailNarrowViewport\.matches\) dialog\.showModal\(\);[\s\S]*else dialog\.show\(\);/,
    'desktop repository detail must preserve the live fleet while mobile keeps a modal full-screen sheet');
  assert.match(js, /document\.documentElement\.classList\.add\('test-detail-open'\)/);
  assert.match(js, /function testDetailHealthTrends\(/);
  assert.match(js, /class: 'test-detail-regression-facts'/);
  assert.match(js, /function renderTestDetail\(/);
  assert.match(js, /state\.testsFleetStale/);
  assert.match(js, /state\.testsFleetStale = false;[\s\S]*?state\.testsError = null;/,
    'a successful warm retained response must not be presented as stale or actionable');
  assert.match(js, /catch \(err\) \{[\s\S]*?state\.testsFleetStale = Boolean\(state\.testsFleet\);/,
    'a failed refresh must keep prior fleet content and expose its stale state locally');
  assert.match(js, /retained\.hidden = !state\.testsFleetStale;/,
    'the retained notice must reflect a real failed refresh, not cache delivery alone');
  assert.doesNotMatch(js, /retained\.hidden = [^;]*delivery\?\.state === 'retained'/,
    'ordinary warm-cache delivery must never unhide the retained notice');
  assert.match(html, /Latest refresh failed — showing last available data/);
  assert.match(js, /function testLocalFailure\(/);
  assert.doesNotMatch(js, /showBanner\(err, \(\) => loadTests/,
    'test-plane failures must stay inside Tests instead of disrupting the global Console banner');
  assert.doesNotMatch(js, /showBanner\(err, \(\) => loadTestDetail/,
    'repository-stat failures must stay inside the repository detail view');
  const attentionSource = js.slice(js.indexOf('function testFleetAttention('), js.indexOf('const testDetailNarrowViewport'));
  assert.doesNotMatch(attentionSource, /host_memory|Waiting for memory|testRunMemoryWait/,
    'ordinary memory waits must not become fleet-wide attention');
  assert.match(js, /testAttentionCount/);
  assert.match(js, /item\.severity === 'critical' \|\| item\.severity === 'error'/,
    'the Tests badge must represent actionable conditions, not healthy run volume');
  assert.doesNotMatch(js, /const running = Number\(fleet\.summary\?\.running_count/,
    'thousands of ordinary running tests must not inflate the navigation badge');
  assert.match(js, /id: 'test-detail-runs-panel'/);
  assert.match(js, /class: 'test-run-row'/,
    'individual run evidence must be disclosed only on demand');
  assert.match(js, /class: 'test-run-evidence'/);
  assert.match(js, /run\.state === 'queued'[\s\S]*testRunMemoryWaitLabel\(testRunMemoryWait\(run\)\)/,
    'memory waits belong only to queued repository run cards');
  assert.match(js, /selectTestDetailTab\('runs'\)/,
    'individual run evidence must remain behind an explicit repository-detail tab');
  assert.match(js, /\/api\/tests\/repositories\/\$\{encodeURIComponent\(repoId\)\}\/runs\//,
    'run detail and operations must remain scoped by repository before lookup');
  assert.match(js, /\/failures\?limit=3/);
  assert.match(js, /\/artifacts\?limit=12/);
  assert.match(js, /if \(event\.currentTarget\.open\) loadTestRunEvidence/,
    'failure and artifact reads must start only after the user expands a run');
  assert.match(js, /function renderTestSetupTab\(/);
  assert.match(js, /Capabilities & fixtures/);
  assert.doesNotMatch(js, /Network and fixture capabilities are administrator-clamped/,
    'Setup must not imply that repository resource declarations are enforced quotas');
  assert.match(js, /const operationId = state\.testsPlanOperationId \|\| crypto\.randomUUID\(\);[\s\S]*state\.testsPlanOperationId = operationId;[\s\S]*operation_id: operationId/,
    'plan preview retries must preserve one caller-generated idempotency UUID');
  assert.match(js, /if \(plan\.operation_id !== operationId\)/,
    'the Console must reject a contradictory planning-operation identity');
  assert.match(js, /function testSetupTargetEntries\(/);
  assert.doesNotMatch(js, /administrator grant required|missing sealed capabilities/i,
    'repository test setup must not expose the removed capability-grant model');
  assert.match(js, /\/api\/tests\/repositories\/\$\{encodeURIComponent\(project\)\}\/setup/);
  assert.match(js, /new URLSearchParams\(\{ repo_id: project, limit: '50' \}\)/);
  assert.match(js, /\['ArrowLeft', 'ArrowRight', 'Home', 'End'\]/,
    'repository detail tabs must support the keyboard tab pattern');
  assert.match(js, /data-test-focus-key/);
  assert.match(js, /restore\?\.focus\(\{ preventScroll: true \}\)/,
    'background refresh must preserve the focused fleet cell or repository');
  assert.match(js, /details\[open\]\[data-test-disclosure\]/,
    'repository and fleet refreshes must preserve on-demand disclosures');
  assert.match(js, /request !== state\.testsDetailRequest \|\| project !== state\.testsProject/,
    'late repository responses must not render beneath a newly selected repository');
  assert.match(js, /state\.testsDetailLoadingKey === queryKey/,
    'only an identical repository-period request may be coalesced');
  assert.match(js, /state\.testsRenderSignature === renderSignature/,
    'unchanged fleet polling must retain the mounted UI instead of blinking it');
  assert.match(js, /const TESTS_POLL_MS = 5000/);
  assert.match(js, /setInterval\(refreshTestsInPlace, TESTS_POLL_MS\)/,
    'the open Tests route must refresh independently of unrelated inventory polling');
  assert.match(js, /window\.addEventListener\('focus', refreshTestsInPlace\)/);
  assert.match(js, /window\.addEventListener\('online', refreshTestsInPlace\)/,
    'focus and connectivity recovery must promptly refresh retained fleet data');
  assert.match(js, /setAttribute\('aria-labelledby', `test-detail-tab-\$\{tab\}`\)/,
    'the shared dynamic tab panel must follow the selected tab label');
  assert.match(js, /`\$\{attention\.length\} current`/,
    'Needs attention must report the complete issue count');
  assert.match(js, /`Show \$\{remaining\.length\} more`/,
    'the bounded attention list must expose every remaining issue on demand');
  assert.match(js, /\/api\/tests\/plan/);
  assert.match(js, /\/api\/tests\/runs/);
  assert.match(js, /function testRunsNextCursor\(/);
  assert.match(js, /query\.set\('after', after\)/);
  assert.match(js, /data-test-runs-load-more/);
  assert.match(js, /loadTestRuns\(\{ append: true \}\)/,
    'run history must expose cursor-backed progressive disclosure');
  assert.match(js, /function loadTestRunTargets\(/);
  assert.match(js, /requested_targets: requestedTargets/,
    'manual runs may submit only selected manifest target names');
  assert.match(js, /intent === 'manual' \? \{ requested_targets: requestedTargets \} : \{\}/,
    'non-manual intents must not accept browser-selected targets');
  assert.match(js, /\/api\/tests\/repositories\/\$\{encodeURIComponent\(repoId\)\}\/sources/,
    'source choices must come from the server-authorized source catalog');
  assert.match(js, /source: source\.selector/,
    'planning must carry only the exact typed selector returned by the server');
  assert.match(js, /sourceKey\(plan\.source_selector\) !== sourceKey\(source\.selector\)/,
    'the preview must reject a contradictory source identity');
  assert.match(js, /state\.testsRunSourceSelections\.set/,
    'repository source choice must survive background rendering and dialog reopen');
  assert.match(js, /repo_id: state\.testsPlan\?\.repository_id \?\? state\.testsPlan\?\.repo_id/,
    'submission must remain bound to the immutable repository returned by planning');
  assert.match(js, /class: 'test-summary-compact'/);
  assert.match(js, /function testRepositoryState\(repository\)/);
  assert.match(js, /function normalizeTestFleetSemantics\(fleet\)/);
  assert.match(js, /repository\.state !== 'failing'/);
  assert.match(js, /testFailures > 0 \|\| infrastructureFailures <= 0/,
    'only infrastructure-only legacy failures may be reclassified');
  assert.match(js, /state\.testsFleet = normalizeTestFleetSemantics\(fleet\)/,
    'retained and fresh schema-2 fleet payloads must share one semantic normalization path');
  assert.match(js, /label = 'Could not run'/,
    'infrastructure and setup failures must not be presented as test assertion failures');
  assert.match(js, /label = 'Tests failed'/,
    'test assertion failures must have an explicit outcome label');
  assert.match(js, /summary\.infrastructure_failure_count/);
  assert.match(js, /summary\.test_failure_count/);
  assert.match(js, /return `\$\{fmtTestCount\(attempts\)\} \$\{attempts === 1 \? 'attempt' : 'attempts'\}`/,
    'a failed pre-test attempt must replace the misleading zero-minute metric');
  assert.match(js, /'data-test-infrastructure': infrastructureFailures/,
    'fleet heat cells must expose infrastructure events separately from test failures');
  assert.match(js, /class: `test-heat-hour/);
  assert.match(js, /role: 'tooltip'/);
  assert.match(js, /data-test-seconds/);
  assert.match(js, /onpointerenter: .*showTestHeatTooltip/);
  assert.match(js, /onclick: .*togglePinnedTestHeatTooltip/);
  assert.match(js, /'aria-pressed': 'false'/,
    'hour cells must expose their pinned exact-value state');
  assert.match(js, /event\.key === 'Escape' && pinnedTestHeatTooltipTarget/,
    'a pinned exact value must be dismissible from the keyboard');
  assert.match(js, /bar\.dataset\.testTooltipDetail/,
    'the fleet load chart must expose exact hourly load and queue values');
  assert.match(js, /bar\.addEventListener\('focus', \(\) => showTestHeatTooltip\(bar\)\)/);
  assert.match(js, /function testTrendPoint\(/);
  assert.match(js, /node\.addEventListener\('pointerenter', \(\) => showTestHeatTooltip\(node\)\)/);
  assert.match(js, /node\.addEventListener\('focus', \(\) => showTestHeatTooltip\(node\)\)/);
  assert.match(js, /node\.addEventListener\('click', \(\) => togglePinnedTestHeatTooltip\(node\)\)/,
    'trend points must disclose exact values by pointer, keyboard focus and touch');
  assert.match(js, /testChartDataDisclosure\('Hourly fleet data'/);
  assert.match(js, /testChartDataDisclosure\('Daily trend data'/,
    'charts must provide an on-demand exact-value data table');
  assert.match(js, /stats\.hourly/);
  assert.match(js, /stats\.comparison_summary/);
  assert.match(js, /stats\.previous_daily/);
  assert.match(js, /stats\.dynamics/);
  assert.match(js, /cell\.dataset\.label = headers\[index\]/);
  assert.match(js, /cell\.setAttribute\('aria-label'/);
  assert.match(css, /\.test-table td::before/);
  assert.match(css, /content: attr\(data-label\)/);
  assert.match(css, /\.test-heat-scroll \{ max-width: 100%; overflow-x: clip/);
  assert.match(css, /\.test-heatmap \{ width: 100%; min-width: 0/);
  assert.match(css, /\.test-heat-tooltip \{/);
  assert.match(css, /\.test-heat-tooltip\[hidden\] \{ display: none; \}/);
  assert.match(css, /\.test-trend-point:hover, \.test-trend-point:focus/);
  assert.match(css, /\.test-runs-pager \{/);
  assert.match(css, /\.test-local-failure \{/);
  assert.match(css, /\.test-fleet-matrix \{ width: 100%; min-width: 0/);
  assert.match(css, /\.test-state\.is-infrastructure/);
  assert.doesNotMatch(css, /\.test-fleet-cell\.has-infrastructure|\.test-fleet-cell\.has-test-failure|\.test-heat-cell \.icon/,
    'heatmap diagnostics must not reintroduce warning decoration into intensity cells');
  assert.match(css, /\.test-heat-tooltip-facts \{ display: grid; grid-template-columns: repeat\(2, minmax\(0, 1fr\)\)/,
    'the exact-value popup must expose several metrics without a narrow three-column squeeze');
  assert.match(css, /#test-detail-dialog \{/);
  assert.match(css, /width: min\(530px, 35\.6vw\)/,
    'the selected desktop composition reserves roughly one third of the viewport for repository detail');
  assert.match(css, /#test-detail-dialog \{[\s\S]*?container-type: inline-size/,
    'run history must adapt to the detail sheet rather than the full viewport');
  assert.match(css, /@container \(max-width: 620px\)[\s\S]*?\.test-run-evidence \{ grid-template-columns: repeat\(2, minmax\(0, 1fr\)\); \}/,
    'narrow desktop sheets must reflow evidence facts instead of producing a horizontal scroller');
  assert.match(css, /\.test-run-evidence \.test-run-evidence-wide \{ grid-column: 1 \/ -1; \}/);
  assert.match(css, /\.test-run-wait \{[\s\S]*grid-column: 1 \/ -1;[\s\S]*overflow-wrap: anywhere;/,
    'the quiet memory-wait line must wrap inside narrow repository sheets');
  assert.match(css, /html\.test-detail-open #main \{[\s\S]*margin-right: min\(530px, 35\.6vw\)/,
    'the fleet must reflow beside detail rather than being obscured');
  assert.match(css, /@media \(min-width: 1101px\)[\s\S]*\.test-fleet-row \{ height: 22px; \}/,
    'the long fleet must retain first-viewport density');
  assert.match(css, /@media \(max-width: 680px\)[\s\S]*\.test-fleet-matrix-panel \{ display: none; \}/);
  assert.match(css, /@media \(max-width: 680px\)[\s\S]*\.test-fleet-mobile \{ display: grid/);
  assert.match(css, /@media \(max-width: 680px\)[\s\S]*#test-run-dialog \.dialog-actions \{ flex-wrap: wrap; \}/,
    'the three run-dialog actions must wrap instead of overflowing narrow screens');
  assert.match(css, /@media \(max-width: 680px\)[\s\S]*\.test-run-targets \{ grid-template-columns: minmax\(0, 1fr\); \}/,
    'manual target choices must become one readable mobile column');
  assert.match(css, /@media \(max-width: 1100px\)[\s\S]*\.test-summary \{ display: none; \}/);
  assert.match(css, /@media \(max-width: 360px\)[\s\S]*\.test-heat-hour\.is-six/);
});

test('every literal icon request has registered SVG markup', async () => {
  const js = await fsp.readFile(new URL('app.js', UI), 'utf8');
  const registry = js.match(/const ICONS = \{([\s\S]*?)\n  \};/);
  assert.ok(registry, 'app.js must retain the static icon registry');
  const defined = new Set(
    [...registry[1].matchAll(/^\s+([a-z][a-z0-9]*):/gm)].map((match) => match[1]),
  );
  const requested = new Set(
    [...js.matchAll(/\bicon\('([a-z][a-z0-9]*)'\)/g)].map((match) => match[1]),
  );
  assert.deepEqual(
    [...requested].filter((name) => !defined.has(name)),
    [],
    'literal icon calls must never silently render an empty icon',
  );
});
