import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

const UI = new URL('../src/ui/', import.meta.url);

test('Tests destination leads with repository-scoped hourly timing and period dynamics', async () => {
  const [html, js, css] = await Promise.all([
    fsp.readFile(new URL('index.html', UI), 'utf8'),
    fsp.readFile(new URL('app.js', UI), 'utf8'),
    fsp.readFile(new URL('app.css', UI), 'utf8'),
  ]);
  assert.match(html, /data-nav="tests">Tests/);
  assert.match(html, /data-page="performance"[\s\S]*href="#\/tests">Test dashboards<\/a>/,
    'Performance must disclose where test-run dashboards live');
  assert.match(html, /data-page="tests"/);
  assert.ok(html.indexOf('id="tests-h"') < html.indexOf('id="tests-body"'));
  assert.match(js, /function loadTests\(/);
  assert.match(js, /function loadTestRepositories\(/);
  assert.match(js, /\/api\/tests\/repositories/);
  assert.match(js, /metricTestRepositories/);
  assert.match(js, /\/api\/tests\?project=/);
  for (const promisedView of [
    'Testing time by hour', 'Testing time trend', 'Largest dynamics',
  ]) {
    assert.ok(js.includes(promisedView), promisedView);
  }
  assert.match(js, /function testHeatColor\(seconds\)/);
  assert.match(js, /minutes <= 60/);
  assert.match(js, /minutes <= 120/);
  assert.match(js, /Aggregate test time may exceed 60m when tests run in parallel/);
  assert.match(js, /class: 'test-summary-compact'/);
  assert.match(js, /class: `test-heat-hour/);
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
  assert.match(css, /@media \(max-width: 1100px\)[\s\S]*\.test-summary \{ display: none; \}/);
  assert.match(css, /@media \(max-width: 360px\)[\s\S]*\.test-heat-hour\.is-six/);
});
