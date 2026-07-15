// Guardrail for the UI's stable-ordering contract (docs/journeys.md): list
// pages must keep a deterministic order across polls — live CPU/memory
// readings must never be an ordering key. The comparator lives in browser
// code (src/ui/app.js), so it is extracted by brace matching and exercised
// directly; the must-catch fixture reproduces the reported failure (groups
// reshuffling when only cpu_percent changes between polls).

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';

const APP_JS_URL = new URL('../src/ui/app.js', import.meta.url);

function extractFunction(source, header) {
  const start = source.indexOf(header);
  assert.notEqual(start, -1, `app.js no longer contains "${header}"`);
  let depth = 0;
  for (let i = source.indexOf('{', start); i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  assert.fail(`unbalanced braces extracting ${header}`);
  return '';
}

async function loadGroupOrder() {
  const appJs = await fsp.readFile(APP_JS_URL, 'utf8');
  const src = extractFunction(appJs, 'function projectGroupOrder(a, b)');
  // eslint-disable-next-line no-new-func
  return { appJs, projectGroupOrder: new Function(`${src}; return projectGroupOrder;`)() };
}

async function loadContainerStatus() {
  const appJs = await fsp.readFile(APP_JS_URL, 'utf8');
  const runningSource = extractFunction(appJs, 'function isContainerRunning(c)');
  const metaSource = extractFunction(appJs, 'function containerStatusMeta(c)');
  // eslint-disable-next-line no-new-func
  return new Function(`${runningSource}; ${metaSource}; return { isContainerRunning, containerStatusMeta };`)();
}

const group = (name, runningCount, cpu, key = `path:/repo/${name}`) => ({
  name,
  key,
  runningCount,
  row: { cpu_percent: cpu },
});

test('project groups: order is INDEPENDENT of live cpu readings (the reported reshuffle)', async () => {
  const { projectGroupOrder } = await loadGroupOrder();

  // Two polls of the same three running projects, differing ONLY in
  // cpu_percent — mirroring the live reproduction where GlobalFinance and
  // holyskills swapped places between 6s refreshes.
  const poll1 = [group('skydive', 3, 4.6), group('globalfinance', 2, 1.5), group('holyskills', 4, 1.4)];
  const poll2 = [group('skydive', 3, 7.4), group('globalfinance', 2, 1.4), group('holyskills', 4, 1.5)];
  const order1 = poll1.slice().sort(projectGroupOrder).map((g) => g.name);
  const order2 = poll2.slice().sort(projectGroupOrder).map((g) => g.name);

  assert.deepEqual(order1, order2,
    'group order must not change when only cpu readings change between polls');
  assert.deepEqual(order1, ['globalfinance', 'holyskills', 'skydive'],
    'running groups order by name, not by load');
});

test('project groups: running-first survives, ties break deterministically', async () => {
  const { projectGroupOrder } = await loadGroupOrder();

  const groups = [
    group('idle-a', 0, 0),
    group('zulu', 1, 0.1),
    group('alpha', 5, 99.9), // hottest AND running — but name decides among running
    group('idle-b', 0, 0),
  ];
  const order = groups.sort(projectGroupOrder).map((g) => g.name);
  assert.deepEqual(order, ['alpha', 'zulu', 'idle-a', 'idle-b']);

  // Same name (display names can collide) → unique key decides, stably.
  const twins = [group('app', 1, 0, 'path:/b/app'), group('app', 1, 0, 'path:/a/app')];
  assert.deepEqual(twins.sort(projectGroupOrder).map((g) => g.key), ['path:/a/app', 'path:/b/app']);
});

test('ordering wiring: the stable comparator is used and no live-metric sort keys remain', async () => {
  const { appJs } = await loadGroupOrder();
  assert.ok(appJs.includes('groups.sort(projectGroupOrder)'),
    'projectGroupsOf must sort through the stable comparator');
  // The two live-metric ordering keys this guardrail exists to keep out:
  assert.ok(!appJs.includes('cpu_percent || 0) - (a'),
    'no list may order by live cpu_percent');
  assert.ok(!appJs.includes('lastCpu(b) - lastCpu(a)'),
    'performance cards may not order by current load');
});

test('browser container status accepts normalized and docker-CLI running vocabularies', async () => {
  const { isContainerRunning, containerStatusMeta } = await loadContainerStatus();
  for (const status of ['running', 'Up 3 minutes (healthy)']) {
    assert.equal(isContainerRunning({ status }), true, status);
    assert.deepEqual(containerStatusMeta({ status }), { css: 'ok', label: 'running' }, status);
  }
  assert.equal(isContainerRunning({ status: 'stopped' }), false);
  assert.deepEqual(containerStatusMeta({ status: 'stopped' }), { css: 'dim', label: 'stopped' });
});
