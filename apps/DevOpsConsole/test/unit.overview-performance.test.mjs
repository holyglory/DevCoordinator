import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';
import { createMetricsStore } from '../src/metrics.mjs';

function responseRecorder() {
  return {
    status: null,
    headers: null,
    body: '',
    headersSent: false,
    writeHead(status, headers) {
      this.status = status;
      this.headers = headers;
      this.headersSent = true;
    },
    end(body = '') {
      this.body += String(body);
    },
  };
}

function makeApi({ snapshot, inventoryError = null } = {}) {
  let inventoryReads = 0;
  let routeResolves = 0;
  let routeSnapshot = null;
  let testRepositoryReads = 0;
  const coordinator = {
    async inventory() {
      inventoryReads += 1;
      if (inventoryError) throw inventoryError;
      return snapshot;
    },
    async inventoryForOverview() {
      return inventoryError
        ? { inventory: null, state: 'error', ageMs: null, refreshing: false, error: inventoryError }
        : { inventory: snapshot, state: 'fresh', ageMs: 0, refreshing: false, error: null };
    },
    status() {
      return { ok: !inventoryError, url: 'http://127.0.0.1:29876', lastError: inventoryError?.message ?? null };
    },
    async testRepositories() {
      testRepositoryReads += 1;
      return {
        schema_version: 1,
        repositories: [{ repo_id: 'repo-1', canonical_root: '/repo', display_name: 'Repo' }],
      };
    },
  };
  const routeStore = {
    list() {
      return [{
        slug: 'app', kind: 'server', project: '/repo', serverName: 'web',
        auth: 'google', createdAt: '2026-07-27T00:00:00Z', updatedAt: '2026-07-27T00:00:00Z',
      }];
    },
    async resolve(_slug, _coordinator, suppliedSnapshot) {
      routeResolves += 1;
      routeSnapshot = suppliedSnapshot;
      return { port: 3000, server: { status: 'running' } };
    },
  };
  const api = createConsoleApi({
    config: {
      version: 'test', domain: 'example.test', consoleHost: 'console.example.test',
      consoleOrigin: 'https://console.example.test', projectRoot: '/repo', lifecycleEnabled: false,
    },
    log: null,
    coordinator,
    routeStore,
    upstreamAuthStore: { describe: () => ({ configured: false }) },
    accessStore: { isAdmin: () => true, canAccess: () => false },
    guard: { checkOrigin: () => true },
    certManager: { info: () => null },
    metrics: { ingest: () => {}, history: () => ({ entities: [], host: null }) },
    prefs: null,
  });
  return {
    api,
    counts: () => ({ inventoryReads, routeResolves, routeSnapshot, testRepositoryReads }),
  };
}

async function overview(api) {
  const req = { method: 'GET', url: '/api/overview', headers: {} };
  const res = responseRecorder();
  const started = performance.now();
  await api.handle(req, res, { email: 'owner@example.test' });
  return { res, elapsedMs: performance.now() - started, json: JSON.parse(res.body) };
}

function p99(values) {
  return [...values].sort((left, right) => left - right)[Math.ceil(values.length * 0.99) - 1];
}

test('overview returns a truthful dependency error within 100ms without a second route-resolution read', async () => {
  const failure = Object.assign(new Error('broker maintenance in progress'), { status: 503 });
  const { api, counts } = makeApi({ inventoryError: failure });
  const result = await overview(api);

  assert.equal(result.res.status, 200);
  assert.ok(result.elapsedMs < 100, `overview TTFB budget exceeded: ${result.elapsedMs.toFixed(1)}ms`);
  assert.equal(result.json.inventory, null);
  assert.equal(result.json.coordinator.inventoryState, 'error');
  assert.match(result.json.routes[0].resolved.reason, /broker maintenance in progress/);
  assert.deepEqual(counts(), {
    inventoryReads: 0, routeResolves: 0, routeSnapshot: null, testRepositoryReads: 0,
  },
    'a failed inventory snapshot must not start another Coordinator route-resolution request');
});

test('overview resolves every route from the one bounded inventory snapshot', async () => {
  const snapshot = {
    servers: [{ id: 'server-1', project: '/repo', name: 'web', status: 'running', port: 3000 }],
    docker: { available: true, containers: [] },
  };
  const { api, counts } = makeApi({ snapshot });
  const result = await overview(api);

  assert.equal(result.res.status, 200);
  assert.equal(result.json.routes[0].resolved.port, 3000);
  assert.equal(counts().inventoryReads, 0);
  assert.equal(counts().routeResolves, 1);
  assert.equal(counts().routeSnapshot, snapshot,
    'route resolution must consume the same inventory object returned in the overview');
});

test('cached healthy Console overview handler p99 remains below 100ms', async () => {
  const snapshot = {
    servers: [{ id: 'server-1', project: '/repo', name: 'web', status: 'running', port: 3000 }],
    docker: { available: true, containers: [] },
  };
  const { api } = makeApi({ snapshot });
  await overview(api);
  const durations = [];
  for (let sample = 0; sample < 40; sample += 1) {
    const result = await overview(api);
    assert.equal(result.res.status, 200);
    assert.equal(result.json.routes[0].resolved.port, 3000);
    durations.push(result.elapsedMs);
  }
  const elapsedP99 = p99(durations);
  assert.ok(elapsedP99 < 100,
    `cached Console overview handler p99 was ${elapsedP99.toFixed(1)}ms`);
});

test('test repository catalog does not build the heavyweight overview', async () => {
  const { api, counts } = makeApi({ snapshot: null });
  const req = { method: 'GET', url: '/api/tests/repositories', headers: {} };
  const res = responseRecorder();
  const started = performance.now();
  await api.handle(req, res, { email: 'owner@example.test' });

  assert.equal(res.status, 200);
  assert.ok(performance.now() - started < 100);
  assert.equal(JSON.parse(res.body).repositories[0].repo_id, 'repo-1');
  assert.deepEqual(counts(), {
    inventoryReads: 0, routeResolves: 0, routeSnapshot: null, testRepositoryReads: 1,
  });
});

test('browser boot renders Performance metrics independently of a slow overview', async () => {
  const source = await fsp.readFile(new URL('../src/ui/app.js', import.meta.url), 'utf8');
  assert.match(source,
    /const initialOverview = refreshOverview\(\{ force: true \}\);[\s\S]{0,180}const initialMetrics = refreshMetrics\(\);/,
    'initial overview and metrics requests must start concurrently');
  assert.match(source,
    /if \(!o\) \{[\s\S]{0,180}page === 'performance'[\s\S]{0,240}buildPerf\(null\)/,
    'Performance must replace its skeleton from local metrics even while overview is unavailable');
  assert.doesNotMatch(source,
    /await refreshOverview\(\{ force: true \}\);\s*await refreshMetrics\(\);/,
    'a slow overview must not block the first meaningful Performance paint');
  assert.match(source,
    /inventoryWarmupStartedAt \?\?= Date\.now\(\);[\s\S]{0,120}Date\.now\(\) - inventoryWarmupStartedAt < 15_000[\s\S]{0,500}setTimeout/,
    'a bounded cold response must follow the coalesced cache warm-up instead of abandoning the loading screen');
  assert.match(source,
    /function degradedPanel\(o\)[\s\S]{0,180}inventoryState === 'loading'/,
    'a bounded cold read must render as loading rather than falsely claiming the Coordinator is unreachable');
  assert.match(source,
    /!data\.inventory[\s\S]{0,120}state\.overview\?\.inventory[\s\S]{0,220}inventoryState === 'loading'[\s\S]{0,160}failureKind[\s\S]{0,500}inventory: state\.overview\.inventory/,
    'a background cold or failed response must retain the last authoritative inventory instead of flashing an empty page');
});

test('retained inventory sampling never starts a live host observation', async () => {
  let inventoryReads = 0;
  let observations = 0;
  const coordinator = {
    async inventory() {
      inventoryReads += 1;
      return { servers: [], docker: { available: true, containers: [] } };
    },
    async observeHost() {
      observations += 1;
      throw new Error('the Console must not own observation');
    },
  };
  const store = createMetricsStore({
    config: { metricsIntervalMs: 2_000, retainedInventory: true, projectRoot: '/repo' },
    coordinator,
    host: {
      async sample() {
        return { at: Date.now(), cpuPercent: null, mem: null };
      },
    },
  });

  await store.sampleOnce();

  assert.equal(inventoryReads, 1);
  assert.equal(observations, 0);
  assert.equal(store.history().sampler.observationFailures, 0);
});
