import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';

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
    accessStore: { isAdmin: () => false },
    guard: { checkOrigin: () => true },
    certManager: { info: () => null },
    metrics: { ingest: () => {}, history: () => ({ entities: [], host: null }) },
    prefs: null,
  });
  return {
    api,
    counts: () => ({ inventoryReads, routeResolves, routeSnapshot }),
  };
}

async function overview(api) {
  const req = { method: 'GET', url: '/api/overview', headers: {} };
  const res = responseRecorder();
  const started = performance.now();
  await api.handle(req, res, { email: 'owner@example.test' });
  return { res, elapsedMs: performance.now() - started, json: JSON.parse(res.body) };
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
  assert.deepEqual(counts(), { inventoryReads: 0, routeResolves: 0, routeSnapshot: null },
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
    /inventoryState === 'loading'[\s\S]{0,260}inventoryWarmupRetries < 4[\s\S]{0,260}setTimeout/,
    'a bounded cold response must trigger a few quick cache follow-ups instead of waiting for the polling interval');
  assert.match(source,
    /function degradedPanel\(o\)[\s\S]{0,180}inventoryState === 'loading'/,
    'a bounded cold read must render as loading rather than falsely claiming the Coordinator is unreachable');
});
