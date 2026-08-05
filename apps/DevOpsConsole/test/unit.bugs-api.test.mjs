import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';
import { createBugStore } from '../src/bugs.mjs';

const BUG_ID = `bug-${'a'.repeat(32)}`;

async function tempDir(t) {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-bug-api-'));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  return directory;
}

function bug(bugId = BUG_ID) {
  return {
    schema_version: 1,
    bug_id: bugId,
    fingerprint: '1'.repeat(64),
    component: 'Console API',
    summary: 'Open bug registry request failed',
    expected: 'The open list is returned without using Coordinator inventory.',
    actual: 'The request failed before the open registry was read.',
    reproduction_steps: ['Open the Bugs page.', 'Refresh the open collection.'],
    reporter: 'codex-root',
    peer_uid: 1000,
    first_seen_at: '2026-08-04T08:00:00.000Z',
    last_seen_at: '2026-08-04T08:00:00.000Z',
    occurrence_count: 1,
    correlations: { call_id: 'call-console-api' },
  };
}

async function writeBug(directory, value = bug()) {
  await fsp.mkdir(directory, { recursive: true });
  await fsp.writeFile(path.join(directory, `${value.bug_id}.json`), JSON.stringify(value));
}

async function apiServer(t, directory) {
  const coordinator = new Proxy({}, {
    get() {
      return () => { throw new Error('open-bug API must not contact Coordinator'); };
    },
  });
  const api = createConsoleApi({
    config: {
      consoleOrigin: 'https://console.example.test',
      consoleHost: 'console.example.test',
      domain: 'example.test',
      lifecycleEnabled: false,
    },
    log: null,
    coordinator,
    routeStore: { list: () => [] },
    upstreamAuthStore: null,
    accessStore: { isAdmin: (email) => email === 'owner@example.test' },
    guard: { checkOrigin: (req) => req.headers['x-origin-ok'] !== '0' },
    certManager: null,
    metrics: null,
    prefs: null,
    telegram: null,
    bugStore: createBugStore({ directory, originServerId: 'console.example.test' }),
  });
  const server = http.createServer((req, res) => api.handle(req, res, {
    email: req.headers['x-user'] || 'reader@example.test',
  }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return async function request(pathname, {
    method = 'GET', user = 'reader@example.test', originOk = true, body,
  } = {}) {
    const response = await fetch(`${origin}${pathname}`, {
      method,
      headers: {
        'x-user': user,
        'x-origin-ok': originOk ? '1' : '0',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, json: await response.json() };
  };
}

test('authenticated readers can list bugs while Coordinator is unavailable', async (t) => {
  const directory = await tempDir(t);
  await writeBug(directory);
  const request = await apiServer(t, directory);

  const response = await request('/api/bugs');

  assert.equal(response.status, 200);
  assert.equal(response.json.bugs.length, 1);
  assert.equal(response.json.bugs[0].summary, 'Open bug registry request failed');
});

test('authenticated readers can export while only owners can import portable bugs', async (t) => {
  const sourceDirectory = await tempDir(t);
  await writeBug(sourceDirectory);
  const sourceRequest = await apiServer(t, sourceDirectory);
  const exported = await sourceRequest('/api/bugs/export');
  assert.equal(exported.status, 200);
  assert.equal(exported.json.kind, 'devcoordinator-open-bugs');
  assert.equal(exported.json.exporting_server, 'console.example.test');
  assert.equal(exported.json.bugs[0].origin.kind, 'local');

  const destinationDirectory = await tempDir(t);
  const destinationRequest = await apiServer(t, destinationDirectory);
  const denied = await destinationRequest('/api/bugs/import', {
    method: 'POST', body: exported.json,
  });
  assert.equal(denied.status, 403);
  assert.equal((await destinationRequest('/api/bugs')).json.bugs.length, 0);

  const imported = await destinationRequest('/api/bugs/import', {
    method: 'POST', user: 'owner@example.test', body: exported.json,
  });
  assert.equal(imported.status, 200);
  assert.deepEqual(imported.json.import_result, {
    received: 1, imported: 1, already_present: 0,
  });
  assert.equal(imported.json.bugs[0].origin.kind, 'remote');
  assert.equal(imported.json.bugs[0].origin.server_id, 'console.example.test');

  const repeated = await destinationRequest('/api/bugs/import', {
    method: 'POST', user: 'owner@example.test', body: exported.json,
  });
  assert.equal(repeated.status, 200);
  assert.deepEqual(repeated.json.import_result, {
    received: 1, imported: 0, already_present: 1,
  });
});

test('only an owner with a valid same-origin mutation can close an exact report', async (t) => {
  const directory = await tempDir(t);
  await writeBug(directory);
  const request = await apiServer(t, directory);

  const denied = await request(`/api/bugs/${BUG_ID}`, { method: 'DELETE' });
  assert.equal(denied.status, 403);
  assert.equal((await request('/api/bugs')).json.bugs.length, 1);

  const crossOrigin = await request(`/api/bugs/${BUG_ID}`, {
    method: 'DELETE', user: 'owner@example.test', originOk: false,
  });
  assert.equal(crossOrigin.status, 403);
  assert.equal((await request('/api/bugs')).json.bugs.length, 1);

  const closed = await request(`/api/bugs/${BUG_ID}`, {
    method: 'DELETE', user: 'owner@example.test',
  });
  assert.equal(closed.status, 200);
  assert.deepEqual(closed.json.bugs, []);
  await assert.rejects(fsp.stat(path.join(directory, `${BUG_ID}.json`)), { code: 'ENOENT' });
});

test('two Console instances converge after a close race with no history row', async (t) => {
  const directory = await tempDir(t);
  await writeBug(directory);
  const first = await apiServer(t, directory);
  const second = await apiServer(t, directory);

  const results = await Promise.all([
    first(`/api/bugs/${BUG_ID}`, { method: 'DELETE', user: 'owner@example.test' }),
    second(`/api/bugs/${BUG_ID}`, { method: 'DELETE', user: 'owner@example.test' }),
  ]);

  assert.deepEqual(results.map((result) => result.status), [200, 200]);
  assert.deepEqual((await first('/api/bugs')).json.bugs, []);
  assert.deepEqual((await second('/api/bugs')).json.bugs, []);
  assert.deepEqual(await fsp.readdir(directory), []);
});

test('store failures stay on the Bugs API and do not become Coordinator failures', async (t) => {
  const root = await tempDir(t);
  const unavailable = path.join(root, 'occupied');
  await fsp.writeFile(unavailable, 'not a directory', 'utf8');
  const request = await apiServer(t, unavailable);

  const response = await request('/api/bugs');

  assert.equal(response.status, 503);
  assert.equal(response.json.error, 'Open Coordinator bugs are temporarily unavailable.');
  assert.equal(response.json.classification, undefined);
});
