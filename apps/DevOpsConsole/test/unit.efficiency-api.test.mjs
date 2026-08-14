import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';

const REPOSITORY_ID = '123e4567-e89b-42d3-a456-426614174000';

async function requestFrom(t, { projection, inventory }) {
  const api = createConsoleApi({
    config: {
      consoleOrigin: 'https://console.example.test', consoleHost: 'console.example.test',
      domain: 'example.test', lifecycleEnabled: false,
    },
    log: null,
    coordinator: { inventory },
    routeStore: { list: () => [] },
    upstreamAuthStore: null,
    accessStore: { isAdmin: () => false },
    guard: { checkOrigin: () => true },
    certManager: null, metrics: null, prefs: null, telegram: null, bugStore: null,
    efficiencyStore: { list: async () => projection },
  });
  const server = http.createServer((req, res) => api.handle(req, res, { email: 'reader@example.test' }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return async () => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/efficiency`);
    return { status: response.status, json: await response.json() };
  };
}

const projection = {
  schema_version: 1,
  available: true,
  repositories: [{ repository_id: REPOSITORY_ID, task_count: 2 }],
};

test('efficiency API enriches retained repository statistics with inventory name', async (t) => {
  const request = await requestFrom(t, {
    projection,
    inventory: async () => ({ repositories: [{ repo_id: REPOSITORY_ID, display_name: 'Holy Skills' }] }),
  });
  const response = await request();
  assert.equal(response.status, 200);
  assert.equal(response.json.repositories[0].display_name, 'Holy Skills');
});

test('efficiency API stays readable during Coordinator inventory failure without exposing an ID as UI text', async (t) => {
  const request = await requestFrom(t, {
    projection,
    inventory: async () => { throw new Error('broker unavailable'); },
  });
  const response = await request();
  assert.equal(response.status, 200);
  assert.equal(response.json.repositories[0].display_name, 'Repository unavailable');
  assert.notEqual(response.json.repositories[0].display_name, REPOSITORY_ID);
});

test('missing optional store returns an unavailable projection', async (t) => {
  const api = createConsoleApi({
    config: { consoleOrigin: 'https://console.example.test', lifecycleEnabled: false },
    log: null, coordinator: {}, routeStore: { list: () => [] }, upstreamAuthStore: null,
    accessStore: { isAdmin: () => false }, guard: { checkOrigin: () => true },
    certManager: null, metrics: null, prefs: null, telegram: null, bugStore: null,
  });
  const server = http.createServer((req, res) => api.handle(req, res, { email: 'reader@example.test' }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${server.address().port}/api/efficiency`);
  assert.deepEqual(await response.json(), { schema_version: 1, available: false, repositories: [] });
});
