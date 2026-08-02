import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';
import { CoordError } from '../src/coordinator.mjs';

const HOST_ID = '00000000-0000-4000-8000-000000000001';
const FUTURE_UUID_HOST_ID = '018f2e4d-7c2a-7b3c-8d4e-0123456789ab';

function projection() {
  return {
    schema: 'spectre.infrastructure.projection.v1',
    generated_at: '2026-07-29T12:00:00Z',
    observation_cadence_seconds: 60,
    stale_after_seconds: 180,
    sort: 'host_id',
    after_host_id: null,
    host_limit: 100,
    vm_limit_per_host: 256,
    rejection_limit_per_host: 20,
    hosts: [],
    has_more: false,
    next_after_host_id: null,
  };
}

async function fixture(t) {
  const calls = [];
  let failure = null;
  const coordinator = {
    infrastructure: async (options) => {
      calls.push(options);
      if (failure) throw failure;
      return projection();
    },
  };
  const api = createConsoleApi({
    config: {
      consoleOrigin: 'https://console.example.test',
      consoleHost: 'console.example.test',
      domain: 'example.test',
    },
    log: null,
    coordinator,
    routeStore: { list: () => [] },
    upstreamAuthStore: null,
    accessStore: { isAdmin: (email) => email === 'owner@example.test' },
    guard: { checkOrigin: () => true },
    certManager: null,
    metrics: null,
    prefs: null,
  });
  const server = http.createServer((req, res) => api.handle(
    req,
    res,
    req.headers['x-authenticated'] === '1'
      ? { email: req.headers['x-fixture-email'] || 'owner@example.test' }
      : null,
  ));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;

  async function request(pathname, {
    method = 'GET',
    authenticated = true,
    email = 'owner@example.test',
  } = {}) {
    const response = await fetch(`${origin}${pathname}`, {
      method,
      headers: authenticated
        ? { 'x-authenticated': '1', 'x-fixture-email': email }
        : {},
    });
    return { status: response.status, json: await response.json() };
  }
  return {
    calls,
    coordinator,
    request,
    failWith(error) { failure = error; },
  };
}

test('infrastructure read requires an exact Console owner before any Coordinator read', async (t) => {
  const { calls, request } = await fixture(t);
  const unauthenticated = await request('/api/infrastructure', { authenticated: false });
  assert.equal(unauthenticated.status, 401);
  assert.deepEqual(calls, []);

  const nonOwner = await request('/api/infrastructure', { email: 'operator@example.test' });
  assert.equal(nonOwner.status, 403);
  assert.equal(nonOwner.json.error, 'only configured Console owners can read infrastructure');
  assert.deepEqual(calls, []);

  const malformedNonOwner = await request('/api/infrastructure?after=not-a-guid', {
    email: 'operator@example.test',
  });
  assert.equal(malformedNonOwner.status, 403);
  assert.deepEqual(calls, [], 'authorization must precede cursor parsing and Coordinator access');

  const first = await request('/api/infrastructure');
  assert.equal(first.status, 200);
  assert.equal(first.json.schema, 'spectre.infrastructure.projection.v1');
  assert.deepEqual(calls, [{ afterHostId: null }]);

  const next = await request(`/api/infrastructure?after=${HOST_ID}`);
  assert.equal(next.status, 200);
  assert.deepEqual(calls.at(-1), { afterHostId: HOST_ID });

  const futureUuid = await request(`/api/infrastructure?after=${FUTURE_UUID_HOST_ID}`);
  assert.equal(futureUuid.status, 200);
  assert.deepEqual(calls.at(-1), { afterHostId: FUTURE_UUID_HOST_ID });
});

test('infrastructure API rejects generic parameters and exposes no mutation route', async (t) => {
  const { calls, request } = await fixture(t);
  for (const pathname of [
    '/api/infrastructure?operation=infrastructure.ingest',
    '/api/infrastructure?after=not-a-guid',
    `/api/infrastructure?after=${HOST_ID}&after=${HOST_ID}`,
  ]) {
    const response = await request(pathname);
    assert.equal(response.status, 400, pathname);
  }
  const mutation = await request('/api/infrastructure', { method: 'POST' });
  assert.equal(mutation.status, 404);
  assert.deepEqual(calls, []);
});

test('unavailable broker is a gateway failure, never an empty collection', async (t) => {
  const { failWith, request } = await fixture(t);
  failWith(new CoordError('infrastructure read broker is unavailable'));
  const response = await request('/api/infrastructure');
  assert.equal(response.status, 502);
  assert.equal(response.json.error, 'infrastructure read broker is unavailable');
});
