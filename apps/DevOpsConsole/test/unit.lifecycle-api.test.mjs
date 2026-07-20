import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';
import { CoordError } from '../src/coordinator.mjs';

async function fixture(t) {
  const calls = [];
  const archives = [{
    target_kind: 'repository',
    target_id: 'repo-fixture-1',
    display_name: 'Fixture repository',
    restorable: true,
    removable: true,
  }];
  const coordinator = {
    inventory: async (options) => {
      calls.push({ method: 'inventory', body: options });
      return {
        repositories: [{ repo_id: 'repo-fixture-1' }],
        servers: [{ id: 'server-fixture-1' }],
        docker: { containers: [{ host_resource_id: 'container-fixture-1' }] },
      };
    },
    lifecycleArchives: async () => {
      calls.push({ method: 'lifecycleArchives' });
      return { archives };
    },
    lifecyclePlan: async (body) => {
      calls.push({ method: 'lifecyclePlan', body });
      return {
        plan_id: 'plan-fixture-1',
        plan_fingerprint: 'fingerprint-fixture-1',
        effects: ['stop exact resource'],
        retained: ['history'],
        deleted: [],
        blockers: [],
      };
    },
    lifecycleApply: async (body) => {
      calls.push({ method: 'lifecycleApply', body });
      return { ok: true, status: 'completed', partial: false, needs_attention: false };
    },
    lifecycleRestore: async (body) => {
      calls.push({ method: 'lifecycleRestore', body });
      return { ok: true, status: 'completed', partial: false, needs_attention: false };
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
  const server = http.createServer((req, res) => api.handle(req, res, {
    email: req.headers['x-fixture-email'] || 'owner@example.test',
  }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  async function request(pathname, { method = 'GET', body, email = 'owner@example.test' } = {}) {
    const response = await fetch(`${origin}${pathname}`, {
      method,
      headers: {
        'x-fixture-email': email,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, json: await response.json() };
  }
  return { archives, calls, coordinator, request };
}

test('lifecycle API is owner-only and does not touch coordinator state for non-owners', async (t) => {
  const { calls, request } = await fixture(t);

  const list = await request('/api/lifecycle/list', { email: 'guest@example.test' });
  const plan = await request('/api/lifecycle/plan', {
    method: 'POST',
    email: 'guest@example.test',
    body: {
      target_kind: 'project', target_id: 'repo-fixture-1', action: 'archive', reason: 'fixture',
    },
  });

  assert.equal(list.status, 403);
  assert.equal(plan.status, 403);
  assert.deepEqual(calls, [], 'authorization must fail before inventory, archive, or plan reads');
});

test('repository compatibility input and archive rows normalize to canonical project targets', async (t) => {
  const { calls, request } = await fixture(t);

  const list = await request('/api/lifecycle/list');
  assert.equal(list.status, 200);
  assert.equal(list.json.archives[0].target_kind, 'project');

  const response = await request('/api/lifecycle/plan', {
    method: 'POST',
    body: {
      target_kind: 'repository',
      target_id: 'repo-fixture-1',
      action: 'archive',
      reason: 'Canonical compatibility regression',
    },
  });

  assert.equal(response.status, 200);
  assert.equal(response.json.plan.plan_id, 'plan-fixture-1');
  const call = calls.find((item) => item.method === 'lifecyclePlan');
  assert.deepEqual(call.body, {
    target_kind: 'project',
    target_id: 'repo-fixture-1',
    action: 'archive',
    reason: 'Canonical compatibility regression',
    agent: 'devops-console:owner@example.test',
  });
});

test('malformed archive identities fail closed instead of becoming lifecycle controls', async (t) => {
  const { archives, request } = await fixture(t);
  archives[0].target_kind = 'filesystem';

  const response = await request('/api/lifecycle/list');
  assert.equal(response.status, 502);
  assert.match(response.json.error, /invalid lifecycle archive identity/);
});

test('purge and restore are bound to advertised archived capabilities and exact identifiers', async (t) => {
  const { archives, calls, request } = await fixture(t);

  const purge = await request('/api/lifecycle/plan', {
    method: 'POST',
    body: {
      target_kind: 'repository',
      target_id: 'repo-fixture-1',
      action: 'purge',
      reason: 'Remove fixture',
    },
  });
  assert.equal(purge.status, 200);
  assert.equal(calls.findLast((item) => item.method === 'lifecyclePlan').body.target_kind, 'project');

  archives[0].removable = false;
  const blockedPurge = await request('/api/lifecycle/plan', {
    method: 'POST',
    body: { target_kind: 'project', target_id: 'repo-fixture-1', action: 'purge' },
  });
  assert.equal(blockedPurge.status, 409);
  assert.match(blockedPurge.json.error, /not currently removable/);

  const restore = await request('/api/lifecycle/restore', {
    method: 'POST',
    body: { target_kind: 'repository', target_id: 'repo-fixture-1', reason: 'Bring it back' },
  });
  assert.equal(restore.status, 200);
  assert.deepEqual(calls.findLast((item) => item.method === 'lifecycleRestore').body, {
    target_kind: 'project',
    target_id: 'repo-fixture-1',
    reason: 'Bring it back',
    agent: 'devops-console:owner@example.test',
    explicit: true,
  });

  archives[0].restorable = false;
  const blockedRestore = await request('/api/lifecycle/restore', {
    method: 'POST',
    body: { target_kind: 'project', target_id: 'repo-fixture-1' },
  });
  assert.equal(blockedRestore.status, 409);
  assert.match(blockedRestore.json.error, /not currently restorable/);
});

test('lifecycle apply forwards only the immutable reviewed plan and optional exact phrase', async (t) => {
  const { calls, request } = await fixture(t);
  const response = await request('/api/lifecycle/apply', {
    method: 'POST',
    body: {
      plan_id: 'plan-fixture-1',
      plan_fingerprint: 'fingerprint-fixture-1',
      confirmation_phrase: 'PURGE project repo-fixture-1',
      target_kind: 'project',
      target_id: 'ignored-client-identity',
    },
  });

  assert.equal(response.status, 200);
  assert.deepEqual(calls.find((item) => item.method === 'lifecycleApply').body, {
    plan_id: 'plan-fixture-1',
    plan_fingerprint: 'fingerprint-fixture-1',
    confirmation_phrase: 'PURGE project repo-fixture-1',
  });

  const archive = await request('/api/lifecycle/apply', {
    method: 'POST',
    body: {
      plan_id: 'plan-fixture-archive',
      plan_fingerprint: 'fingerprint-fixture-archive',
    },
  });
  assert.equal(archive.status, 200);
  assert.deepEqual(calls.findLast((item) => item.method === 'lifecycleApply').body, {
    plan_id: 'plan-fixture-archive',
    plan_fingerprint: 'fingerprint-fixture-archive',
    confirmation_phrase: '',
  }, 'archive apply must satisfy the exact three-field coordinator contract');
});

test('incomplete lifecycle results preserve conflict status and evidence for the dialog', async (t) => {
  const { coordinator, request } = await fixture(t);
  coordinator.lifecycleApply = async () => {
    throw new CoordError('lifecycle apply partial: cleanup failed', {
      status: 409,
      body: { ok: false, partial: true, needs_attention: true },
    });
  };

  const response = await request('/api/lifecycle/apply', {
    method: 'POST',
    body: { plan_id: 'plan-fixture-1', plan_fingerprint: 'fingerprint-fixture-1' },
  });
  assert.equal(response.status, 409);
  assert.match(response.json.error, /cleanup failed/);
});
