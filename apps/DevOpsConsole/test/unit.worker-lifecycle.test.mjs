import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';
import { CoordError } from '../src/coordinator.mjs';

const WORKER_ID = 'worker-definition-1';

function workerInventory() {
  return {
    servers: [{
      id: WORKER_ID,
      name: 'queue-worker',
      status: 'running',
      supervision: {
        keep_alive: true,
        desired_state: 'running',
        state: 'running',
        breaker: { state: 'armed', crash_limit: 10, window_seconds: 300 },
      },
    }],
    repository_trees: [{
      family_id: 'family-root',
      root_repository: {
        repo_id: 'repo-root', canonical_root: '/src/root', display_name: 'Root',
      },
      scopes: [{
        repo_id: 'repo-root', kind: 'root', canonical_root: '/src/root',
        display_name: 'Root', server_ids: [], container_resource_ids: [],
        database_binding_ids: [],
      }, {
        repo_id: 'repo-temp', kind: 'temporary', canonical_root: '/src/root-wt-test',
        display_name: 'Root test', server_ids: [WORKER_ID], container_resource_ids: [],
        database_binding_ids: [],
      }],
    }],
  };
}

async function fixture(t) {
  const calls = [];
  const inventory = workerInventory();
  const coordinator = {
    inventory: async (options) => {
      calls.push({ method: 'inventory', body: options });
      return inventory;
    },
    runtimeAction: async (body) => {
      calls.push({ method: 'runtimeAction', body });
      return {
        schema_version: 1,
        ok: true,
        action: body.action,
        classification: body.action === 'remove' ? 'worker_remove_plan_ready' : 'worker_running',
        target: body.target,
        result: body.action === 'remove' ? {
          stage: 'archive',
          plan: {
            action: 'archive',
            plan_id: 'remove-plan-1',
            plan_fingerprint: 'remove-fingerprint-1',
            confirmation_phrase: '',
            effects: ['stop worker'], retained: ['history'], deleted: [], blockers: [],
          },
        } : {},
      };
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
  async function request(body, email = 'owner@example.test') {
    const response = await fetch(`${origin}/api/workers/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-fixture-email': email },
      body: JSON.stringify(body),
    });
    return { status: response.status, json: await response.json() };
  }
  return { calls, coordinator, inventory, request };
}

test('worker actions use exact root and temporary repository context from the tree', async (t) => {
  const { calls, request } = await fixture(t);
  const response = await request({
    id: WORKER_ID,
    action: 'start',
    keep_alive: true,
    rearm_crash_loop: false,
    reason: 'Start the fixture worker',
  });

  assert.equal(response.status, 200);
  assert.deepEqual(calls[0], { method: 'inventory', body: { maxAgeMs: 0 } });
  assert.deepEqual(calls[1], {
    method: 'runtimeAction',
    body: {
      schema_version: 1,
      action: 'start',
      agent: 'devops-console:owner@example.test',
      root_repo: '/src/root',
      temporary_repo: '/src/root-wt-test',
      target: { kind: 'service', id: WORKER_ID, name: 'queue-worker' },
      purpose: 'development',
      ttl_seconds: null,
      kill_after_run: false,
      options: {
        reason: 'Start the fixture worker',
        keep_alive: true,
        rearm_crash_loop: false,
      },
    },
  });
});

test('worker removal is owner-only before inventory or runtime state is read', async (t) => {
  const { calls, request } = await fixture(t);
  const response = await request(
    { id: WORKER_ID, action: 'remove' },
    'guest@example.test',
  );
  assert.equal(response.status, 403);
  assert.deepEqual(calls, []);
});

test('worker removal preserves blocked plans and forwards exact apply evidence', async (t) => {
  const { calls, coordinator, request } = await fixture(t);
  coordinator.runtimeAction = async (body) => {
    calls.push({ method: 'runtimeAction', body });
    if (!body.options.remove_plan_id) {
      throw new CoordError('removal blocked', {
        status: 409,
        body: {
          schema_version: 1,
          ok: false,
          action: 'remove',
          classification: 'worker_remove_blocked',
          target: body.target,
          result: {
            stage: 'archive',
            plan: {
              action: 'archive', plan_id: 'blocked-plan',
              plan_fingerprint: 'blocked-fingerprint', confirmation_phrase: '',
              effects: [], retained: [], deleted: [], blockers: ['unknown listener'],
            },
          },
        },
      });
    }
    return {
      schema_version: 1, ok: true, action: 'remove',
      classification: 'worker_archived', target: body.target,
      result: { stage: 'archive', lifecycle: { ok: true, status: 'succeeded' } },
    };
  };

  const planned = await request({ id: WORKER_ID, action: 'remove' });
  assert.equal(planned.status, 200);
  assert.equal(planned.json.runtime.result.plan.blockers[0], 'unknown listener');

  const applied = await request({
    id: WORKER_ID,
    action: 'remove',
    remove_plan_id: 'blocked-plan',
    remove_plan_fingerprint: 'blocked-fingerprint',
    remove_confirmation_phrase: '',
  });
  assert.equal(applied.status, 200);
  const call = calls.findLast((item) => item.method === 'runtimeAction');
  assert.deepEqual({
    remove_plan_id: call.body.options.remove_plan_id,
    remove_plan_fingerprint: call.body.options.remove_plan_fingerprint,
    remove_confirmation_phrase: call.body.options.remove_confirmation_phrase,
  }, {
    remove_plan_id: 'blocked-plan',
    remove_plan_fingerprint: 'blocked-fingerprint',
    remove_confirmation_phrase: '',
  });
});

test('ambiguous worker membership fails closed before a runtime call', async (t) => {
  const { calls, inventory, request } = await fixture(t);
  inventory.repository_trees[0].scopes[0].server_ids.push(WORKER_ID);

  const response = await request({ id: WORKER_ID, action: 'stop' });
  assert.equal(response.status, 409);
  assert.match(response.json.error, /more than one repository scope/);
  assert.equal(calls.filter((item) => item.method === 'runtimeAction').length, 0);
});
