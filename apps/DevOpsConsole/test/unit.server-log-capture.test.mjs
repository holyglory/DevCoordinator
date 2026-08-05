import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';

const SERVER_ID = 'server-resource-alpha';
const ARTIFACT_ID = '33333333-3333-4333-8333-333333333333';

function serverInventory() {
  return {
    servers: [{
      id: SERVER_ID,
      name: 'alpha-worker',
      project: '/repos/alpha-worktree',
      status: 'running',
    }],
    repository_trees: [{
      root_repository: {
        repo_id: 'repo-alpha',
        canonical_root: '/repos/alpha',
        display_name: 'Alpha',
      },
      scopes: [{
        repo_id: 'repo-alpha-worktree',
        kind: 'temporary',
        canonical_root: '/repos/alpha-worktree',
        server_ids: [SERVER_ID],
      }],
    }],
  };
}

async function fixture(t) {
  const calls = [];
  const inventory = serverInventory();
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
        action: 'capture_logs',
        classification: 'available',
        target: { kind: 'service', id: body.target.id },
        artifact: {
          artifact_id: ARTIFACT_ID,
          captured_at: '2026-08-04T00:00:00Z',
          truncated: false,
        },
        artifact_content: {
          artifact_id: ARTIFACT_ID,
          text: 'exact service log\n',
        },
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
    accessStore: { isAdmin: () => false },
    guard: { checkOrigin: () => true },
    certManager: null,
    metrics: null,
    prefs: null,
  });
  const server = http.createServer((req, res) => api.handle(req, res, {
    email: 'operator@example.test',
  }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;

  async function request(body) {
    const response = await fetch(`${origin}/api/servers/logs`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: response.status, json: await response.json() };
  }
  return { calls, coordinator, inventory, request };
}

test('server logs resolve exact authoritative membership and use broker runtime capture', async (t) => {
  const { calls, request } = await fixture(t);

  const response = await request({ id: SERVER_ID });

  assert.equal(response.status, 200);
  assert.deepEqual(response.json, {
    text: 'exact service log\n',
    artifact: {
      artifact_id: ARTIFACT_ID,
      captured_at: '2026-08-04T00:00:00Z',
      retained: false,
      truncated: false,
    },
  });
  assert.deepEqual(calls, [{
    method: 'inventory', body: { maxAgeMs: 0 },
  }, {
    method: 'runtimeAction',
    body: {
      schema_version: 1,
      action: 'capture_logs',
      agent: 'devops-console:operator@example.test',
      root_repo: '/repos/alpha',
      temporary_repo: '/repos/alpha-worktree',
      target: { kind: 'service', id: SERVER_ID, name: 'alpha-worker' },
      purpose: 'development',
      ttl_seconds: null,
      kill_after_run: false,
      options: {},
    },
  }]);
});

test('server logs fail closed on duplicate ownership and contradictory artifacts', async (t) => {
  const { calls, coordinator, inventory, request } = await fixture(t);
  inventory.repository_trees[0].scopes.push({
    repo_id: 'repo-duplicate',
    kind: 'temporary',
    canonical_root: '/repos/duplicate',
    server_ids: [SERVER_ID],
  });

  const duplicate = await request({ id: SERVER_ID });
  assert.equal(duplicate.status, 409);
  assert.match(duplicate.json.error, /more than one repository scope/);
  assert.equal(calls.filter((call) => call.method === 'runtimeAction').length, 0);

  inventory.repository_trees[0].scopes.pop();
  coordinator.runtimeAction = async (body) => {
    calls.push({ method: 'runtimeAction', body });
    return {
      schema_version: 1,
      ok: true,
      action: 'capture_logs',
      classification: 'available',
      target: { kind: 'service', id: 'another-server' },
      artifact: { artifact_id: ARTIFACT_ID },
      artifact_content: {
        artifact_id: '44444444-4444-4444-8444-444444444444',
        text: 'must not be returned',
      },
    };
  };

  const contradictory = await request({ id: SERVER_ID });
  assert.equal(contradictory.status, 502);
  assert.match(contradictory.json.error, /invalid exact-service log artifact/);
});
