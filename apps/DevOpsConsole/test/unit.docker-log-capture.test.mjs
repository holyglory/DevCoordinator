import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';

const RESOURCE_ID = 'container-resource-alpha';
const ARTIFACT_ID = '11111111-1111-4111-8111-111111111111';

function dockerInventory() {
  return {
    docker: {
      containers: [{
        host_resource_id: RESOURCE_ID,
        docker_resource_id: RESOURCE_ID,
        name: 'alpha-web-1',
        project: '/repos/alpha-worktree',
        metadata_source: 'docker_labels',
      }],
    },
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
        container_resource_ids: [RESOURCE_ID],
      }],
    }],
  };
}

async function fixture(t) {
  const calls = [];
  const inventory = dockerInventory();
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
        target: { kind: 'docker', id: body.target.id },
        artifact: {
          artifact_id: ARTIFACT_ID,
          captured_at: '2026-07-31T00:00:00Z',
          truncated: false,
        },
        artifact_content: {
          artifact_id: ARTIFACT_ID,
          text: 'exact container log\n',
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
    const response = await fetch(`${origin}/api/docker/logs`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: response.status, json: await response.json() };
  }
  return { calls, coordinator, inventory, request };
}

test('container logs resolve an immutable ID to one scope and use broker runtime capture', async (t) => {
  const { calls, request } = await fixture(t);

  const response = await request({ resource_id: RESOURCE_ID });

  assert.equal(response.status, 200);
  assert.deepEqual(response.json, {
    text: 'exact container log\n',
    artifact: {
      artifact_id: ARTIFACT_ID,
      captured_at: '2026-07-31T00:00:00Z',
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
      target: { kind: 'docker', id: RESOURCE_ID, name: 'alpha-web-1' },
      purpose: 'development',
      ttl_seconds: null,
      kill_after_run: false,
      options: {},
    },
  }]);
});

test('container logs reject the removed name-based request before inventory', async (t) => {
  const { calls, request } = await fixture(t);

  const response = await request({ name: 'alpha-web-1', tail: 120 });

  assert.equal(response.status, 400);
  assert.match(response.json.error, /unsupported container log field/);
  assert.deepEqual(calls, []);
});

test('container logs fail closed on duplicate ownership and contradictory artifacts', async (t) => {
  const { calls, coordinator, inventory, request } = await fixture(t);
  inventory.repository_trees[0].scopes.push({
    repo_id: 'repo-duplicate',
    kind: 'temporary',
    canonical_root: '/repos/duplicate',
    container_resource_ids: [RESOURCE_ID],
  });

  const duplicate = await request({ resource_id: RESOURCE_ID });
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
      target: { kind: 'docker', id: 'different-container' },
      artifact: { artifact_id: ARTIFACT_ID },
      artifact_content: {
        artifact_id: '22222222-2222-4222-8222-222222222222',
        text: 'must not be returned',
      },
    };
  };

  const contradictory = await request({ resource_id: RESOURCE_ID });
  assert.equal(contradictory.status, 502);
  assert.match(contradictory.json.error, /invalid exact-container log artifact/);
});
