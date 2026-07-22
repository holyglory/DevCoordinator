import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { CoordError, coordinatorTimeoutFor, createCoordinator } from '../src/coordinator.mjs';

const TOKEN = 'fixture-coordinator-token-0123456789abcdef';

test('published HTTP contract describes normalized query-only inventory and its legacy projection', async () => {
  const contract = JSON.parse(await fsp.readFile(
    new URL('../docs/coordinator-http-api.json', import.meta.url),
    'utf8',
  ));
  assert.equal(contract.inventory_contract.schema_version, 2);
  assert.equal(contract.inventory_contract.read_semantics, 'query-only');
  assert.deepEqual(contract.inventory_contract.normalized_top_level, [
    'store',
    'repositories',
    'coordinator_sources',
    'docker_engines',
    'memberships',
    'resources',
    'leases',
    'port_assignments',
    'backup_evidence',
    'database_backups',
    'database_restore_events',
    'events',
    'unassigned_resources',
    'lifecycle_violations',
    'observations',
    'control_bindings',
  ]);
  assert.equal(contract.inventory_contract.compatibility_projection, 'v1_compatibility');
  assert.match(contract.inventory_contract.ordinary_inventory, /without runtime sampling or persistence/);
  assert.match(contract.inventory_contract.no_docker, /in-memory copy/);
  assert.match(contract.inventory_contract.no_docker, /never persists/);
  assert.match(contract.inventory_contract.no_docker, /without a Docker CLI\/daemon probe/);
  assert.match(contract.inventory_contract.no_docker, /project, name, and port query target/);
  assert.match(contract.inventory_contract.no_docker, /excludes unrelated services/);
  assert.equal(contract.state.persistence_model, 'normalized SQLite');
  assert.ok(contract.endpoints.POST.includes('/v1/ports/relocate'));
});

test('host observation receives a Docker-sized deadline without widening ordinary requests', () => {
  assert.equal(coordinatorTimeoutFor('/v1/observe'), 60_000);
  assert.equal(coordinatorTimeoutFor('/v1/inventory'), 60_000);
  assert.equal(coordinatorTimeoutFor('/v1/servers/start'), 15_000);
  assert.equal(coordinatorTimeoutFor('/v1/lifecycle/apply'), 600_000);
});

async function fixture(t, { tokenOnDisk = TOKEN, expectedToken = TOKEN, responder = null } = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-coordinator-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const tokenFile = path.join(dir, 'api-token');
  if (tokenOnDisk !== null) {
    await fsp.writeFile(tokenFile, `${tokenOnDisk}\n`, { mode: 0o600 });
    await fsp.chmod(tokenFile, 0o600);
  }
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const record = {
      method: req.method,
      path: req.url,
      authorization: req.headers.authorization ?? null,
      body: Buffer.concat(chunks).toString('utf8'),
    };
    requests.push(record);
    if (req.url === '/healthz') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, service: 'codex-dev-coordinator', version: 2 }));
      return;
    }
    if (req.headers.authorization !== `Bearer ${expectedToken}`) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }
    if (responder && await responder({ req, res, record, requests })) return;
    if (req.url === '/v1/projects/start') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        ok: false,
        partial: false,
        preflight_failed: true,
        classification: 'missing_dependency',
        action_errors: [{ error: 'Docker daemon unavailable' }],
      }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ leases: [], servers: [], project_usage: [] }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;
  const client = createCoordinator({
    config: {
      coordinatorUrl: `http://127.0.0.1:${port}`,
      coordinatorTokenFile: tokenFile,
      coordinatorAutostart: false,
      coordinatorScript: '/unused/dev_coordinator.py',
      coordinatorHome: dir,
      stateDir: dir,
    },
    log: null,
  });
  t.after(() => client.close());
  return { client, requests, tokenFile };
}

test('coordinator probe is anonymous while every protected request uses the private bearer token', async (t) => {
  const { client, requests } = await fixture(t);
  assert.equal(await client.probe(), true);
  await client.inventory({ maxAgeMs: 0 });
  assert.equal(requests[0].path, '/healthz');
  assert.equal(requests[0].authorization, null);
  assert.equal(requests[1].path, '/v1/inventory');
  assert.equal(requests[1].authorization, `Bearer ${TOKEN}`);
});

test('event pages preserve opaque cursors and explicit host observation identity', async (t) => {
  const page = {
    schema_version: 1,
    events: [{
      event_id: 'event-1',
      repo_id: 'repo-1',
      event_kind: 'server_failed',
      code: 'process_exited',
      message: 'web exited unexpectedly',
      occurred_at: '2026-07-18T12:00:00Z',
    }],
    next_cursor: 'opaque_cursor-1',
    has_more: false,
  };
  const responder = async ({ req, res }) => {
    if (req.url === '/v1/events?limit=200&after=opaque_cursor-0') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(page));
      return true;
    }
    if (req.url === '/v1/observe') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, observed: true }));
      return true;
    }
    return false;
  };
  const { client, requests } = await fixture(t, { responder });

  assert.deepEqual(await client.events({ after: 'opaque_cursor-0', limit: 200 }), page);
  assert.deepEqual(await client.observeHost({ agent: 'console:telegram', project: '/repo' }), {
    ok: true,
    observed: true,
  });
  assert.deepEqual(JSON.parse(requests.find((request) => request.path === '/v1/observe').body), {
    agent: 'console:telegram',
    project: '/repo',
  });
  assert.throws(
    () => client.events({ after: '', limit: 100 }),
    (error) => error instanceof CoordError && error.status === 400,
  );
  assert.throws(
    () => client.events({ after: null, limit: 501 }),
    (error) => error instanceof CoordError && error.status === 400,
  );
});

test('schema-v2 inventory projects only its declared v1 compatibility rows for Console consumers', async (t) => {
  const normalizedLease = {
    lease_id: 'lease-normalized',
    repo_id: 'repo-1',
    server_definition_id: 'server-1',
    source_id: 'source-1',
    port: 4317,
    status: 'active',
  };
  const normalizedAssignment = {
    assignment_id: 'assignment-normalized',
    repo_id: 'repo-1',
    server_name: 'web',
    port: 4317,
    status: 'active',
  };
  const compatibility = {
    coordinator_home: '/fixture/coordinator',
    state_path: '/fixture/coordinator/coordinator.sqlite3',
    project: null,
    urls: [],
    servers: [{ id: 'server-1', key: '/repo::web', project: '/repo', name: 'web' }],
    leases: [{ id: 'lease-console', project: '/repo', port: 4317, status: 'active' }],
    port_assignments: [{
      id: 'assignment-console',
      key: '/repo::web',
      project: '/repo',
      name: 'web',
      port: 4317,
      status: 'active',
    }],
    recent_events: [],
    docker: { available: true, containers: [], postgres: [] },
    postgres: [],
    backups: [],
    project_usage: [],
  };
  const payload = {
    schema_version: 2,
    repositories: [{ repo_id: 'repo-1', canonical_root: '/repo' }],
    leases: [normalizedLease],
    port_assignments: [normalizedAssignment],
    v1_compatibility: compatibility,
  };
  const responder = async ({ req, res }) => {
    if (req.url !== '/v1/inventory') return false;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(payload));
    return true;
  };
  const { client } = await fixture(t, { responder });

  const inventory = await client.inventory({ maxAgeMs: 0 });

  assert.deepEqual(inventory.leases, compatibility.leases);
  assert.deepEqual(inventory.port_assignments, compatibility.port_assignments);
  assert.deepEqual(inventory.servers, compatibility.servers);
  assert.deepEqual(inventory.repositories, payload.repositories,
    'the Console projection must retain non-conflicting normalized evidence');
  assert.deepEqual(inventory.v1_compatibility, compatibility,
    'the wire compatibility object must remain available and unmodified');
  assert.equal(inventory.leases[0].lease_id, undefined);
  assert.equal(inventory.port_assignments[0].assignment_id, undefined);
});

test('schema-v2 inventory derives current Docker stats and excludes absent compatibility rows', async (t) => {
  const currentStats = {
    source: 'normalized_observation',
    cpu_percent: 9,
    memory_usage_bytes: 9000,
  };
  const compatibility = {
    coordinator_home: '/fixture/coordinator',
    state_path: '/fixture/coordinator/coordinator.sqlite3',
    project: null,
    urls: [],
    servers: [],
    leases: [],
    port_assignments: [],
    recent_events: [],
    docker: {
      available: true,
      containers: [
        {
          id: 'full-1',
          host_resource_id: 'docker-1',
          name: 'current-running',
          status: 'running',
        },
        {
          id: 'full-2',
          host_resource_id: 'docker-2',
          name: 'current-stopped',
          status: 'stopped',
        },
        {
          id: 'full-3',
          host_resource_id: 'docker-3',
          name: 'canonical-stats-win',
          status: 'running',
          stats: currentStats,
        },
        {
          id: 'full-absent',
          host_resource_id: 'docker-absent',
          name: 'absent-history',
          status: 'running',
        },
      ],
      postgres: [],
    },
    postgres: [],
    backups: [],
    project_usage: [],
  };
  const payload = {
    schema_version: 2,
    repositories: [],
    docker_engines: [
      { engine_id: 'engine-1', host_id: 'host-1', capability_state: 'available' },
    ],
    resources: {
      docker: [
        { docker_resource_id: 'docker-1', engine_id: 'engine-1' },
        { docker_resource_id: 'docker-2', engine_id: 'engine-1' },
        { docker_resource_id: 'docker-3', engine_id: 'engine-1' },
      ],
    },
    observations: {
      snapshots: [
        {
          snapshot_id: 'snapshot-running',
          host_id: 'host-1',
          observer_domain: 'host-runtime-v2:full-docker',
          status: 'running',
          started_at: '2026-07-21T11:00:00Z',
          completed_at: null,
        },
        {
          snapshot_id: 'snapshot-current',
          host_id: 'host-1',
          observer_domain: 'host-runtime-v2:full-docker',
          status: 'completed',
          started_at: '2026-07-21T10:00:00Z',
          completed_at: '2026-07-21T10:00:10Z',
        },
        {
          snapshot_id: 'snapshot-old',
          host_id: 'host-1',
          observer_domain: 'host-runtime-v2:full-docker',
          status: 'completed',
          started_at: '2026-07-21T09:00:00Z',
          completed_at: '2026-07-21T09:00:10Z',
        },
      ],
      docker: [
        {
          docker_resource_id: 'docker-1', lifecycle: 'running',
          sampled_at: '2026-07-21T10:00:09Z',
        },
        {
          docker_resource_id: 'docker-2', lifecycle: 'stopped',
          sampled_at: '2026-07-21T10:00:09Z',
        },
        {
          docker_resource_id: 'docker-3', lifecycle: 'running',
          sampled_at: '2026-07-21T10:00:09Z',
        },
      ],
      telemetry: [
        {
          sample_id: 'sample-current-1',
          host_resource_kind: 'docker',
          host_resource_id: 'docker-1',
          sampled_at: '2026-07-21T10:00:08Z',
          cpu_percent: 1.25,
          memory_bytes: 48234496,
          network_rx_bytes: 11,
          network_tx_bytes: 12,
          block_read_bytes: 13,
          block_write_bytes: 14,
        },
        {
          sample_id: 'sample-old-1',
          host_resource_kind: 'docker',
          host_resource_id: 'docker-1',
          sampled_at: '2026-07-21T09:00:08Z',
          cpu_percent: 99,
          memory_bytes: 999,
        },
        {
          sample_id: 'sample-stopped-2',
          host_resource_kind: 'docker',
          host_resource_id: 'docker-2',
          sampled_at: '2026-07-21T10:00:08Z',
          cpu_percent: 2,
          memory_bytes: 2000,
        },
        {
          sample_id: 'sample-current-3',
          host_resource_kind: 'docker',
          host_resource_id: 'docker-3',
          sampled_at: '2026-07-21T10:00:08Z',
          cpu_percent: 88,
          memory_bytes: 88000,
        },
      ],
    },
    v1_compatibility: compatibility,
  };
  const responder = async ({ req, res }) => {
    if (req.url === '/v1/observe') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        schema_version: 2,
        status: 'completed',
        snapshot_id: 'snapshot-current',
        host_id: 'host-1',
        observer_domain: 'host-runtime-v2:full-docker',
        docker_available: true,
        capability_fingerprint: 'capability-proof',
        material_fingerprint: 'material-proof',
        completed_at: '2026-07-21T10:00:10Z',
      }));
      return true;
    }
    if (req.url !== '/v1/inventory') return false;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(payload));
    return true;
  };
  const { client } = await fixture(t, { responder });

  await client.observeHost({ agent: 'devops-console:metrics', project: '/repo' });
  const inventory = await client.inventory({ maxAgeMs: 0 });

  assert.deepEqual(inventory.docker.containers.map((item) => item.name), [
    'current-running', 'current-stopped', 'canonical-stats-win',
  ]);
  assert.deepEqual(inventory.docker.containers[0].stats, {
    source: 'normalized_observation',
    id: 'full-1',
    container_id: 'full-1',
    name: 'current-running',
    timestamp: '2026-07-21T10:00:08Z',
    live: true,
    cpu_percent: 1.25,
    memory_usage_bytes: 48234496,
    network_rx_bytes: 11,
    network_tx_bytes: 12,
    block_read_bytes: 13,
    block_write_bytes: 14,
  });
  assert.equal(inventory.docker.containers[1].stats, undefined,
    'stopped containers must never receive stale utilization');
  assert.deepEqual(inventory.docker.containers[2].stats, currentStats,
    'the canonical compatibility projection wins once the broker is updated');
  assert.equal(inventory.v1_compatibility.docker.containers.length, 4,
    'the wire compatibility graph must remain available and unmodified');
  assert.equal(inventory.v1_compatibility.docker.containers[0].stats, undefined);
});

test('Docker fallback rejects unproved, unavailable, stale, and stopped telemetry', async (t) => {
  const containers = [
    {
      id: 'full-null', host_resource_id: 'docker-null', name: 'explicit-null',
      status: 'running', stats: null,
    },
    {
      id: 'full-unavailable', host_resource_id: 'docker-unavailable',
      name: 'unavailable-engine', status: 'running',
    },
    {
      id: 'full-other-host', host_resource_id: 'docker-other-host',
      name: 'unproved-host', status: 'running',
    },
    {
      id: 'full-newer-window', host_resource_id: 'docker-newer-window',
      name: 'untrusted-newer-window', status: 'running',
    },
    {
      id: 'full-stopped-observation', host_resource_id: 'docker-stopped-observation',
      name: 'stopped-observation', status: 'running',
    },
  ];
  const compatibility = {
    coordinator_home: '/fixture/coordinator',
    state_path: '/fixture/coordinator/coordinator.sqlite3',
    project: null,
    urls: [],
    servers: [],
    leases: [],
    port_assignments: [],
    recent_events: [],
    docker: { available: true, containers, postgres: [] },
    postgres: [],
    backups: [],
    project_usage: [],
  };
  const payload = {
    schema_version: 2,
    docker_engines: [
      { engine_id: 'engine-1', host_id: 'host-1', capability_state: 'available' },
      { engine_id: 'engine-down', host_id: 'host-1', capability_state: 'unavailable' },
      { engine_id: 'engine-2', host_id: 'host-2', capability_state: 'available' },
    ],
    resources: {
      docker: [
        { docker_resource_id: 'docker-null', engine_id: 'engine-1' },
        { docker_resource_id: 'docker-unavailable', engine_id: 'engine-down' },
        { docker_resource_id: 'docker-other-host', engine_id: 'engine-2' },
        { docker_resource_id: 'docker-newer-window', engine_id: 'engine-1' },
        { docker_resource_id: 'docker-stopped-observation', engine_id: 'engine-1' },
      ],
    },
    observations: {
      snapshots: [
        {
          snapshot_id: 'approved-snapshot', host_id: 'host-1',
          observer_domain: 'host-runtime-v2:full-docker', status: 'completed',
          started_at: '2026-07-21T10:00:00Z', completed_at: '2026-07-21T10:00:10Z',
        },
        {
          snapshot_id: 'untrusted-newer-snapshot', host_id: 'host-1',
          observer_domain: 'host-runtime-v2:full-docker', status: 'completed',
          started_at: '2026-07-21T11:00:00Z', completed_at: '2026-07-21T11:00:10Z',
        },
        {
          snapshot_id: 'other-host-snapshot', host_id: 'host-2',
          observer_domain: 'host-runtime-v2:full-docker', status: 'completed',
          started_at: '2026-07-21T10:00:00Z', completed_at: '2026-07-21T10:00:10Z',
        },
      ],
      docker: [
        {
          docker_resource_id: 'docker-null', lifecycle: 'running',
          sampled_at: '2026-07-21T10:00:09Z',
        },
        {
          docker_resource_id: 'docker-unavailable', lifecycle: 'running',
          sampled_at: '2026-07-21T10:00:09Z',
        },
        {
          docker_resource_id: 'docker-other-host', lifecycle: 'running',
          sampled_at: '2026-07-21T10:00:09Z',
        },
        {
          docker_resource_id: 'docker-newer-window', lifecycle: 'running',
          sampled_at: '2026-07-21T11:00:09Z',
        },
        {
          docker_resource_id: 'docker-stopped-observation', lifecycle: 'stopped',
          sampled_at: '2026-07-21T10:00:09Z',
        },
      ],
      telemetry: [
        {
          sample_id: 'null-sample', host_resource_kind: 'docker',
          host_resource_id: 'docker-null', sampled_at: '2026-07-21T10:00:08Z',
          cpu_percent: 1, memory_bytes: 1000,
        },
        {
          sample_id: 'unavailable-sample', host_resource_kind: 'docker',
          host_resource_id: 'docker-unavailable', sampled_at: '2026-07-21T10:00:08Z',
          cpu_percent: 2, memory_bytes: 2000,
        },
        {
          sample_id: 'other-host-sample', host_resource_kind: 'docker',
          host_resource_id: 'docker-other-host', sampled_at: '2026-07-21T10:00:08Z',
          cpu_percent: 3, memory_bytes: 3000,
        },
        {
          sample_id: 'newer-window-sample', host_resource_kind: 'docker',
          host_resource_id: 'docker-newer-window', sampled_at: '2026-07-21T11:00:08Z',
          cpu_percent: 4, memory_bytes: 4000,
        },
        {
          sample_id: 'stopped-observation-sample', host_resource_kind: 'docker',
          host_resource_id: 'docker-stopped-observation', sampled_at: '2026-07-21T10:00:08Z',
          cpu_percent: 5, memory_bytes: 5000,
        },
      ],
    },
    v1_compatibility: compatibility,
  };
  const responder = async ({ req, res }) => {
    if (req.url === '/v1/observe') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        schema_version: 2,
        status: 'completed',
        snapshot_id: 'approved-snapshot',
        host_id: 'host-1',
        observer_domain: 'host-runtime-v2:full-docker',
        docker_available: true,
        capability_fingerprint: 'approved-capability',
        material_fingerprint: 'approved-material',
        completed_at: '2026-07-21T10:00:10Z',
      }));
      return true;
    }
    if (req.url !== '/v1/inventory') return false;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(payload));
    return true;
  };
  const { client } = await fixture(t, { responder });

  await client.observeHost({ agent: 'devops-console:metrics', project: '/repo' });
  const first = await client.inventory({ maxAgeMs: 0 });
  const cached = await client.inventory({ maxAgeMs: 60_000 });

  assert.equal(first.docker.containers[0].stats, null,
    'an explicit canonical null is not replaced by fallback telemetry');
  for (const item of first.docker.containers.slice(1)) {
    assert.equal(item.stats, undefined, `${item.name} must not receive unproved telemetry`);
  }
  assert.equal(cached.v1_compatibility.docker.containers[0].stats, null);
  assert.equal(cached.v1_compatibility.docker.containers[1].stats, undefined,
    're-projecting a cached wire graph must not mutate its compatibility rows');
});

test('schema-v2 inventory without a complete v1 compatibility projection fails closed', async (t) => {
  const responder = async ({ req, res }) => {
    if (req.url !== '/v1/inventory') return false;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      schema_version: 2,
      leases: [{ lease_id: 'lease-normalized', repo_id: 'repo-1', port: 4317 }],
      port_assignments: [{
        assignment_id: 'assignment-normalized',
        repo_id: 'repo-1',
        server_name: 'web',
        port: 4317,
      }],
      v1_compatibility: { leases: [], port_assignments: [] },
    }));
    return true;
  };
  const { client } = await fixture(t, { responder });

  await assert.rejects(
    () => client.inventory({ maxAgeMs: 0 }),
    (err) => err instanceof CoordError
      && err.status === 502
      && /compatibility projection is incomplete/.test(err.message),
  );
});

for (const [label, tokenOnDisk] of [['missing', null], ['wrong', `${TOKEN}-wrong`]]) {
  test(`${label} coordinator credential fails closed without leaking token material`, async (t) => {
    const { client } = await fixture(t, { tokenOnDisk });
    await assert.rejects(
      () => client.inventory({ maxAgeMs: 0 }),
      (err) => {
        assert.ok(err instanceof CoordError);
        assert.equal(err.status, 401);
        assert.match(err.message, /authentication failed/);
        assert.doesNotMatch(err.message, /0123456789abcdef/);
        return true;
      },
    );
    assert.doesNotMatch(String(client.status().lastError), /0123456789abcdef/);
  });
}

for (const mode of [0o644, 0o700]) {
  test(`token-file mode ${mode.toString(8)} is rejected before a protected request is sent`, async (t) => {
    const { client, tokenFile, requests } = await fixture(t);
    fs.chmodSync(tokenFile, mode);
    await assert.rejects(
      () => client.inventory({ maxAgeMs: 0 }),
      (err) => err instanceof CoordError && err.status === 503 && /permissions are unsafe/.test(err.message),
    );
    assert.equal(requests.length, 0);
  });
}

test('symlink token file is rejected before its target can become an Authorization header', async (t) => {
  const { client, tokenFile, requests } = await fixture(t);
  const target = path.join(path.dirname(tokenFile), 'symlink-target-token');
  const targetToken = 'symlink-target-secret-0123456789abcdef';
  fs.writeFileSync(target, `${targetToken}\n`, { mode: 0o600 });
  fs.unlinkSync(tokenFile);
  fs.symlinkSync(target, tokenFile);

  await assert.rejects(
    () => client.inventory({ maxAgeMs: 0 }),
    (err) => {
      assert.ok(err instanceof CoordError);
      assert.equal(err.status, 503);
      assert.match(err.message, /regular non-symlink file/);
      assert.doesNotMatch(err.message, new RegExp(targetToken));
      return true;
    },
  );
  assert.equal(requests.length, 0);
  assert.doesNotMatch(String(client.status().lastError), new RegExp(targetToken));
});

test('non-regular token file is rejected without attempting to read it', async (t) => {
  const { client, tokenFile, requests } = await fixture(t);
  fs.unlinkSync(tokenFile);
  fs.mkdirSync(tokenFile, { mode: 0o700 });

  await assert.rejects(
    () => client.inventory({ maxAgeMs: 0 }),
    (err) => err instanceof CoordError && err.status === 503 && /regular non-symlink file/.test(err.message),
  );
  assert.equal(requests.length, 0);
});

test('oversized token file is rejected before token material is read or sent', async (t) => {
  const { client, tokenFile, requests } = await fixture(t);
  const oversizedSecret = `oversized-secret-${'x'.repeat(4097)}`;
  fs.writeFileSync(tokenFile, oversizedSecret, { mode: 0o600 });

  await assert.rejects(
    () => client.inventory({ maxAgeMs: 0 }),
    (err) => {
      assert.ok(err instanceof CoordError);
      assert.equal(err.status, 503);
      assert.match(err.message, /oversized/);
      assert.doesNotMatch(err.message, /oversized-secret/);
      return true;
    },
  );
  assert.equal(requests.length, 0);
  assert.doesNotMatch(String(client.status().lastError), /oversized-secret/);
});

test('token path replacement at open time fails closed instead of following the replacement', async (t) => {
  const { client, tokenFile, requests } = await fixture(t);
  const replacement = path.join(path.dirname(tokenFile), 'replacement-token');
  const replacementToken = 'replacement-secret-0123456789abcdef';
  fs.writeFileSync(replacement, `${replacementToken}\n`, { mode: 0o600 });

  const originalOpenSync = fs.openSync;
  let replacementInjected = false;
  fs.openSync = function guardedOpenSync(file, flags, ...rest) {
    if (!replacementInjected && path.resolve(String(file)) === path.resolve(tokenFile)) {
      replacementInjected = true;
      fs.unlinkSync(tokenFile);
      fs.symlinkSync(replacement, tokenFile);
    }
    return originalOpenSync.call(this, file, flags, ...rest);
  };
  try {
    await assert.rejects(
      () => client.inventory({ maxAgeMs: 0 }),
      (err) => {
        assert.ok(err instanceof CoordError);
        assert.equal(err.status, 503);
        assert.match(err.message, /regular non-symlink file/);
        assert.doesNotMatch(err.message, new RegExp(replacementToken));
        return true;
      },
    );
  } finally {
    fs.openSync = originalOpenSync;
  }
  assert.equal(replacementInjected, true, 'fixture must replace the path immediately before the credential open');
  assert.equal(requests.length, 0);
  assert.doesNotMatch(String(client.status().lastError), new RegExp(replacementToken));
});

test('HTTP 200 project reports with ok=false remain failures with structured evidence', async (t) => {
  const { client } = await fixture(t);
  await assert.rejects(
    () => client.projectAction('start', { agent: 'console-test', project: '/repo' }),
    (err) => {
      assert.ok(err instanceof CoordError);
      assert.equal(err.status, 409);
      assert.equal(err.body?.preflight_failed, true);
      assert.match(err.message, /failed preflight/);
      assert.match(err.message, /Docker daemon unavailable/);
      return true;
    },
  );
});

test('lifecycle client uses only fixed coordinator endpoints and preserves exact plan payloads', async (t) => {
  const responder = async ({ req, res }) => {
    const payloads = {
      '/v1/archives': { archives: [] },
      '/v1/lifecycle/plan': {
        plan_id: 'plan-fixture-1',
        plan_fingerprint: 'fingerprint-fixture-1',
        effects: ['stop'],
        retained: ['history'],
        deleted: [],
        blockers: [],
      },
      '/v1/lifecycle/apply': {
        ok: true, status: 'completed', partial: false, needs_attention: false,
      },
      '/v1/lifecycle/restore': {
        ok: true, status: 'completed', partial: false, needs_attention: false,
      },
    };
    if (!Object.hasOwn(payloads, req.url)) return false;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(payloads[req.url]));
    return true;
  };
  const { client, requests } = await fixture(t, { responder });
  const planBody = {
    target_kind: 'project',
    target_id: 'repo-fixture-1',
    action: 'archive',
    reason: 'fixture reason',
    agent: 'devops-console:owner@example.test',
  };
  const applyBody = {
    plan_id: 'plan-fixture-1',
    plan_fingerprint: 'fingerprint-fixture-1',
    confirmation_phrase: 'PURGE project repo-fixture-1',
  };
  const restoreBody = {
    target_kind: 'project',
    target_id: 'repo-fixture-1',
    reason: 'fixture restore',
    agent: 'devops-console:owner@example.test',
    explicit: true,
  };

  assert.deepEqual(await client.lifecycleArchives(), { archives: [] });
  assert.equal((await client.lifecyclePlan(planBody)).plan_id, 'plan-fixture-1');
  assert.equal((await client.lifecycleApply(applyBody)).status, 'completed');
  assert.equal((await client.lifecycleRestore(restoreBody)).status, 'completed');

  assert.deepEqual(requests.map((request) => [request.method, request.path]), [
    ['GET', '/v1/archives'],
    ['POST', '/v1/lifecycle/plan'],
    ['POST', '/v1/lifecycle/apply'],
    ['POST', '/v1/lifecycle/restore'],
  ]);
  assert.equal(requests.every((request) => request.authorization === `Bearer ${TOKEN}`), true);
  assert.deepEqual(JSON.parse(requests[1].body), planBody);
  assert.deepEqual(JSON.parse(requests[2].body), applyBody);
  assert.deepEqual(JSON.parse(requests[3].body), restoreBody);
});

for (const [endpoint, invoke, payload, evidence] of [
  [
    '/v1/lifecycle/apply',
    (client) => client.lifecycleApply({ plan_id: 'p', plan_fingerprint: 'f' }),
    {
      ok: false,
      status: 'partial',
      partial: true,
      needs_attention: true,
      action_errors: [{ error: 'container cleanup failed' }],
    },
    'container cleanup failed',
  ],
  [
    '/v1/lifecycle/restore',
    (client) => client.lifecycleRestore({
      target_kind: 'server', target_id: 's', reason: 'fixture', agent: 'test', explicit: true,
    }),
    {
      ok: false,
      status: 'needs_attention',
      partial: false,
      needs_attention: true,
      blockers: [{ message: 'manual recovery required' }],
    },
    'manual recovery required',
  ],
]) {
  test(`${endpoint} HTTP 200 incomplete result remains a visible lifecycle failure`, async (t) => {
    const responder = async ({ req, res }) => {
      if (req.url !== endpoint) return false;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(payload));
      return true;
    };
    const { client } = await fixture(t, { responder });
    await assert.rejects(
      () => invoke(client),
      (err) => {
        assert.ok(err instanceof CoordError);
        assert.equal(err.status, 409);
        assert.deepEqual(err.body, payload);
        assert.match(err.message, new RegExp(evidence));
        return true;
      },
    );
  });
}

test('a completed mutation detaches an older in-flight inventory read before it can repopulate the cache', async (t) => {
  let releaseStale;
  const staleGate = new Promise((resolve) => { releaseStale = resolve; });
  let firstSeen;
  const firstSeenPromise = new Promise((resolve) => { firstSeen = resolve; });
  let secondSeen;
  const secondSeenPromise = new Promise((resolve) => { secondSeen = resolve; });
  let inventoryRequests = 0;
  const responder = async ({ req, res }) => {
    if (req.url === '/v1/inventory') {
      inventoryRequests += 1;
      if (inventoryRequests === 1) {
        firstSeen();
        await staleGate;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ snapshot: 'stale' }));
        return true;
      }
      secondSeen();
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ snapshot: 'fresh' }));
      return true;
    }
    if (req.url === '/v1/ports/lease') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: 'lease-after-stale-read' }));
      return true;
    }
    return false;
  };
  const { client } = await fixture(t, { responder });

  const staleRead = client.inventory({ maxAgeMs: 5000 });
  await firstSeenPromise;
  await client.leasePort({ agent: 'console-test', project: '/repo' });
  const freshRead = client.inventory({ maxAgeMs: 5000 });
  const detached = await Promise.race([
    secondSeenPromise.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 250)),
  ]);
  releaseStale();
  await staleRead;
  const fresh = await freshRead;

  assert.equal(detached, true, 'post-mutation inventory must start a new request instead of joining stale work');
  assert.equal(fresh.snapshot, 'fresh');
  assert.equal((await client.inventory({ maxAgeMs: 5000 })).snapshot, 'fresh',
    'the detached stale response must not overwrite the fresh cache');
  assert.equal(inventoryRequests, 2);
});
