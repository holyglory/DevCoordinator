import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { CoordError, createCoordinator } from '../src/coordinator.mjs';

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
  assert.equal(contract.state.persistence_model, 'normalized SQLite');
  assert.ok(contract.endpoints.POST.includes('/v1/ports/relocate'));
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
