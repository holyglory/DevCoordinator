// Unit tests for src/routes.mjs — slug validation matrix, duplicate 409,
// atomic persistence across a reload, and resolve() for kind=port and
// kind=server (running/stopped/missing). The route store is REAL and writes
// real files under fs.mkdtemp dirs; only the coordinator is a stub object
// exposing serversRaw() (it is not the module under test).

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createRouteStore, RouteError } from '../src/routes.mjs';

const CONFIG = {
  consoleHost: 'panel.vr.ae',
  coordinatorUrl: 'http://127.0.0.1:29876',
};

async function makeStore(t, { config = CONFIG } = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-routes-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'routes.json');
  const store = createRouteStore({ file, config });
  await store.load();
  return { store, file, dir };
}

async function assertRejectsRoute(promise, status, messageRe) {
  await assert.rejects(promise, (err) => {
    assert.ok(err instanceof RouteError, `expected RouteError, got ${err?.constructor?.name}: ${err?.message}`);
    assert.equal(err.status, status, `expected status ${status}, got ${err.status} (${err.message})`);
    if (messageRe) assert.match(err.message, messageRe);
    return true;
  });
}

test('slug validation: valid slugs are accepted and default to auth=google', async (t) => {
  const { store } = await makeStore(t);
  const valid = ['app', 'a', '9to5', 'my-app-2', 'a'.repeat(63)];

  for (const [i, slug] of valid.entries()) {
    const route = await store.create({ slug, kind: 'port', port: 5000 + i });
    assert.equal(route.slug, slug);
    assert.equal(route.kind, 'port');
    assert.equal(route.port, 5000 + i);
    assert.equal(route.auth, 'google', 'default-deny: new routes must default to google auth');
    assert.ok(route.createdAt && route.updatedAt);
  }
  assert.equal(store.list().length, valid.length);

  // Returned objects are copies — mutating them must not corrupt the store.
  const copy = store.get('app');
  copy.auth = 'public';
  assert.equal(store.get('app').auth, 'google');
});

test('slug validation: uppercase, hyphen placement, length, and garbage are 400s', async (t) => {
  const { store } = await makeStore(t);

  const invalid = [
    'MyApp', // uppercase
    'APP', // uppercase
    '-app', // leading hyphen
    'app-', // trailing hyphen
    'a'.repeat(64), // 64 chars (max is 63)
    'a.b', // dot — must be a single label
    'app_1', // underscore
    'app!', // punctuation
    '', // empty
    '   ', // whitespace only
  ];
  for (const slug of invalid) {
    await assertRejectsRoute(
      store.create({ slug, kind: 'port', port: 8000 }),
      400,
      undefined,
    );
  }
  await assertRejectsRoute(store.create({ slug: 42, kind: 'port', port: 8000 }), 400, /required/);
  await assertRejectsRoute(store.create({ kind: 'port', port: 8000 }), 400, /required/);

  assert.equal(store.list().length, 0, 'no invalid slug may be stored');

  // Boundary partner: 63 chars is fine.
  await store.create({ slug: 'b'.repeat(63), kind: 'port', port: 8001 });
});

test('slug validation: reserved set rejected, including the console label from config', async (t) => {
  const { store } = await makeStore(t); // consoleHost panel.vr.ae → 'panel' reserved too

  for (const slug of ['console', 'www', 'api', 'auth', 'static', 'healthz', 'panel']) {
    await assertRejectsRoute(store.create({ slug, kind: 'port', port: 8000 }), 400, /reserved/);
  }
});

test('duplicate slug → 409, first route untouched', async (t) => {
  const { store } = await makeStore(t);
  await store.create({ slug: 'dup', kind: 'port', port: 5173 });

  await assertRejectsRoute(store.create({ slug: 'dup', kind: 'port', port: 9999 }), 409, /already exists/);
  assert.equal(store.get('dup').port, 5173);
});

test('field validation: kind, port range, coordinator port, server identity', async (t) => {
  const { store } = await makeStore(t);

  await assertRejectsRoute(store.create({ slug: 'x1', kind: 'weird' }), 400, /kind/);
  await assertRejectsRoute(store.create({ slug: 'x2', kind: 'port' }), 400, /port/);
  await assertRejectsRoute(store.create({ slug: 'x3', kind: 'port', port: 0 }), 400, /port/);
  await assertRejectsRoute(store.create({ slug: 'x4', kind: 'port', port: 65536 }), 400, /port/);
  await assertRejectsRoute(store.create({ slug: 'x5', kind: 'port', port: 'abc' }), 400, /port/);
  // Security invariant: never allow a public route onto the coordinator API.
  await assertRejectsRoute(store.create({ slug: 'x6', kind: 'port', port: 29876 }), 400, /coordinator/);
  await assertRejectsRoute(store.create({ slug: 'x7', kind: 'server' }), 400, /project/);
  await assertRejectsRoute(store.create({ slug: 'x8', kind: 'server', project: '/p' }), 400, /serverName/);
  await assertRejectsRoute(store.create({ slug: 'x9', kind: 'port', port: 80, auth: 'nope' }), 400, /auth/);

  // Numeric string ports are normalized to numbers.
  const r = await store.create({ slug: 'ok', kind: 'port', port: '5173' });
  assert.equal(r.port, 5173);
});

test('persistence is atomic and survives a reload', async (t) => {
  const { store, file } = await makeStore(t);

  await store.create({ slug: 'web', kind: 'port', port: 5173, title: '  Vite dev  ' });
  await store.create({
    slug: 'srv',
    kind: 'server',
    project: '/repo/demo/', // trailing slash must be normalized away
    serverName: 'backend',
    auth: 'public',
  });
  await store.update('web', { auth: 'public' });
  await store.create({ slug: 'gone', kind: 'port', port: 6000 });
  await store.remove('gone');

  // No stray tmp file after the atomic tmp+rename dance.
  await assert.rejects(fsp.stat(`${file}.tmp`), { code: 'ENOENT' });

  // On-disk shape is the documented v1 schema.
  const onDisk = JSON.parse(await fsp.readFile(file, 'utf8'));
  assert.equal(onDisk.version, 1);
  assert.deepEqual(Object.keys(onDisk.routes).sort(), ['srv', 'web']);

  // A brand-new store instance reading the same file sees identical state.
  const reloaded = createRouteStore({ file, config: CONFIG });
  await reloaded.load();
  assert.deepEqual(reloaded.list(), store.list());

  const srv = reloaded.get('srv');
  assert.equal(srv.project, '/repo/demo');
  assert.equal(srv.serverName, 'backend');
  assert.equal(srv.auth, 'public');
  assert.equal(srv.port, undefined);

  const web = reloaded.get('web');
  assert.equal(web.auth, 'public'); // update persisted
  assert.equal(web.title, 'Vite dev'); // trimmed
  assert.equal(reloaded.get('gone'), null); // removal persisted
});

test('corrupt store file: preserved as backup, store starts empty', async (t) => {
  const { store, file, dir } = await makeStore(t);
  await fsp.writeFile(file, 'this is { not json', 'utf8');

  await store.load();
  assert.deepEqual(store.list(), []);

  const names = await fsp.readdir(dir);
  assert.ok(
    names.some((n) => n.startsWith('routes.json.corrupt-')),
    `expected a corrupt-backup file, saw: ${names.join(', ')}`,
  );
});

test('update: patch semantics, slug immutable, 404 for unknown', async (t) => {
  const { store } = await makeStore(t);
  await store.create({ slug: 'app', kind: 'port', port: 3000 });

  const patched = await store.update('app', { auth: 'public', title: 'My app' });
  assert.equal(patched.auth, 'public');
  assert.equal(patched.title, 'My app');
  assert.equal(patched.port, 3000);

  // Clearing the title with an empty string removes it.
  const untitled = await store.update('app', { title: '' });
  assert.equal(untitled.title, undefined);

  // kind switch to server requires the server identity...
  await assertRejectsRoute(store.update('app', { kind: 'server' }), 400, /project and serverName/);
  // ...and works when provided, dropping the stale port.
  const switched = await store.update('app', { kind: 'server', project: '/repo/x', serverName: 'web' });
  assert.equal(switched.port, undefined);
  assert.equal(switched.project, '/repo/x');

  await assertRejectsRoute(store.update('app', { slug: 'other' }), 400, /slug cannot be changed/);
  await assertRejectsRoute(store.update('missing', { auth: 'public' }), 404, /not found/);
  await assertRejectsRoute(store.remove('missing'), 404, /not found/);
});

test('resolve: kind=port returns the fixed port without touching the coordinator', async (t) => {
  const { store } = await makeStore(t);
  await store.create({ slug: 'web', kind: 'port', port: 5173 });

  const coordinatorMustNotBeCalled = {
    serversRaw: async () => {
      throw new Error('resolve(kind=port) must not consult the coordinator');
    },
  };
  assert.deepEqual(await store.resolve('web', coordinatorMustNotBeCalled), { port: 5173 });
});

test('resolve: kind=server running / stopped / missing / coordinator down', async (t) => {
  const { store } = await makeStore(t);
  await store.create({ slug: 'srv', kind: 'server', project: '/repo/demo', serverName: 'backend' });

  // Running → its port.
  const running = {
    serversRaw: async () => [
      { id: 's-other', name: 'other', project: '/repo/demo', status: 'running', port: 1111 },
      { id: 's-1', name: 'backend', project: '/repo/demo', status: 'running', port: 4321 },
    ],
  };
  assert.deepEqual(await store.resolve('srv', running), {
    port: 4321,
    server: { id: 's-1', name: 'backend', project: '/repo/demo', status: 'running' },
  });

  // Stopped → port null + reason + server identity for the error page.
  const stopped = {
    serversRaw: async () => [
      { id: 's-1', name: 'backend', project: '/repo/demo', status: 'stopped', port: null },
    ],
  };
  assert.deepEqual(await store.resolve('srv', stopped), {
    port: null,
    reason: 'server stopped',
    server: { id: 's-1', name: 'backend', project: '/repo/demo', status: 'stopped' },
  });

  // Several records with the same identity → prefer the running one.
  const mixed = {
    serversRaw: async () => [
      { id: 's-old', name: 'backend', project: '/repo/demo', status: 'stopped', port: 1111 },
      { id: 's-new', name: 'backend', project: '/repo/demo', status: 'running', port: 2222 },
    ],
  };
  assert.equal((await store.resolve('srv', mixed)).port, 2222);

  // Missing entirely.
  const empty = { serversRaw: async () => [] };
  assert.deepEqual(await store.resolve('srv', empty), { port: null, reason: 'server not found' });

  // Wrong project must not match a same-named server elsewhere.
  const wrongProject = {
    serversRaw: async () => [
      { id: 's-x', name: 'backend', project: '/repo/OTHER', status: 'running', port: 9999 },
    ],
  };
  assert.deepEqual(await store.resolve('srv', wrongProject), { port: null, reason: 'server not found' });

  // Coordinator down → resolvable error, not a throw.
  const down = {
    serversRaw: async () => {
      throw new Error('connect ECONNREFUSED 127.0.0.1:29876');
    },
  };
  const failed = await store.resolve('srv', down);
  assert.equal(failed.port, null);
  assert.match(failed.reason, /^coordinator unavailable: /);

  // Unknown slug.
  assert.deepEqual(await store.resolve('nope', empty), { port: null, reason: 'route not found' });
});

test('resolve: kind=server never resolves to the coordinator API port (invariant #1)', async (t) => {
  const { store } = await makeStore(t); // coordinator port 29876 from CONFIG
  await store.create({ slug: 'srv', kind: 'server', project: '/repo/demo', serverName: 'backend', auth: 'public' });

  // A coordinator server record that happens to be running on the coordinator's
  // own API port must NOT be proxied to — even for a public route. validatePort
  // never runs on this path, so resolve() must screen the resolved port itself.
  const onCoordinatorPort = {
    serversRaw: async () => [
      { id: 's-1', name: 'backend', project: '/repo/demo', status: 'running', port: 29876 },
    ],
  };
  const resolved = await store.resolve('srv', onCoordinatorPort);
  assert.equal(resolved.port, null, 'must refuse a server record on the coordinator API port');
  assert.match(resolved.reason, /coordinator API port/);
});

test('load: a disk-seeded route on the coordinator API port is dropped (invariant #1)', async (t) => {
  const { store, file } = await makeStore(t); // coordinator port 29876

  // Hand-write a routes.json whose kind:'port' route targets 29876 — this path
  // bypasses create()/validatePort entirely, so load() must reject it.
  const seeded = {
    version: 1,
    routes: {
      evil: {
        slug: 'evil',
        kind: 'port',
        port: 29876, // the coordinator API port
        auth: 'public',
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
      },
      safe: {
        slug: 'safe',
        kind: 'port',
        port: 5173,
        auth: 'public',
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
      },
    },
  };
  await fsp.writeFile(file, `${JSON.stringify(seeded, null, 2)}\n`, 'utf8');

  await store.load();

  // The dangerous route must not exist at all after load; the safe one survives.
  assert.equal(store.get('evil'), null, 'route targeting the coordinator API port must be dropped on load');
  assert.equal(store.get('safe')?.port, 5173);

  // And it must not be resolvable/proxyable either.
  const noCoord = { serversRaw: async () => [] };
  assert.deepEqual(await store.resolve('evil', noCoord), { port: null, reason: 'route not found' });
});
