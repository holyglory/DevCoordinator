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

import {
  createRouteStore,
  parsePublishedPorts,
  publishedContainerPorts,
  publishedHostPort,
  RouteError,
} from '../src/routes.mjs';

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

// ---------------------------------------------------------------------------
// kind=docker: published-ports parsing and container route resolution
// ---------------------------------------------------------------------------

test('parsePublishedPorts: v4/v6 pairs, ranges, remaps, and junk-resistance', () => {
  // Plain dual-stack publish (the common compose case).
  assert.deepEqual(parsePublishedPorts('0.0.0.0:5001->5001/tcp, :::5001->5001/tcp'), [
    { hostAddr: '0.0.0.0', hostPort: 5001, containerPort: 5001 },
    { hostAddr: '::', hostPort: 5001, containerPort: 5001 },
  ]);
  // Host/container remap.
  assert.deepEqual(parsePublishedPorts('127.0.0.1:9010->9000/tcp'), [
    { hostAddr: '127.0.0.1', hostPort: 9010, containerPort: 9000 },
  ]);
  // Ranges expand positionally.
  assert.deepEqual(parsePublishedPorts('0.0.0.0:9000-9001->9000-9001/tcp'), [
    { hostAddr: '0.0.0.0', hostPort: 9000, containerPort: 9000 },
    { hostAddr: '0.0.0.0', hostPort: 9001, containerPort: 9001 },
  ]);
  // Exposed-only (no publish), udp, empty, and malformed entries are skipped.
  assert.deepEqual(parsePublishedPorts('5432/tcp'), []);
  assert.deepEqual(parsePublishedPorts('0.0.0.0:5353->5353/udp'), []);
  assert.deepEqual(parsePublishedPorts(''), []);
  assert.deepEqual(parsePublishedPorts(null), []);
  assert.deepEqual(parsePublishedPorts('0.0.0.0:9000-9002->9000-9001/tcp'), [], 'mismatched range must be dropped');
  // Bracketed IPv6 literal.
  assert.deepEqual(parsePublishedPorts('[::]:8080->80/tcp'), [
    { hostAddr: '::', hostPort: 8080, containerPort: 80 },
  ]);
});

test('publishedHostPort / publishedContainerPorts: loopback preference and reachability', () => {
  const dual = parsePublishedPorts('0.0.0.0:5001->5001/tcp, :::5001->5001/tcp');
  assert.equal(publishedHostPort(dual, 5001), 5001);
  assert.equal(publishedHostPort(dual, 80), null, 'unpublished container port must not resolve');

  // v4 binding wins when both exist on different host ports.
  const mixed = parsePublishedPorts(':::9100->9000/tcp, 0.0.0.0:9110->9000/tcp');
  assert.equal(publishedHostPort(mixed, 9000), 9110);

  // A v6-ONLY publish must NOT resolve: the proxy dials v4 loopback, a
  // separate socket namespace — accepting it would 502 or, worse, cross-wire
  // the route into an unrelated v4 process on the same port number.
  const v6only = parsePublishedPorts(':::5000->3000/tcp');
  assert.equal(publishedHostPort(v6only, 3000), null);
  assert.deepEqual(publishedContainerPorts('::1:5000->3000/tcp'), []);

  // A publish bound to a specific external address is NOT loopback-reachable.
  const external = parsePublishedPorts('192.168.1.50:8080->80/tcp');
  assert.equal(publishedHostPort(external, 80), null);
  assert.deepEqual(publishedContainerPorts('192.168.1.50:8080->80/tcp'), []);

  assert.deepEqual(
    publishedContainerPorts('0.0.0.0:19998->3000/tcp, 0.0.0.0:19999->9000/tcp'),
    [
      { containerPort: 3000, hostPort: 19998 },
      { containerPort: 9000, hostPort: 19999 },
    ],
  );
});

test('kind=docker: create validates containerName/containerPort; update keeps kind fields consistent', async (t) => {
  const { store } = await makeStore(t);

  await assertRejectsRoute(
    store.create({ slug: 'dweb', kind: 'docker', containerPort: 3000 }),
    400, /containerName/);
  await assertRejectsRoute(
    store.create({ slug: 'dweb', kind: 'docker', containerName: 'bad name!', containerPort: 3000 }),
    400, /containerName/);
  await assertRejectsRoute(
    store.create({ slug: 'dweb', kind: 'docker', containerName: 'web-1' }),
    400, /containerPort/);
  await assertRejectsRoute(
    store.create({ slug: 'dweb', kind: 'docker', containerName: 'web-1', containerPort: 0 }),
    400, /containerPort/);

  const route = await store.create({ slug: 'dweb', kind: 'docker', containerName: 'web-1', containerPort: 3000 });
  assert.equal(route.kind, 'docker');
  assert.equal(route.containerName, 'web-1');
  assert.equal(route.containerPort, 3000);
  assert.equal(route.auth, 'google', 'default-deny applies to docker routes too');

  // Converting to kind=port drops the container fields; converting back
  // demands them again.
  const asPort = await store.update('dweb', { kind: 'port', port: 4100 });
  assert.equal(asPort.containerName, undefined);
  assert.equal(asPort.containerPort, undefined);
  await assertRejectsRoute(store.update('dweb', { kind: 'docker' }), 400, /containerName and containerPort/);
});

function dockerCoordinator(containers, { available = true, error } = {}) {
  return {
    inventory: async () => ({ docker: { available, error, containers } }),
    serversRaw: async () => [],
  };
}

test('resolve: kind=docker running / stopped / unpublished / missing / docker down', async (t) => {
  const { store } = await makeStore(t);
  await store.create({ slug: 'dweb', kind: 'docker', containerName: 'web-1', containerPort: 3000 });

  // Running with a published mapping resolves to the HOST port.
  const up = dockerCoordinator([
    { name: 'web-1', status: 'Up 5 minutes (healthy)', ports: '0.0.0.0:32771->3000/tcp, :::32771->3000/tcp' },
  ]);
  assert.deepEqual(await store.resolve('dweb', up), {
    port: 32771,
    container: { name: 'web-1', status: 'Up 5 minutes (healthy)' },
  });

  // Normalized SQLite inventory uses lifecycle vocabulary rather than the
  // human-formatted `docker ps` Status column. It is the same running state.
  const normalizedRunning = dockerCoordinator([
    { name: 'web-1', status: 'running', ports: '0.0.0.0:32772->3000/tcp' },
  ]);
  assert.deepEqual(await store.resolve('dweb', normalizedRunning), {
    port: 32772,
    container: { name: 'web-1', status: 'running' },
  });

  // Stopped container: no port, actionable reason.
  const down = dockerCoordinator([{ name: 'web-1', status: 'Exited (0) 2 hours ago', ports: '' }]);
  const stopped = await store.resolve('dweb', down);
  assert.equal(stopped.port, null);
  assert.match(stopped.reason, /not running/);

  // Running but the routed container port is not published.
  const unpublished = dockerCoordinator([{ name: 'web-1', status: 'Up 1 minute', ports: '0.0.0.0:8081->8080/tcp' }]);
  const missing = await store.resolve('dweb', unpublished);
  assert.equal(missing.port, null);
  assert.match(missing.reason, /does not publish port 3000/);

  // Container gone entirely.
  const absent = await store.resolve('dweb', dockerCoordinator([]));
  assert.equal(absent.port, null);
  assert.match(absent.reason, /container not found/);

  // Docker unavailable on the box.
  const noDocker = await store.resolve('dweb', dockerCoordinator([], { available: false, error: 'no docker' }));
  assert.equal(noDocker.port, null);
  assert.match(noDocker.reason, /docker unavailable/);

  // Coordinator unreachable.
  const dead = { inventory: async () => { throw new Error('boom'); } };
  const unreachable = await store.resolve('dweb', dead);
  assert.equal(unreachable.port, null);
  assert.match(unreachable.reason, /coordinator unavailable/);
});

test('resolve: kind=docker never resolves to the coordinator API port (invariant #1)', async (t) => {
  const { store } = await makeStore(t);
  await store.create({ slug: 'dtrap', kind: 'docker', containerName: 'trap-1', containerPort: 3000 });
  // A container publishing its port ON the coordinator API port must be refused.
  const trap = dockerCoordinator([
    { name: 'trap-1', status: 'Up 1 minute', ports: '0.0.0.0:29876->3000/tcp' },
  ]);
  const resolved = await store.resolve('dtrap', trap);
  assert.equal(resolved.port, null);
  assert.match(resolved.reason, /coordinator API port/);
});

// The UI keeps a hand-mirrored copy of the published-ports parser (browser
// code cannot import node modules). Extract it from app.js by brace matching
// and run BOTH implementations over the same corpus so they cannot drift.
test('ui parser mirror: app.js parsePublishedPorts/publishedContainerPorts match src/routes.mjs', async () => {
  const appJs = await fsp.readFile(
    new URL('../src/ui/app.js', import.meta.url), 'utf8');

  function extractFunction(source, header) {
    const start = source.indexOf(header);
    assert.notEqual(start, -1, `app.js no longer contains "${header}"`);
    let depth = 0;
    for (let i = source.indexOf('{', start); i < source.length; i += 1) {
      if (source[i] === '{') depth += 1;
      else if (source[i] === '}') {
        depth -= 1;
        if (depth === 0) return source.slice(start, i + 1);
      }
    }
    assert.fail(`unbalanced braces extracting ${header}`);
    return '';
  }

  const parserSrc = extractFunction(appJs, 'function parsePublishedPorts(text)');
  const v4Line = appJs.match(/const V4_ADDRS = new Set\(\[[^\]]*\]\);/)?.[0];
  assert.ok(v4Line, 'app.js V4_ADDRS definition missing');
  const portsSrc = extractFunction(appJs, 'function publishedContainerPorts(text)');

  // eslint-disable-next-line no-new-func
  const uiModule = new Function(`
    ${parserSrc}
    ${v4Line}
    ${portsSrc}
    return { parsePublishedPorts, publishedContainerPorts };
  `)();

  const corpus = [
    '0.0.0.0:5001->5001/tcp, :::5001->5001/tcp',
    '127.0.0.1:9010->9000/tcp',
    '0.0.0.0:9000-9001->9000-9001/tcp',
    ':::5000->3000/tcp',
    '::1:5000->3000/tcp',
    '[::]:8080->80/tcp',
    '192.168.1.50:8080->80/tcp',
    '5432/tcp',
    '0.0.0.0:5353->5353/udp',
    '0.0.0.0:19998->3000/tcp, 0.0.0.0:19999->9000/tcp',
    '0.0.0.0:9000-9002->9000-9001/tcp',
    '',
    'garbage, more->garbage/tcp',
  ];
  for (const ports of corpus) {
    assert.deepEqual(
      uiModule.parsePublishedPorts(ports), parsePublishedPorts(ports),
      `parsePublishedPorts drift for ${JSON.stringify(ports)}`);
    assert.deepEqual(
      uiModule.publishedContainerPorts(ports), publishedContainerPorts(ports),
      `publishedContainerPorts drift for ${JSON.stringify(ports)}`);
  }
});
