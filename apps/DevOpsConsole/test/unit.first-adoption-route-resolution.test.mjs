import assert from 'node:assert/strict';
import fs from 'node:fs';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  RouteResolutionError,
  buildRouteResolution,
  publishRouteResolution,
  validateRetainedRoutes,
} from '../edge/first-adoption-route-resolution-cli.mjs';
import {
  buildPublication,
  validateConsole,
} from '../edge/console-state-migration-cli.mjs';

function route(slug, extra = {}) {
  return {
    slug,
    kind: 'port',
    port: 31000,
    auth: 'google',
    instanceId: '11111111-1111-4111-8111-111111111111',
    ...extra,
  };
}

test('producer emits the exact credential-free consumer contract and prefers verified TLS', async () => {
  const routes = [
    route('plain'),
    route('secure', { port: 31001 }),
    route('fixed', {
      port: 31002,
      upstreamScheme: 'https',
      upstreamServerName: 'internal.vr.ae',
      upstreamTlsVerify: false,
    }),
  ];
  const resolved = new Map(routes.map((item) => [item.slug, { port: item.port }]));
  const seen = [];
  const result = await buildRouteResolution({
    routes,
    resolved,
    domain: 'vr.ae',
    probe: async ({ route: item }) => {
      seen.push(item.slug);
      if (item.slug === 'plain') return { http: true, https: false };
      return { http: item.slug === 'secure', https: true };
    },
  });
  assert.deepEqual(seen.sort(), ['fixed', 'plain', 'secure']);
  assert.deepEqual(result, {
    schema_version: 1,
    routes: {
      fixed: {
        host: '127.0.0.1', port: 31002, scheme: 'https',
        tls_server_name: 'internal.vr.ae', tls_verify: false,
      },
      plain: {
        host: '127.0.0.1', port: 31000, scheme: 'http',
        tls_server_name: null, tls_verify: true,
      },
      secure: {
        host: '127.0.0.1', port: 31001, scheme: 'https',
        tls_server_name: 'secure.vr.ae', tls_verify: true,
      },
    },
  });
  assert.equal(JSON.stringify(result).includes('authorization'), false);
});

test('producer records unavailable runtimes without weakening identity or protocol validation', async () => {
  const retained = {
    version: 1,
    routes: { app: route('app') },
  };
  assert.equal(validateRetainedRoutes(retained), retained);
  assert.throws(
    () => validateRetainedRoutes({ version: 1, routes: { app: { ...route('app'), instanceId: 'bad' } } }),
    RouteResolutionError,
  );
  const unresolved = await buildRouteResolution({
    routes: [route('app')], resolved: new Map([['app', { port: null, reason: 'stopped' }]]),
    domain: 'vr.ae', probe: async () => ({ http: true, https: false }),
  });
  assert.deepEqual(unresolved.routes.app, {
    status: 'unavailable', scheme: 'http', tls_server_name: null, tls_verify: true,
  });
  const unresponsive = await buildRouteResolution({
    routes: [route('secure', {
      upstreamScheme: 'https',
      upstreamServerName: 'internal.vr.ae',
      upstreamTlsVerify: false,
    })],
    resolved: new Map([['secure', { port: 31000 }]]),
    domain: 'vr.ae', probe: async () => ({ http: false, https: false, tls: false }),
  });
  assert.deepEqual(unresponsive.routes.secure, {
    status: 'unavailable', scheme: 'https',
    tls_server_name: 'internal.vr.ae', tls_verify: false,
  });
  await assert.rejects(
    buildRouteResolution({
      routes: [route('app')], resolved: new Map([['app', { port: 31000 }]]),
      domain: 'vr.ae', probe: async () => ({ http: true, https: false, tls: true }),
    }),
    /accepts TLS but its certificate cannot be verified/,
  );
  await assert.rejects(
    buildRouteResolution({
      routes: [route('app')], resolved: new Map([['app', { port: 29876 }]]),
      domain: 'vr.ae', probe: async () => ({ http: true, https: false }),
    }),
    /reserved control-plane listener/,
  );
});

test('same-server publication is atomic, replay-safe, and ignores local permission metadata', async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'route-resolution-test-'));
  await fsp.chmod(root, 0o777);
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const output = path.join(root, 'resolution.json');
  const value = {
    schema_version: 1,
    routes: {
      app: {
        host: '127.0.0.1', port: 31000, scheme: 'http',
        tls_server_name: null, tls_verify: true,
      },
    },
  };
  const first = await publishRouteResolution(output, value);
  assert.equal(first.replayed, false);
  // New files still use a conservative mode as hygiene, but mode is not a
  // same-server authorization gate and may be changed by another local UID.
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  await fsp.chmod(output, 0o644);
  const second = await publishRouteResolution(output, value);
  assert.equal(second.replayed, true);
  assert.equal(second.sha256, first.sha256);
  await assert.rejects(
    publishRouteResolution(output, { ...value, routes: {} }),
    /belongs to another snapshot/,
  );
  assert.deepEqual(JSON.parse(await fsp.readFile(output, 'utf8')), value);
});

test('Console migration retains the explicit unavailable descriptor in its publication', async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'route-migration-test-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const state = path.join(root, 'state');
  const releaseRoot = path.join(root, 'releases');
  const digest = 'a'.repeat(64);
  await fsp.mkdir(state, { mode: 0o700 });
  await fsp.mkdir(
    path.join(releaseRoot, digest, 'apps/DevOpsConsole/src/ui'),
    { recursive: true },
  );
  await fsp.writeFile(path.join(root, 'console.env'), [
    'DOMAIN=vr.ae',
    'CONSOLE_SUBDOMAIN=console',
    'ALLOWED_EMAILS=owner@example.com',
    '',
  ].join('\n'));
  await fsp.writeFile(path.join(state, 'routes.json'), `${JSON.stringify({
    version: 1,
    routes: {
      offline: route('offline', { auth: 'public' }),
    },
  })}\n`);
  const descriptor = {
    status: 'unavailable',
    scheme: 'https',
    tls_server_name: 'offline.vr.ae',
    tls_verify: true,
  };
  const resolution = path.join(root, 'resolution.json');
  await fsp.writeFile(resolution, `${JSON.stringify({
    schema_version: 1,
    routes: { offline: descriptor },
  })}\n`);
  const output = path.join(root, 'publication.json');
  const receipt = await buildPublication({
    state_dir: state,
    env_file: path.join(root, 'console.env'),
    resolution,
    output,
    release_root: releaseRoot,
    release_digest: digest,
    console_port: '31000',
    generation: '1',
  });
  assert.equal(receipt.unavailable_routes, 1);
  assert.deepEqual(
    JSON.parse(await fsp.readFile(output, 'utf8')).routes.offline.upstream,
    descriptor,
  );
});

test('Console migration validates Telegram state through a configured administrator identity', async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'console-validation-test-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const state = path.join(root, 'state');
  await fsp.mkdir(state, { mode: 0o700 });
  const envFile = path.join(root, 'console.env');
  await fsp.writeFile(envFile, [
    'DOMAIN=vr.ae',
    'CONSOLE_SUBDOMAIN=console',
    'ALLOWED_EMAILS=owner@example.com',
    '',
  ].join('\n'));
  const documents = {
    'routes.json': { version: 1, routes: {} },
    'upstream-auth.json': { version: 1, routes: {} },
    'access-control.json': { version: 3, users: {}, requests: {} },
    'telegram-control.json': {
      version: 1,
      revision: 0,
      eventCursor: null,
      bots: {},
      authorizationRequests: {},
      outbox: {},
    },
  };
  await Promise.all(Object.entries(documents).map(async ([name, document]) => {
    const file = path.join(state, name);
    await fsp.writeFile(file, `${JSON.stringify(document)}\n`, { mode: 0o600 });
    await fsp.chmod(file, 0o600);
  }));

  const result = await validateConsole({ state_dir: state, env_file: envFile });
  assert.equal(result.ok, true);
  assert.equal(result.identities, 1);
  assert.equal(result.telegram_bots, 0);
});
