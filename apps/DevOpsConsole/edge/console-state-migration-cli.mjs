#!/usr/bin/env node
// Parser/producer used only by software-owned first adoption. Any local account
// that can read the inputs may run it; UID/GID/mode metadata is not an
// authorization boundary on this single-developer host. Output contains metadata only; route
// credentials remain in the private publication proposal file.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { createAccessStore } from '../src/access.mjs';
import { createPrefsStore } from '../src/prefs.mjs';
import { createRouteStore } from '../src/routes.mjs';
import { createTelegramService } from '../src/telegram.mjs';
import { createUpstreamAuthStore } from '../src/upstream-auth.mjs';
import {
  isUnavailableRouteUpstream,
  validatePublication,
} from './publication.mjs';

const CONSOLE_FILES = [
  'routes.json',
  'upstream-auth.json',
  'access-control.json',
  'telegram-control.json',
  'ui-prefs.json',
  'test-stats-cache-v1.json',
];
const MAX_FILE = new Map([
  ['telegram-control.json', 16 * 1024 * 1024],
  ...CONSOLE_FILES.filter((name) => name !== 'telegram-control.json').map((name) => [name, 2 * 1024 * 1024]),
]);

function fail(message) { throw new Error(message); }

function parse(argv) {
  const command = argv.shift();
  if (!['validate-console', 'validate-identity', 'build-publication'].includes(command)) fail('unknown migration command');
  const out = { command };
  while (argv.length) {
    const flag = argv.shift();
    const value = argv.shift();
    if (!flag?.startsWith('--') || value === undefined || value.startsWith('--')) fail('invalid migration argument');
    out[flag.slice(2).replaceAll('-', '_')] = value;
  }
  const required = command === 'validate-identity'
    ? ['identity_dir', 'issuer']
    : command === 'validate-console'
      ? ['state_dir', 'env_file']
      : ['state_dir', 'env_file', 'resolution', 'output', 'release_root', 'release_digest', 'console_port', 'generation'];
  for (const name of required) if (!out[name]) fail(`--${name.replaceAll('_', '-')} is required`);
  for (const name of ['identity_dir', 'state_dir', 'env_file', 'resolution', 'output', 'release_root']) {
    if (out[name] && !path.isAbsolute(out[name])) fail(`--${name.replaceAll('_', '-')} must be absolute`);
  }
  return out;
}

async function privateMetadata(file, maximum) {
  const info = await fsp.lstat(file);
  if (!info.isFile() || info.isSymbolicLink() || info.size < 1 || info.size > maximum) {
    fail(`state file is unsafe: ${file}`);
  }
  const body = await fsp.readFile(file);
  return { size: info.size, sha256: crypto.createHash('sha256').update(body).digest('hex') };
}

function parseEnv(text) {
  const out = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
    if (!match) fail('non-secret Console configuration contains an invalid line');
    out[match[1]] = match[2];
  }
  return out;
}

async function configView(file) {
  const env = parseEnv(await fsp.readFile(file, 'utf8'));
  const domain = env.DOMAIN;
  const consoleSubdomain = env.CONSOLE_SUBDOMAIN || 'console';
  if (!/^[a-z0-9.-]+$/.test(domain || '') || !/^[a-z0-9-]+$/.test(consoleSubdomain)) fail('Console domain configuration is invalid');
  const owners = (env.ALLOWED_EMAILS || '').split(',').map((value) => value.trim().toLowerCase()).filter(Boolean);
  return {
    domain,
    consoleHost: `${consoleSubdomain}.${domain}`,
    coordinatorUrl: env.COORDINATOR_URL || 'http://127.0.0.1:29876',
    cookieName: env.SESSION_COOKIE_NAME || 'dc_session',
    owners,
  };
}

async function loadStores(stateDir, envFile) {
  const config = await configView(envFile);
  const routeStore = createRouteStore({ file: path.join(stateDir, 'routes.json'), config });
  await routeStore.load();
  const upstream = createUpstreamAuthStore({ file: path.join(stateDir, 'upstream-auth.json') });
  await upstream.load();
  const access = createAccessStore({
    file: path.join(stateDir, 'access-control.json'),
    adminEmails: config.owners,
    routeStore,
  });
  await access.load();
  const telegram = createTelegramService({
    file: path.join(stateDir, 'telegram-control.json'),
    isAdmin: (email) => access.isAdmin(email),
    coordinator: {
      hasProject: async () => true,
      observeHost: async () => ({}),
      readEvents: async () => ({ events: [], next_cursor: null, has_more: false }),
    },
  });
  await telegram.load();
  createPrefsStore({ file: path.join(stateDir, 'ui-prefs.json') }).get();
  const cacheFile = path.join(stateDir, 'test-stats-cache-v1.json');
  try {
    const cache = JSON.parse(await fsp.readFile(cacheFile, 'utf8'));
    if (cache?.version !== 1 || !Array.isArray(cache.entries) || cache.entries.length > 1000) fail('test statistics cache contract is invalid');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  return { config, routeStore, upstream, access, telegram };
}

export async function validateConsole(options) {
  const before = {};
  for (const name of CONSOLE_FILES) {
    try { before[name] = await privateMetadata(path.join(options.state_dir, name), MAX_FILE.get(name)); }
    catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }
  const stores = await loadStores(options.state_dir, options.env_file);
  const after = {};
  for (const name of Object.keys(before)) after[name] = await privateMetadata(path.join(options.state_dir, name), MAX_FILE.get(name));
  if (JSON.stringify(before) !== JSON.stringify(after)) fail('an immutable state parser changed migrated bytes');
  const ownerEmail = stores.config.owners[0];
  if (!ownerEmail) fail('Console migration requires at least one configured owner');
  const telegram = await stores.telegram.status({ email: ownerEmail });
  return {
    ok: true,
    files: before,
    routes: stores.routeStore.list().length,
    identities: stores.access.list().length,
    telegram_bots: telegram.bots.length,
  };
}

function validateRetiredIdentity() {
  // First-adoption journals may still contain this bounded validation step.
  // Local project attribution no longer has key material: the edge injects
  // plain context after Google grant authorization, so migration performs no
  // identity-state I/O and records the retired capability deterministically.
  return { ok: true, retired: true };
}

export async function buildPublication(options) {
  const stores = await loadStores(options.state_dir, options.env_file);
  const resolution = JSON.parse(await fsp.readFile(options.resolution, 'utf8'));
  if (resolution?.schema_version !== 1 || !resolution.routes || Array.isArray(resolution.routes)) fail('route resolution snapshot is invalid');
  const routes = {};
  const stateRoutes = stores.routeStore.list();
  if (Object.keys(resolution.routes).sort().join('\0') !== stateRoutes.map((route) => route.slug).sort().join('\0')) fail('route resolution snapshot does not cover the exact state route set');
  for (const route of stateRoutes) {
    const upstream = resolution.routes[route.slug];
    routes[route.slug] = {
      auth: route.auth,
      instance_id: route.instanceId,
      title: route.title || null,
      upstream,
      upstream_authorization: route.auth === 'public' ? null : stores.upstream.authorizationFor(route.slug),
    };
  }
  const grants = {};
  const owners = [];
  for (const identity of stores.access.list()) {
    if (identity.owner) owners.push(identity.email);
    else grants[identity.email] = identity.grants.filter((grant) => grant === 'console' || grant.startsWith('route:'));
  }
  const consolePort = Number(options.console_port);
  const publication = validatePublication({
    schema_version: 1,
    generation: Number(options.generation),
    published_at: new Date().toISOString(),
    domain: stores.config.domain,
    console_host: stores.config.consoleHost,
    release_digest: options.release_digest,
    maintenance: { active: false, deployment_id: null, retry_after_seconds: 0, started_at: null },
    session: { cookie_name: stores.config.cookieName },
    console: {
      asset_root: path.join(options.release_root, options.release_digest, 'apps/DevOpsConsole/src/ui'),
      upstream: { host: '127.0.0.1', port: consolePort, scheme: 'https', tls_server_name: stores.config.consoleHost, tls_verify: true },
    },
    routes,
    access: { owners, grants },
  }, { releaseRoot: options.release_root });
  const body = `${JSON.stringify(publication, null, 2)}\n`;
  const temporary = `${options.output}.${process.pid}.partial`;
  await fsp.writeFile(temporary, body, { mode: 0o600, flag: 'wx' });
  await fsp.chmod(temporary, 0o600);
  await fsp.rename(temporary, options.output);
  return {
    ok: true,
    output: options.output,
    payload_sha256: crypto.createHash('sha256').update(body).digest('hex'),
    routes: Object.keys(routes).length,
    unavailable_routes: Object.values(publication.routes)
      .filter((route) => isUnavailableRouteUpstream(route.upstream)).length,
    identities: owners.length + Object.keys(grants).length,
  };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parse([...argv]);
  return options.command === 'validate-console'
    ? await validateConsole(options)
    : options.command === 'validate-identity'
      ? validateRetiredIdentity()
      : await buildPublication(options);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  try {
    const result = await main();
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: error?.message || String(error) })}\n`);
    process.exitCode = 1;
  }
}
