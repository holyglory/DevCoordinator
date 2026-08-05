#!/usr/bin/env node
// Build the one credential-free upstream snapshot consumed by
// the first-adoption Console state migration. Runtime discovery is delegated
// to the Coordinator inventory CLI under the legacy Console execution UID;
// this process never inspects Docker, processes, or listeners directly.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { promises as fsp } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { promisify } from 'node:util';
import { execFile as execFileCallback } from 'node:child_process';

import { createRouteStore } from '../src/routes.mjs';
import { unavailableRouteUpstream } from './publication.mjs';

const execFile = promisify(execFileCallback);
const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const MAX_INVENTORY_BYTES = 64 * 1024 * 1024;
const MAX_ROUTES = 4096;
const PROBE_TIMEOUT_MS = 2500;
const PROBE_CONCURRENCY = 8;
const DNS_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DNS_NAME_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const RELEASE_RE = /^[a-f0-9]{64}$/;
const INSTANCE_RE = /^[0-9a-f-]{16,64}$/i;
const RESERVED_PORTS = new Set([29876]);
const USAGE = `usage: first-adoption-route-resolution-cli.mjs
  --release PATH
  --legacy-routes PATH
  --legacy-source-uid UID
  --legacy-source-gid GID
  --legacy-source-home PATH
  --domain DOMAIN
  --output PATH
  [--broker-profile /etc/devcoordinator/client-profiles.json]\n`;

export class RouteResolutionError extends Error {
  constructor(message, { code = 'route_resolution_invalid', cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'RouteResolutionError';
    this.code = code;
  }
}

function fail(message, code = 'route_resolution_invalid') {
  throw new RouteResolutionError(message, { code });
}

function absolute(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value) {
    fail(`${label} must be one normalized absolute path`);
  }
  return value;
}

function positiveInteger(value, label, { allowZero = false } = {}) {
  if (!/^\d+$/.test(String(value ?? ''))) fail(`${label} must be an integer`);
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < (allowZero ? 0 : 1)) fail(`${label} is invalid`);
  return result;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function encoded(value) {
  return Buffer.from(`${JSON.stringify(canonicalize(value), null, 2)}\n`, 'utf8');
}

function digest(payload) {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs;
}

async function noSymlinkComponents(target, { includeLeaf = true } = {}) {
  const normalized = absolute(target, 'path');
  const parts = normalized.split('/').filter(Boolean);
  let current = '/';
  const limit = includeLeaf ? parts.length : Math.max(0, parts.length - 1);
  for (let index = 0; index < limit; index += 1) {
    current = path.join(current, parts[index]);
    const info = await fsp.lstat(current);
    if (info.isSymbolicLink()) fail(`path contains a symbolic link: ${current}`);
    if (index < limit - 1 && !info.isDirectory()) fail(`path ancestor is not a directory: ${current}`);
  }
}

async function readBoundedExact(file, {
  maximum = MAX_SOURCE_BYTES,
  label = 'file',
} = {}) {
  absolute(file, label);
  await noSymlinkComponents(file, { includeLeaf: false });
  const beforeRaw = await fsp.lstat(file, { bigint: true });
  const before = {
    dev: beforeRaw.dev,
    ino: beforeRaw.ino,
    size: beforeRaw.size,
    mtimeNs: beforeRaw.mtimeNs,
  };
  if (!beforeRaw.isFile() || beforeRaw.isSymbolicLink()) fail(`${label} must be a regular non-symlink file`);
  if (before.size < 1n || before.size > BigInt(maximum)) fail(`${label} size is invalid`);
  const handle = await fsp.open(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  let payload;
  try {
    const openedRaw = await handle.stat({ bigint: true });
    const opened = {
      dev: openedRaw.dev,
      ino: openedRaw.ino,
      size: openedRaw.size,
      mtimeNs: openedRaw.mtimeNs,
    };
    if (!sameIdentity(before, opened)) fail(`${label} identity changed before it was read`);
    payload = await handle.readFile();
    if (BigInt(payload.length) !== before.size) fail(`${label} changed while it was read`);
    const afterOpenRaw = await handle.stat({ bigint: true });
    const afterOpen = {
      dev: afterOpenRaw.dev,
      ino: afterOpenRaw.ino,
      size: afterOpenRaw.size,
      mtimeNs: afterOpenRaw.mtimeNs,
    };
    if (!sameIdentity(before, afterOpen)) fail(`${label} changed while it was read`);
  } finally {
    await handle.close();
  }
  const afterRaw = await fsp.lstat(file, { bigint: true });
  const after = {
    dev: afterRaw.dev,
    ino: afterRaw.ino,
    size: afterRaw.size,
    mtimeNs: afterRaw.mtimeNs,
  };
  if (!sameIdentity(before, after)) fail(`${label} identity changed after it was read`);
  return { payload, identity: before, sha256: digest(payload) };
}

function parseJson(payload, label) {
  try {
    const value = JSON.parse(payload.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
    return value;
  } catch (error) {
    if (error instanceof RouteResolutionError) throw error;
    throw new RouteResolutionError(`${label} is not valid JSON`, { cause: error });
  }
}

export function validateRetainedRoutes(document) {
  if (document.version !== 1 || !document.routes || typeof document.routes !== 'object' || Array.isArray(document.routes)) {
    fail('legacy route state contract is invalid');
  }
  const entries = Object.entries(document.routes);
  if (entries.length > MAX_ROUTES) fail('legacy route state exceeds the route limit');
  for (const [slug, route] of entries) {
    if (!DNS_LABEL_RE.test(slug) || !route || typeof route !== 'object' || Array.isArray(route)) {
      fail(`legacy route '${slug}' is invalid`);
    }
    if (route.slug !== slug || !['port', 'server', 'docker'].includes(route.kind)) {
      fail(`legacy route '${slug}' identity is invalid`);
    }
    if (!['google', 'public'].includes(route.auth) || !INSTANCE_RE.test(String(route.instanceId ?? ''))) {
      fail(`legacy route '${slug}' access/instance identity is invalid`);
    }
    if (route.kind === 'port' && (!Number.isInteger(route.port) || route.port < 1 || route.port > 65535)) {
      fail(`legacy route '${slug}' port is invalid`);
    }
    if (route.kind === 'server' && (typeof route.project !== 'string' || !route.project || typeof route.serverName !== 'string' || !route.serverName)) {
      fail(`legacy route '${slug}' server identity is invalid`);
    }
    if (route.kind === 'docker' && (typeof route.containerName !== 'string' || !route.containerName || !Number.isInteger(route.containerPort) || route.containerPort < 1 || route.containerPort > 65535)) {
      fail(`legacy route '${slug}' Docker identity is invalid`);
    }
    if (route.upstreamScheme !== undefined && !['http', 'https'].includes(route.upstreamScheme)) {
      fail(`legacy route '${slug}' upstream scheme is invalid`);
    }
    if (route.upstreamTlsVerify !== undefined && typeof route.upstreamTlsVerify !== 'boolean') {
      fail(`legacy route '${slug}' TLS verification flag is invalid`);
    }
    if (route.upstreamServerName !== undefined && (typeof route.upstreamServerName !== 'string' || !DNS_NAME_RE.test(route.upstreamServerName) || route.upstreamServerName !== route.upstreamServerName.toLowerCase())) {
      fail(`legacy route '${slug}' TLS server name is invalid`);
    }
    if (route.upstreamScheme !== 'https' && (route.upstreamTlsVerify !== undefined || route.upstreamServerName !== undefined)) {
      fail(`legacy route '${slug}' declares TLS options without an HTTPS scheme`);
    }
  }
  return document;
}

function normalizedUpstream(value, slug) {
  const keys = Object.keys(value).sort();
  const wanted = ['host', 'port', 'scheme', 'tls_server_name', 'tls_verify'];
  if (keys.length !== wanted.length || keys.some((key, index) => key !== wanted[index])) {
    fail(`route '${slug}' upstream fields are invalid`);
  }
  if (value.host !== '127.0.0.1' || !Number.isInteger(value.port) || value.port < 1 || value.port > 65535 || RESERVED_PORTS.has(value.port)) {
    fail(`route '${slug}' upstream listener is invalid`);
  }
  if (!['http', 'https'].includes(value.scheme) || typeof value.tls_verify !== 'boolean') {
    fail(`route '${slug}' upstream protocol is invalid`);
  }
  if (value.scheme === 'http') {
    if (value.tls_server_name !== null || value.tls_verify !== true) fail(`route '${slug}' HTTP upstream has TLS overrides`);
  } else if (typeof value.tls_server_name !== 'string' || value.tls_server_name !== value.tls_server_name.toLowerCase() || !DNS_NAME_RE.test(value.tls_server_name)) {
    fail(`route '${slug}' HTTPS server name is invalid`);
  }
  return { ...value };
}

function routeProtocol(route, domain, { scheme } = {}) {
  const selected = scheme ?? route.upstreamScheme ?? 'http';
  if (!['http', 'https'].includes(selected)) {
    fail(`route '${route.slug}' upstream protocol is invalid`);
  }
  return selected === 'http'
    ? { scheme: 'http', tls_server_name: null, tls_verify: true }
    : {
        scheme: 'https',
        tls_server_name: route.upstreamServerName ?? `${route.slug}.${domain}`,
        tls_verify: route.upstreamTlsVerify ?? true,
      };
}

function unavailableUpstream(route, domain, options) {
  return unavailableRouteUpstream(
    routeProtocol(route, domain, options),
    `routes.${route.slug}.upstream`,
  );
}

function probeRequest({
  scheme, port, hostHeader, serverName = hostHeader, tlsVerify, timeoutMs = PROBE_TIMEOUT_MS,
}) {
  const client = scheme === 'https' ? https : http;
  return new Promise((resolve) => {
    const request = client.request({
      host: '127.0.0.1',
      port,
      method: 'HEAD',
      path: '/',
      headers: { host: hostHeader },
      ...(scheme === 'https' ? { servername: serverName, rejectUnauthorized: tlsVerify } : {}),
    }, (response) => {
      response.resume();
      resolve(true);
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error('probe timeout')));
    request.once('error', () => resolve(false));
    request.end();
  });
}

export async function probeProtocols({ route, port, domain, timeoutMs = PROBE_TIMEOUT_MS }) {
  const publicHost = `${route.slug}.${domain}`;
  const explicitScheme = route.upstreamScheme;
  const tlsServerName = route.upstreamServerName ?? publicHost;
  const tlsVerify = route.upstreamTlsVerify ?? true;
  if (explicitScheme === 'http') {
    const [httpReady, tlsReady] = await Promise.all([
      probeRequest({ scheme: 'http', port, hostHeader: publicHost, tlsVerify: true, timeoutMs }),
      probeRequest({ scheme: 'https', port, hostHeader: publicHost, serverName: tlsServerName, tlsVerify: false, timeoutMs }),
    ]);
    return { http: httpReady, https: false, tls: tlsReady };
  }
  if (explicitScheme === 'https') {
    return {
      http: false,
      https: await probeRequest({ scheme: 'https', port, hostHeader: publicHost, serverName: tlsServerName, tlsVerify, timeoutMs }),
      tls: true,
    };
  }
  const [httpReady, httpsReady, tlsReady] = await Promise.all([
    probeRequest({ scheme: 'http', port, hostHeader: publicHost, tlsVerify: true, timeoutMs }),
    probeRequest({ scheme: 'https', port, hostHeader: publicHost, serverName: tlsServerName, tlsVerify: true, timeoutMs }),
    probeRequest({ scheme: 'https', port, hostHeader: publicHost, serverName: tlsServerName, tlsVerify: false, timeoutMs }),
  ]);
  return { http: httpReady, https: httpsReady, tls: tlsReady };
}

async function mapLimit(items, limit, operation) {
  const result = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      result[index] = await operation(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, Math.max(1, items.length)) }, () => worker()));
  return result;
}

export async function buildRouteResolution({ routes, resolved, domain, probe = probeProtocols }) {
  if (typeof domain !== 'string' || domain !== domain.toLowerCase() || !DNS_NAME_RE.test(domain)) {
    fail('route publication domain is invalid');
  }
  const sorted = [...routes].sort((left, right) => left.slug.localeCompare(right.slug));
  const pairs = await mapLimit(sorted, PROBE_CONCURRENCY, async (route) => {
    const observation = resolved.get(route.slug);
    const port = observation?.port;
    if (!Number.isInteger(port)) {
      return [route.slug, unavailableUpstream(route, domain)];
    }
    if (RESERVED_PORTS.has(port)) fail(`route '${route.slug}' targets a reserved control-plane listener`);
    const readiness = await probe({ route, port, domain });
    let scheme = route.upstreamScheme;
    if (scheme === 'https' && readiness?.https !== true) {
      return [route.slug, unavailableUpstream(route, domain, { scheme })];
    }
    if (scheme === 'http' && readiness?.tls === true) {
      fail(`route '${route.slug}' is configured for HTTP but accepts TLS`, 'route_upstream_protocol_conflict');
    }
    if (scheme === 'http' && readiness?.http !== true) {
      return [route.slug, unavailableUpstream(route, domain, { scheme })];
    }
    if (scheme === undefined) {
      // A TLS listener commonly returns a valid plaintext HTTP 400. A verified
      // TLS handshake is therefore stronger evidence and wins when both probes
      // return a protocol response.
      if (readiness?.https === true) scheme = 'https';
      else if (readiness?.tls === true) {
        fail(`route '${route.slug}' accepts TLS but its certificate cannot be verified; declare the exact HTTPS policy`, 'route_upstream_tls_unverified');
      }
      else if (readiness?.http === true) scheme = 'http';
      else return [route.slug, unavailableUpstream(route, domain)];
    }
    const upstream = { host: '127.0.0.1', port, ...routeProtocol(route, domain, { scheme }) };
    return [route.slug, normalizedUpstream(upstream, route.slug)];
  });
  return { schema_version: 1, routes: Object.fromEntries(pairs) };
}

function stableResolvedIdentity(route, observation) {
  return {
    slug: route.slug,
    instance_id: route.instanceId,
    port: observation?.port ?? null,
    resource_identity: route.kind === 'server'
      ? observation?.server?.id ?? null
      : route.kind === 'docker' ? route.containerName : `port:${route.port}`,
  };
}

async function resolveAll(routeStore, inventory) {
  const rows = new Map();
  for (const route of routeStore.list()) {
    rows.set(route.slug, await routeStore.resolve(route.slug, {}, inventory));
  }
  return rows;
}

function assertStableResolution(routes, before, after) {
  for (const route of routes) {
    const left = stableResolvedIdentity(route, before.get(route.slug));
    const right = stableResolvedIdentity(route, after.get(route.slug));
    if (JSON.stringify(left) !== JSON.stringify(right)) {
      fail(`route '${route.slug}' changed while the resolution snapshot was built`, 'route_resolution_drift');
    }
  }
}

async function validateRelease(release) {
  absolute(release, 'release');
  if (!RELEASE_RE.test(path.basename(release))) fail('release directory name is not one SHA-256 digest');
  await noSymlinkComponents(release);
  const info = await fsp.lstat(release);
  if (!info.isDirectory() || info.isSymbolicLink()) fail('release directory is invalid');
  const helper = path.join(release, 'skills/codex-dev-coordinator/scripts/dev_coordinator.py');
  const helperInfo = await fsp.lstat(helper);
  if (!helperInfo.isFile() || helperInfo.isSymbolicLink() || helperInfo.size < 1) fail('inventory helper is invalid');
  return helper;
}

async function runInventory({ release, sourceUid, sourceGid, sourceHome, brokerProfile, maintenanceDeploymentId }) {
  const helper = await validateRelease(release);
  absolute(sourceHome, 'legacy source home');
  const home = await fsp.lstat(sourceHome);
  if (!home.isDirectory() || home.isSymbolicLink()) fail('legacy source home is invalid');
  absolute(brokerProfile, 'broker profile');
  await noSymlinkComponents(brokerProfile);
  const profile = await fsp.lstat(brokerProfile);
  if (!profile.isFile() || profile.isSymbolicLink() || profile.size < 1 || profile.size > 1024 * 1024) {
    fail('broker profile must be one bounded regular file');
  }
  const args = [
    '--no-new-privs',
    '--reuid', String(sourceUid),
    '--regid', String(sourceGid),
    '--init-groups',
    '/usr/bin/python3', '-I', '-B', helper,
    'inventory', '--compact-json', '--stats-history-limit', '0',
  ];
  let stdout;
  try {
    ({ stdout } = await execFile('/usr/bin/setpriv', args, {
      encoding: 'utf8',
      maxBuffer: MAX_INVENTORY_BYTES,
      timeout: 70_000,
      env: {
        HOME: sourceHome,
        PATH: '/usr/bin:/bin',
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        DEVCOORDINATOR_BROKER_PROFILE: brokerProfile,
        DEVCOORDINATOR_MAINTENANCE_DEPLOYMENT_ID: maintenanceDeploymentId,
      },
    }));
  } catch (error) {
    throw new RouteResolutionError('Coordinator inventory failed under the legacy source identity', {
      code: 'route_inventory_failed',
      cause: error,
    });
  }
  const inventory = parseJson(Buffer.from(stdout, 'utf8'), 'Coordinator inventory');
  if (inventory.schema_version !== 2 || !Array.isArray(inventory.servers) || !inventory.docker || typeof inventory.docker !== 'object') {
    fail('Coordinator inventory contract is invalid', 'route_inventory_invalid');
  }
  return inventory;
}

export async function publishRouteResolution(output, value, _compatibility = {}) {
  absolute(output, 'route resolution output');
  await noSymlinkComponents(output, { includeLeaf: false });
  const parent = path.dirname(output);
  const parentInfo = await fsp.lstat(parent);
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) fail('route resolution output parent is invalid');
  const payload = encoded(value);
  if (payload.length < 1 || payload.length > MAX_SOURCE_BYTES) fail('route resolution output is too large');
  try {
    const existing = await readBoundedExact(output, {
      maximum: MAX_SOURCE_BYTES,
      label: 'route resolution output',
    });
    if (!existing.payload.equals(payload)) {
      fail('route resolution output belongs to another snapshot');
    }
    return { replayed: true, sha256: existing.sha256, bytes: existing.payload.length };
  } catch (error) {
    if (!(error instanceof Error && error.code === 'ENOENT')) throw error;
  }
  const temporary = path.join(parent, `.route-resolution-${process.pid}-${crypto.randomUUID()}.partial`);
  let handle;
  try {
    handle = await fsp.open(temporary, 'wx', 0o600);
    await handle.writeFile(payload);
    await handle.sync();
    await handle.close();
    handle = null;
    await fsp.link(temporary, output);
    const directory = await fsp.open(parent, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0));
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    if (error?.code === 'EEXIST') {
      const existing = await readBoundedExact(output, {
        maximum: MAX_SOURCE_BYTES,
        label: 'route resolution output',
      });
      if (existing.payload.equals(payload)) {
        return { replayed: true, sha256: existing.sha256, bytes: existing.payload.length };
      }
    }
    throw error;
  } finally {
    if (handle) await handle.close().catch(() => {});
    await fsp.unlink(temporary).catch(() => {});
  }
  return { replayed: false, sha256: digest(payload), bytes: payload.length };
}

function parseArguments(argv) {
  const values = {};
  while (argv.length) {
    const flag = argv.shift();
    const value = argv.shift();
    if (!flag?.startsWith('--') || value === undefined || value.startsWith('--')) fail('invalid command argument');
    const key = flag.slice(2).replaceAll('-', '_');
    if (Object.hasOwn(values, key)) fail(`duplicate argument: ${flag}`);
    values[key] = value;
  }
  for (const key of ['release', 'legacy_routes', 'legacy_source_uid', 'legacy_source_gid', 'legacy_source_home', 'domain', 'output', 'maintenance_deployment_id']) {
    if (!values[key]) fail(`--${key.replaceAll('_', '-')} is required`);
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(String(values.maintenance_deployment_id))) {
    fail('--maintenance-deployment-id must be one canonical UUID');
  }
  return {
    release: absolute(values.release, 'release'),
    legacyRoutes: absolute(values.legacy_routes, 'legacy routes'),
    sourceUid: positiveInteger(values.legacy_source_uid, 'legacy source UID'),
    sourceGid: positiveInteger(values.legacy_source_gid, 'legacy source GID'),
    sourceHome: absolute(values.legacy_source_home, 'legacy source home'),
    domain: String(values.domain).toLowerCase(),
    output: absolute(values.output, 'route resolution output'),
    brokerProfile: absolute(values.broker_profile ?? '/etc/devcoordinator/client-profiles.json', 'broker profile'),
    maintenanceDeploymentId: String(values.maintenance_deployment_id),
  };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArguments([...argv]);
  const source = await readBoundedExact(options.legacyRoutes, {
    maximum: MAX_SOURCE_BYTES,
    label: 'legacy routes',
  });
  const sourceDocument = validateRetainedRoutes(parseJson(source.payload, 'legacy routes'));
  const temporaryRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'devcoordinator-route-resolution-'));
  await fsp.chmod(temporaryRoot, 0o700);
  try {
    const copiedRoutes = path.join(temporaryRoot, 'routes.json');
    await fsp.writeFile(copiedRoutes, source.payload, { mode: 0o600, flag: 'wx' });
    const routeStore = createRouteStore({
      file: copiedRoutes,
      config: { consoleHost: `console.${options.domain}`, coordinatorUrl: 'http://127.0.0.1:29876' },
      log: null,
    });
    await routeStore.load();
    const routes = routeStore.list();
    const retainedSlugs = Object.keys(sourceDocument.routes).sort();
    if (routes.map((route) => route.slug).join('\0') !== retainedSlugs.join('\0')) {
      fail('legacy route loader did not retain the exact route set');
    }
    const firstInventory = await runInventory(options);
    const firstResolved = await resolveAll(routeStore, firstInventory);
    const resolution = await buildRouteResolution({ routes, resolved: firstResolved, domain: options.domain });
    const secondInventory = await runInventory(options);
    const secondResolved = await resolveAll(routeStore, secondInventory);
    assertStableResolution(routes, firstResolved, secondResolved);
    const finalSource = await readBoundedExact(options.legacyRoutes, {
      maximum: MAX_SOURCE_BYTES,
      label: 'legacy routes',
    });
    if (finalSource.sha256 !== source.sha256 || !sameIdentity(finalSource.identity, source.identity)) {
      fail('legacy route state changed while the resolution snapshot was built', 'route_resolution_drift');
    }
    const publication = await publishRouteResolution(options.output, resolution);
    return {
      ok: true,
      output: options.output,
      payload_sha256: publication.sha256,
      route_count: routes.length,
      replayed: publication.replayed,
    };
  } finally {
    await fsp.rm(temporaryRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  if (process.argv.length === 3 && ['-h', '--help'].includes(process.argv[2])) {
    process.stdout.write(USAGE);
  } else {
    main()
      .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
      .catch((error) => {
        process.stderr.write(`${JSON.stringify({ ok: false, code: error?.code || 'route_resolution_failed', error: error?.message || String(error) })}\n`);
        process.exitCode = 1;
      });
  }
}
