// Subdomain route store: persists { slug -> Route } in <stateDir>/routes.json
// (schema v1) with atomic tmp+rename writes, and resolves routes to loopback
// ports via the coordinator's raw server records.

import { promises as fsp } from 'node:fs';
import path from 'node:path';

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const BASE_RESERVED = ['console', 'www', 'api', 'auth', 'static', 'healthz'];
const KINDS = new Set(['port', 'server']);
const AUTHS = new Set(['google', 'public']);
const TITLE_MAX = 120;
const TEXT_MAX = 512;

// Status preference order when several coordinator records share project+name.
const STATUS_RANK = { running: 0, starting: 1, unhealthy: 2, stopped: 3 };

export class RouteError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'RouteError';
    this.status = status; // 400 | 404 | 409
  }
}

export function createRouteStore({ file, config, log }) {
  const clog = typeof log?.child === 'function' ? log.child({ mod: 'routes' }) : log;

  const reserved = new Set(BASE_RESERVED);
  const consoleLabel = String(config.consoleHost ?? '').split('.')[0];
  if (consoleLabel) reserved.add(consoleLabel);

  // Routes must never point a public subdomain at the unauthenticated
  // coordinator API (security invariant 1).
  let coordinatorPort = null;
  try {
    const u = new URL(config.coordinatorUrl);
    coordinatorPort = Number(u.port || (u.protocol === 'https:' ? 443 : 80));
  } catch {
    coordinatorPort = null;
  }

  let routes = new Map();
  let writeChain = Promise.resolve();

  function lookupKey(input) {
    return typeof input === 'string' ? input.trim().toLowerCase() : '';
  }

  function validateNewSlug(input) {
    if (typeof input !== 'string' || !input.trim()) {
      throw new RouteError(400, 'slug is required');
    }
    // Validate the input as given: the contract's slug rule is the lowercase
    // DNS-label regex, so uppercase input is a 400, never silently rewritten.
    const slug = input.trim();
    if (!SLUG_RE.test(slug)) {
      throw new RouteError(
        400,
        `invalid slug '${slug.slice(0, 64)}': use 1-63 lowercase letters, digits or hyphens (no leading/trailing hyphen)`,
      );
    }
    if (reserved.has(slug)) {
      throw new RouteError(400, `slug '${slug}' is reserved`);
    }
    return slug;
  }

  // True when this port would proxy a public subdomain straight into the
  // unauthenticated, loopback-only coordinator API (security invariant #1).
  function isCoordinatorPort(n) {
    return coordinatorPort !== null && Number.isInteger(n) && n === coordinatorPort;
  }

  function validatePort(value) {
    let n = value;
    if (typeof n === 'string' && /^\d+$/.test(n.trim())) n = Number(n.trim());
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      throw new RouteError(400, 'port must be an integer between 1 and 65535');
    }
    if (isCoordinatorPort(n)) {
      throw new RouteError(400, 'routes may not target the coordinator API port');
    }
    return n;
  }

  function requireText(value, field) {
    if (typeof value !== 'string' || !value.trim()) {
      throw new RouteError(400, `${field} is required for a server route`);
    }
    const v = value.trim();
    if (v.length > TEXT_MAX) throw new RouteError(400, `${field} is too long`);
    return v;
  }

  function normalizeProject(value) {
    let v = value;
    while (v.length > 1 && v.endsWith('/')) v = v.slice(0, -1);
    return v;
  }

  function validateAuth(value) {
    if (!AUTHS.has(value)) {
      throw new RouteError(400, "auth must be 'google' or 'public'");
    }
    return value;
  }

  function validateTitle(value) {
    if (value === undefined || value === null) return undefined;
    if (typeof value !== 'string') throw new RouteError(400, 'title must be a string');
    const t = value.trim();
    if (!t) return undefined;
    if (t.length > TITLE_MAX) {
      throw new RouteError(400, `title must be at most ${TITLE_MAX} characters`);
    }
    return t;
  }

  async function load() {
    let text;
    try {
      text = await fsp.readFile(file, 'utf8');
    } catch (err) {
      if (err?.code === 'ENOENT') {
        routes = new Map();
        return;
      }
      throw err;
    }
    let parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
    const valid =
      parsed &&
      typeof parsed === 'object' &&
      !Array.isArray(parsed) &&
      parsed.version === 1 &&
      parsed.routes &&
      typeof parsed.routes === 'object' &&
      !Array.isArray(parsed.routes);
    if (!valid) {
      // Preserve the bad file for inspection, then start empty (matches the
      // coordinator's own corrupt-state recovery behavior).
      const backup = `${file}.corrupt-${Date.now()}`;
      await fsp.rename(file, backup).catch(() => {});
      clog?.error?.('route store file invalid; starting with empty store', { file, backup });
      routes = new Map();
      return;
    }
    const next = new Map();
    for (const [slug, route] of Object.entries(parsed.routes)) {
      if (!route || typeof route !== 'object' || Array.isArray(route)) continue;
      // Security invariant #1: a persisted kind:'port' route pointing at the
      // coordinator API port bypasses validatePort (which only runs on the
      // create/update API path). Refuse to load it so a hand-edited or seeded
      // routes.json can never proxy public traffic into the coordinator.
      if (route.kind === 'port' && isCoordinatorPort(Number(route.port))) {
        clog?.error?.('dropping route that targets the coordinator API port', { slug, port: route.port });
        continue;
      }
      next.set(slug, { ...route, slug });
    }
    routes = next;
  }

  function persist() {
    const snapshot = { version: 1, routes: {} };
    for (const slug of [...routes.keys()].sort()) {
      snapshot.routes[slug] = routes.get(slug);
    }
    const payload = `${JSON.stringify(snapshot, null, 2)}\n`;
    // Serialize writers so concurrent mutations cannot interleave tmp files.
    writeChain = writeChain
      .catch(() => {})
      .then(async () => {
        await fsp.mkdir(path.dirname(file), { recursive: true });
        const tmp = `${file}.tmp`;
        await fsp.writeFile(tmp, payload, 'utf8');
        await fsp.rename(tmp, file);
      });
    return writeChain;
  }

  function list() {
    return [...routes.keys()].sort().map((slug) => ({ ...routes.get(slug) }));
  }

  function get(slugInput) {
    const route = routes.get(lookupKey(slugInput));
    return route ? { ...route } : null;
  }

  async function create(def = {}) {
    const slug = validateNewSlug(def.slug);
    if (routes.has(slug)) {
      throw new RouteError(409, `route '${slug}' already exists`);
    }
    if (!KINDS.has(def.kind)) {
      throw new RouteError(400, "kind must be 'port' or 'server'");
    }
    const now = new Date().toISOString();
    const route = {
      slug,
      kind: def.kind,
      // Default-deny: routes are login-protected unless explicitly public.
      auth: def.auth === undefined || def.auth === null ? 'google' : validateAuth(def.auth),
      createdAt: now,
      updatedAt: now,
    };
    const title = validateTitle(def.title);
    if (title !== undefined) route.title = title;
    if (def.kind === 'port') {
      route.port = validatePort(def.port);
    } else {
      route.project = normalizeProject(requireText(def.project, 'project'));
      route.serverName = requireText(def.serverName, 'serverName');
    }
    routes.set(slug, route);
    await persist();
    return { ...route };
  }

  async function update(slugInput, patch = {}) {
    const key = lookupKey(slugInput);
    const existing = routes.get(key);
    if (!existing) {
      throw new RouteError(404, `route '${key.slice(0, 64) || String(slugInput).slice(0, 64)}' not found`);
    }
    if (Object.hasOwn(patch, 'slug') && lookupKey(patch.slug) !== key) {
      throw new RouteError(400, 'slug cannot be changed');
    }
    const next = { ...existing };
    if (Object.hasOwn(patch, 'kind')) {
      if (!KINDS.has(patch.kind)) throw new RouteError(400, "kind must be 'port' or 'server'");
      next.kind = patch.kind;
    }
    if (Object.hasOwn(patch, 'auth')) next.auth = validateAuth(patch.auth);
    if (Object.hasOwn(patch, 'title')) {
      const t = validateTitle(patch.title);
      if (t === undefined) delete next.title;
      else next.title = t;
    }
    if (Object.hasOwn(patch, 'port')) next.port = validatePort(patch.port);
    if (Object.hasOwn(patch, 'project')) {
      next.project = normalizeProject(requireText(patch.project, 'project'));
    }
    if (Object.hasOwn(patch, 'serverName')) {
      next.serverName = requireText(patch.serverName, 'serverName');
    }
    if (next.kind === 'port') {
      if (!Number.isInteger(next.port)) {
        throw new RouteError(400, "a route with kind 'port' requires a port");
      }
      delete next.project;
      delete next.serverName;
    } else {
      if (!next.project || !next.serverName) {
        throw new RouteError(400, "a route with kind 'server' requires project and serverName");
      }
      delete next.port;
    }
    next.slug = existing.slug;
    next.createdAt = existing.createdAt;
    next.updatedAt = new Date().toISOString();
    routes.set(key, next);
    await persist();
    return { ...next };
  }

  async function remove(slugInput) {
    const key = lookupKey(slugInput);
    const existing = routes.get(key);
    if (!existing) {
      throw new RouteError(404, `route '${key.slice(0, 64) || String(slugInput).slice(0, 64)}' not found`);
    }
    routes.delete(key);
    await persist();
    return { ...existing };
  }

  // Central choke point: every resolved port that could reach the proxy passes
  // through here, so kind:'port', kind:'server', and disk-loaded routes are all
  // screened against the coordinator API port — not just the create/update API
  // path (security invariant #1).
  function guardCoordinatorPort(port, extra) {
    if (isCoordinatorPort(port)) {
      return { port: null, reason: 'route targets the coordinator API port', ...extra };
    }
    return null;
  }

  async function resolve(slugInput, coordinator) {
    const route = routes.get(lookupKey(slugInput));
    if (!route) return { port: null, reason: 'route not found' };
    if (route.kind === 'port') {
      return guardCoordinatorPort(route.port) ?? { port: route.port };
    }

    let servers;
    try {
      servers = await coordinator.serversRaw();
    } catch (err) {
      return { port: null, reason: `coordinator unavailable: ${err?.message ?? err}` };
    }
    const candidates = (Array.isArray(servers) ? servers : [])
      .filter((s) => s && s.project === route.project && s.name === route.serverName)
      .sort((a, b) => (STATUS_RANK[a.status] ?? 9) - (STATUS_RANK[b.status] ?? 9));
    if (candidates.length === 0) {
      return { port: null, reason: 'server not found' };
    }
    const best = candidates[0];
    const server = { id: best.id, name: best.name, project: best.project, status: best.status };
    if (best.status === 'running' && Number.isInteger(best.port)) {
      return guardCoordinatorPort(best.port, { server }) ?? { port: best.port, server };
    }
    return { port: null, reason: 'server stopped', server };
  }

  return { load, list, get, create, update, remove, resolve };
}
