// Console REST API (/api/*). The router only dispatches here for the console
// host after session validation; this module still re-checks the session and
// enforces the Origin check on every mutation. Only the fixed endpoint set
// below reaches the authenticated, loopback-only coordinator.

import { CoordError } from './coordinator.mjs';
import { PrefsError } from './prefs.mjs';
import { RouteError, publishedContainerPorts } from './routes.mjs';
import { AccessError, CONSOLE_GRANT, routeGrant } from './access.mjs';
import { TelegramServiceError } from './telegram.mjs';
import { UpstreamAuthError } from './upstream-auth.mjs';

const BODY_LIMIT = 64 * 1024;
const SERVER_ACTIONS = new Set(['stop', 'restart']);
const DOCKER_ACTIONS = new Set(['start', 'stop', 'restart']);
const PROJECT_ACTIONS = new Set(['start', 'stop', 'restart']);
const LIFECYCLE_ACTIONS = new Set(['archive', 'purge']);
const LIFECYCLE_TARGET_KINDS = new Set(['project', 'server', 'container', 'worktree']);
const CONTAINER_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
const TAIL_MAX = 5000;

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export function createConsoleApi({
  config, log, coordinator, routeStore, upstreamAuthStore, accessStore, guard, certManager, metrics, prefs,
  telegram = null,
}) {
  const clog = typeof log?.child === 'function' ? log.child({ mod: 'api' }) : log;

  function sendJson(res, status, payload) {
    const body = JSON.stringify(payload);
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': Buffer.byteLength(body),
      'cache-control': 'no-store',
    });
    res.end(body);
  }

  async function readJsonBody(req) {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > BODY_LIMIT) {
        // Early exit destroys the request stream via the async iterator.
        throw new ApiError(400, 'request body exceeds the 64KB limit');
      }
      chunks.push(chunk);
    }
    if (size === 0) return {};
    let parsed;
    try {
      parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new ApiError(400, 'request body must be valid JSON');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new ApiError(400, 'request body must be a JSON object');
    }
    return parsed;
  }

  function requireString(value, field) {
    if (typeof value !== 'string' || !value.trim()) {
      throw new ApiError(400, `${field} is required`);
    }
    return value.trim();
  }

  function requireContainer(value) {
    if (typeof value !== 'string' || !CONTAINER_RE.test(value)) {
      throw new ApiError(400, 'name must be a valid container name or id');
    }
    return value;
  }

  function clampTail(value, fallback) {
    if (value === undefined || value === null) return fallback;
    let n = value;
    if (typeof n === 'string' && /^\d+$/.test(n.trim())) n = Number(n.trim());
    if (!Number.isInteger(n) || n < 1 || n > TAIL_MAX) {
      throw new ApiError(400, `tail must be an integer between 1 and ${TAIL_MAX}`);
    }
    return n;
  }

  function publicUrl(slug) {
    // Scheme/port follow the deployment (http + explicit port in dev mode);
    // in production this yields exactly https://<slug>.<domain>.
    const origin = new URL(config.consoleOrigin);
    const port = origin.port ? `:${origin.port}` : '';
    return `${origin.protocol}//${slug}.${config.domain}${port}`;
  }

  async function resolveSafe(slug) {
    try {
      // resolve() uses coordinator.serversRaw() for server routes and the
      // cached coordinator.inventory() for docker routes (both coalesced).
      return await routeStore.resolve(slug, coordinator);
    } catch (err) {
      return { port: null, reason: err?.message ?? String(err) };
    }
  }

  function toRouteView(route, resolved) {
    const { instanceId: _privateInstanceId, ...publicRoute } = route;
    const view = {
      ...publicRoute,
      url: publicUrl(route.slug),
      upstreamAuth: upstreamAuthStore?.describe(route.slug) ?? { configured: false },
      resolved: { port: resolved?.port ?? null },
    };
    if (resolved?.reason) view.resolved.reason = resolved.reason;
    if (resolved?.server?.status) view.resolved.serverStatus = resolved.server.status;
    if (resolved?.container?.status) view.resolved.containerStatus = resolved.container.status;
    return view;
  }

  function accessResources() {
    const resources = [{
      id: CONSOLE_GRANT,
      kind: 'console',
      host: config.consoleHost,
      title: 'DevOps Console',
      auth: 'google',
      target: 'Full server and route control',
    }];
    for (const route of routeStore.list()) {
      let target;
      if (route.kind === 'server') target = `${route.serverName} · ${route.project}`;
      else if (route.kind === 'docker') target = `${route.containerName}:${route.containerPort}`;
      else target = `127.0.0.1:${route.port}`;
      resources.push({
        id: routeGrant(route.slug),
        kind: 'route',
        host: `${route.slug}.${config.domain}`,
        title: route.title || route.serverName || route.containerName || route.slug,
        auth: route.auth,
        target,
      });
    }
    return resources;
  }

  function requireAccessAdmin(session) {
    if (!accessStore?.isAdmin(session?.email)) {
      throw new ApiError(403, 'only configured Console owners can manage access');
    }
  }

  function requireLifecycleIdentity(body) {
    const targetKind = requireString(body.target_kind, 'target_kind');
    const targetId = requireString(body.target_id, 'target_id');
    const canonicalKind = targetKind === 'repository' ? 'project' : targetKind;
    if (!LIFECYCLE_TARGET_KINDS.has(canonicalKind)) {
      throw new ApiError(400, 'target_kind must be project, server, container or worktree');
    }
    if (targetId.length > 300 || /[\u0000-\u001f\u007f]/.test(targetId)) {
      throw new ApiError(400, 'target_id is invalid');
    }
    return { target_kind: canonicalKind, target_id: targetId };
  }

  function lifecycleReason(value, fallback) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value !== 'string') throw new ApiError(400, 'reason must be a string');
    const reason = value.trim();
    if (!reason) return fallback;
    if (reason.length > 300) throw new ApiError(400, 'reason must be at most 300 characters');
    return reason;
  }

  function archiveRows(value) {
    const rows = Array.isArray(value) ? value : value?.archives;
    if (!Array.isArray(rows) || rows.some((row) => !row || typeof row !== 'object' || Array.isArray(row))) {
      throw new ApiError(502, 'coordinator returned an invalid lifecycle archive collection');
    }
    return rows.map((row) => {
      const normalized = {
        ...row,
        target_kind: row.target_kind === 'repository' ? 'project' : row.target_kind,
      };
      if (
        !LIFECYCLE_TARGET_KINDS.has(normalized.target_kind)
        || typeof normalized.target_id !== 'string'
        || !normalized.target_id.trim()
        || normalized.target_id.length > 300
        || /[\u0000-\u001f\u007f]/.test(normalized.target_id)
      ) {
        throw new ApiError(502, 'coordinator returned an invalid lifecycle archive identity');
      }
      return normalized;
    });
  }

  function activeLifecycleTarget(inventory, identity) {
    if (identity.target_kind === 'project') {
      return (inventory?.repositories || []).find((row) => row?.repo_id === identity.target_id) || null;
    }
    if (identity.target_kind === 'server') {
      return (inventory?.servers || []).find((row) => row?.id === identity.target_id) || null;
    }
    if (identity.target_kind === 'container') {
      return (inventory?.docker?.containers || [])
        .find((row) => row?.host_resource_id === identity.target_id) || null;
    }
    return null;
  }

  async function handleLifecycleList(res, session) {
    requireAccessAdmin(session);
    const result = await coordinator.lifecycleArchives();
    sendJson(res, 200, { archives: archiveRows(result) });
  }

  async function handleLifecyclePlan(req, res, session) {
    requireAccessAdmin(session);
    const body = await readJsonBody(req);
    const identity = requireLifecycleIdentity(body);
    if (!LIFECYCLE_ACTIONS.has(body.action)) {
      throw new ApiError(400, "action must be 'archive' or 'purge'");
    }

    if (body.action === 'archive') {
      const inventory = await coordinator.inventory({ maxAgeMs: 0 });
      if (!activeLifecycleTarget(inventory, identity)) {
        throw new ApiError(404, 'active lifecycle target not found');
      }
    } else {
      const archives = archiveRows(await coordinator.lifecycleArchives());
      const archived = archives.find(
        (row) => row?.target_kind === identity.target_kind && row?.target_id === identity.target_id,
      );
      if (!archived) throw new ApiError(404, 'archived lifecycle target not found');
      if (archived.removable !== true) {
        throw new ApiError(409, 'archived lifecycle target is not currently removable');
      }
    }

    const plan = await coordinator.lifecyclePlan({
      ...identity,
      action: body.action,
      reason: lifecycleReason(
        body.reason,
        `${body.action} requested via DevOps Console by ${session.email}`,
      ),
      agent: `devops-console:${session.email}`,
    });
    sendJson(res, 200, { plan });
  }

  async function handleLifecycleApply(req, res, session) {
    requireAccessAdmin(session);
    const body = await readJsonBody(req);
    const payload = {
      plan_id: requireString(body.plan_id, 'plan_id'),
      plan_fingerprint: requireString(body.plan_fingerprint, 'plan_fingerprint'),
      confirmation_phrase: '',
    };
    if (Object.hasOwn(body, 'confirmation_phrase')) {
      if (typeof body.confirmation_phrase !== 'string') {
        throw new ApiError(400, 'confirmation_phrase must be a string');
      }
      payload.confirmation_phrase = body.confirmation_phrase;
    }
    const result = await coordinator.lifecycleApply(payload);
    sendJson(res, 200, { result });
  }

  async function handleLifecycleRestore(req, res, session) {
    requireAccessAdmin(session);
    const body = await readJsonBody(req);
    const identity = requireLifecycleIdentity(body);
    const archives = archiveRows(await coordinator.lifecycleArchives());
    const archived = archives.find(
      (row) => row?.target_kind === identity.target_kind && row?.target_id === identity.target_id,
    );
    if (!archived) throw new ApiError(404, 'archived lifecycle target not found');
    if (archived.restorable !== true) {
      throw new ApiError(409, 'archived lifecycle target is not currently restorable');
    }
    const result = await coordinator.lifecycleRestore({
      ...identity,
      reason: lifecycleReason(
        body.reason,
        `restore requested via DevOps Console by ${session.email}`,
      ),
      agent: `devops-console:${session.email}`,
      explicit: true,
    });
    sendJson(res, 200, { result });
  }

  function accessView() {
    const users = accessStore.list();
    return {
      version: 1,
      users,
      resources: accessResources(),
      invitedCount: users.filter((user) => !user.owner).length,
    };
  }

  function handleAccessGet(res, session) {
    requireAccessAdmin(session);
    sendJson(res, 200, accessView());
  }

  async function handleAccessAdd(req, res, session) {
    requireAccessAdmin(session);
    const body = await readJsonBody(req);
    const added = await accessStore.addUser({ email: body.email, grants: body.grants ?? [] });
    clog?.info?.('access user added', {
      admin: session.email,
      email: added.email,
      grants: added.grants,
    });
    sendJson(res, 201, accessView());
  }

  async function handleAccessGrant(req, res, session, email) {
    requireAccessAdmin(session);
    const body = await readJsonBody(req);
    const updated = await accessStore.setGrant(email, body.resource, body.allowed);
    clog?.info?.('access grant changed', {
      admin: session.email,
      email: updated.email,
      resource: body.resource,
      allowed: body.allowed,
    });
    sendJson(res, 200, accessView());
  }

  async function handleAccessRemove(res, session, email) {
    requireAccessAdmin(session);
    const removed = await accessStore.removeUser(email);
    clog?.info?.('access user removed', { admin: session.email, email: removed.email });
    sendJson(res, 200, accessView());
  }

  function handleAccessRequestsGet(res, session, searchParams) {
    requireAccessAdmin(session);
    const status = searchParams.get('status') || 'pending';
    sendJson(res, 200, {
      version: 1,
      pendingCount: accessStore.pendingRequestCount(),
      requests: accessStore.listRequests({ status }),
    });
  }

  async function handleAccessRequestDecision(req, res, session, requestId) {
    requireAccessAdmin(session);
    const body = await readJsonBody(req);
    const decided = await accessStore.decideRequest(requestId, body.decision, session.email);
    clog?.info?.('access request decided', {
      admin: session.email,
      requestId: decided.id,
      email: decided.email,
      resource: decided.resource,
      decision: decided.status,
    });
    sendJson(res, 200, {
      request: decided,
      pendingCount: accessStore.pendingRequestCount(),
      access: accessView(),
    });
  }

  function requireStringArray(value, field, { maxItems = 500 } = {}) {
    if (!Array.isArray(value) || value.length > maxItems) {
      throw new ApiError(400, `${field} must be an array with at most ${maxItems} items`);
    }
    const items = value.map((item) => requireString(item, field));
    if (new Set(items).size !== items.length) {
      throw new ApiError(400, `${field} must not contain duplicates`);
    }
    return items;
  }

  function requireTelegram() {
    if (!telegram) throw new ApiError(503, 'Telegram control is unavailable');
    return telegram;
  }

  async function telegramProjects() {
    const inventory = await coordinator.inventory({ maxAgeMs: 0 });
    if (!Array.isArray(inventory?.repositories)) {
      throw new ApiError(502, 'coordinator returned an invalid repository collection');
    }
    const projects = inventory.repositories.map((repository) => {
      const id = repository?.repo_id;
      if (typeof id !== 'string' || !id || /[\u0000-\u001f\u007f]/.test(id)) {
        throw new ApiError(502, 'coordinator returned an invalid repository identity');
      }
      return {
        id,
        name: repository.display_name || repository.name || id,
        path: repository.canonical_root || repository.project_root || null,
      };
    });
    projects.sort((a, b) => String(a.name).localeCompare(String(b.name)) || a.id.localeCompare(b.id));
    return projects;
  }

  async function telegramView(session) {
    const service = requireTelegram();
    const [managedBots, projects] = await Promise.all([
      service.listBots({ email: session.email }),
      telegramProjects(),
    ]);
    const bots = await Promise.all(managedBots.map(async (bot) => ({
      id: bot.id,
      label: bot.label ?? null,
      username: bot.username ?? null,
      firstName: bot.firstName ?? null,
      ownerEmail: bot.ownerEmail,
      enabled: bot.enabled !== false,
      projects: Array.isArray(bot.projects) ? [...bot.projects] : [],
      createdAt: bot.createdAt ?? null,
      updatedAt: bot.updatedAt ?? null,
      lastPollAt: bot.lastPollAt ?? null,
      lastUpdateAt: bot.lastUpdateAt ?? null,
      lastDeliveryAt: bot.lastDeliveryAt ?? null,
      lastError: bot.lastError ?? null,
      hasToken: bot.hasToken === true,
      authorizations: (await service.listAuthorizationQueue({
        email: session.email,
        botId: bot.id,
        status: null,
      })).map((request) => ({
        id: request.id,
        botId: request.botId,
        botUsername: request.botUsername ?? null,
        telegramUserId: request.telegramUserId,
        username: request.username ?? null,
        firstName: request.firstName ?? null,
        lastName: request.lastName ?? null,
        languageCode: request.languageCode ?? null,
        status: request.status,
        requestedAt: request.requestedAt,
        decidedAt: request.decidedAt ?? null,
        decidedBy: request.decidedBy ?? null,
      })),
    })));
    return { version: 1, bots, projects };
  }

  async function handleTelegramGet(res, session) {
    sendJson(res, 200, await telegramView(session));
  }

  async function handleTelegramRegister(req, res, session) {
    const body = await readJsonBody(req);
    const registered = await requireTelegram().registerBot({
      email: session.email,
      token: body.token, // public-artifact-guard: allow text-secret -- runtime request-value plumbing, not a literal credential
      label: body.label,
      takeoverWebhook: body.takeOver === true,
    });
    clog?.info?.('Telegram bot registered', { owner: session.email });
    sendJson(res, 201, { ...(await telegramView(session)), registeredBotId: registered.id });
  }

  async function handleTelegramRemove(res, session, botId) {
    await requireTelegram().removeBot({ email: session.email, botId });
    clog?.info?.('Telegram bot removed', { actor: session.email, botId });
    sendJson(res, 200, await telegramView(session));
  }

  async function handleTelegramProjects(req, res, session, botId) {
    const service = requireTelegram();
    const body = await readJsonBody(req);
    const repoIds = requireStringArray(body.projectIds, 'projectIds');
    const projects = await telegramProjects();
    const known = new Set(projects.map((project) => project.id));
    if (repoIds.some((repoId) => !known.has(repoId))) {
      throw new ApiError(404, 'one or more coordinator repositories no longer exist');
    }
    if (typeof service.setProjects === 'function') {
      await service.setProjects({ email: session.email, botId, repoIds });
    } else {
      const bot = (await service.listBots({ email: session.email }))
        .find((candidate) => String(candidate.id) === String(botId));
      if (!bot) throw new TelegramServiceError(404, 'bot_not_found', 'Telegram bot not found');
      const current = new Set((bot.projects || []).map(String));
      for (const repoId of new Set([...current, ...repoIds])) {
        const assigned = repoIds.includes(repoId);
        if (current.has(repoId) !== assigned) {
          await service.assignProject({ email: session.email, botId, repoId, assigned });
        }
      }
    }
    clog?.info?.('Telegram bot projects changed', { actor: session.email, botId, count: repoIds.length });
    sendJson(res, 200, await telegramView(session));
  }

  async function handleTelegramAuthorizationDecision(req, res, session, botId, requestId) {
    const service = requireTelegram();
    const body = await readJsonBody(req);
    const request = (await service.listAuthorizationQueue({
      email: session.email,
      botId,
      status: null,
    })).find((candidate) => candidate.id === requestId);
    if (!request) throw new TelegramServiceError(404, 'request_not_found', 'authorization request not found');
    await service.decideAuthorization({ email: session.email, requestId, decision: body.decision });
    clog?.info?.('Telegram authorization decided', {
      actor: session.email,
      botId,
      requestId,
      decision: body.decision,
    });
    sendJson(res, 200, await telegramView(session));
  }

  async function routeViews() {
    // serversRaw() is cached+coalesced, so parallel resolves share one call.
    return Promise.all(
      routeStore.list().map(async (route) => toRouteView(route, await resolveSafe(route.slug))),
    );
  }

  function normProject(value) {
    let v = String(value ?? '');
    while (v.length > 1 && v.endsWith('/')) v = v.slice(0, -1);
    return v;
  }

  // The existing kind:'server' route mapped to this coordinator server, if any.
  function findServerRoute(server) {
    const proj = normProject(server.project);
    return (
      routeStore
        .list()
        .find((r) => r.kind === 'server' && normProject(r.project) === proj && r.serverName === server.name) || null
    );
  }

  async function handleOverview(res) {
    let inventoryData = null;
    let coordErr = null;
    try {
      inventoryData = await coordinator.inventory();
      // Piggyback the fresh reading into the history buffers so charts stay
      // live while somebody is watching, between background sampler ticks.
      metrics?.ingest(inventoryData);
    } catch (err) {
      coordErr = err;
    }
    const base = coordinator.status();
    const coordView = coordErr
      ? { ...base, ok: false, lastError: coordErr?.message ?? String(coordErr) }
      : base;
    const routes = await routeViews();
    sendJson(res, 200, {
      console: {
        version: config.version,
        domain: config.domain,
        consoleHost: config.consoleHost,
        now: new Date().toISOString(),
        tls: typeof certManager?.info === 'function' ? certManager.info() : null,
        devInsecureHttp: Boolean(config.devInsecureHttp),
      },
      coordinator: coordView,
      inventory: inventoryData,
      routes,
    });
  }

  async function handleRouteCreate(req, res) {
    const body = await readJsonBody(req);
    const requestedSlug = typeof body.slug === 'string' ? body.slug.trim().toLowerCase() : '';
    if (requestedSlug && !routeStore.get(requestedSlug)) {
      // A deleted hostname must never resurrect grants if the same slug is
      // assigned to a different server later.
      await accessStore.clearResource(routeGrant(requestedSlug));
      await upstreamAuthStore?.remove(requestedSlug);
    }
    const route = await routeStore.create({
      slug: body.slug,
      kind: body.kind,
      port: body.port,
      project: body.project,
      serverName: body.serverName,
      containerName: body.containerName,
      containerPort: body.containerPort,
      auth: body.auth,
      title: body.title,
    });
    sendJson(res, 201, toRouteView(route, await resolveSafe(route.slug)));
  }

  async function handleRoutePatch(req, res, slug) {
    const body = await readJsonBody(req);
    const patch = {};
    for (const key of ['auth', 'title', 'port', 'project', 'serverName', 'containerName', 'containerPort', 'kind']) {
      if (Object.hasOwn(body, key)) patch[key] = body[key];
    }
    if (Object.keys(patch).length === 0) {
      throw new ApiError(400, 'no updatable fields in request body');
    }
    const route = await routeStore.update(slug, patch);
    if (route.auth === 'public') await upstreamAuthStore?.remove(route.slug);
    sendJson(res, 200, toRouteView(route, await resolveSafe(route.slug)));
  }

  async function handleRouteDelete(res, slug) {
    const existing = routeStore.get(slug);
    if (existing) await upstreamAuthStore?.remove(existing.slug);
    const removed = await routeStore.remove(slug);
    await accessStore.clearResource(routeGrant(removed.slug));
    sendJson(res, 200, { ok: true });
  }

  async function handleRouteUpstreamAuthSet(req, res, session, slug) {
    requireAccessAdmin(session);
    const route = routeStore.get(slug);
    if (!route) throw new ApiError(404, 'route not found');
    if (route.auth !== 'google') {
      throw new ApiError(400, 'upstream credentials can be configured only for a Google-protected route');
    }
    const body = await readJsonBody(req);
    const upstreamAuth = await upstreamAuthStore.set(route.slug, {
      scheme: body.scheme,
      username: body.username,
      secret: body.secret, // public-artifact-guard: allow text-secret -- runtime request field, never literal credential material
    });
    clog?.info?.('route upstream credential configured', {
      admin: session.email,
      slug: route.slug,
      scheme: upstreamAuth.scheme,
    });
    sendJson(res, 200, { slug: route.slug, upstreamAuth });
  }

  async function handleRouteUpstreamAuthRemove(res, session, slug) {
    requireAccessAdmin(session);
    const route = routeStore.get(slug);
    if (!route) throw new ApiError(404, 'route not found');
    const removed = await upstreamAuthStore.remove(route.slug);
    clog?.info?.('route upstream credential removed', { admin: session.email, slug: route.slug, removed });
    sendJson(res, 200, { slug: route.slug, upstreamAuth: { configured: false } });
  }

  async function handleServerAction(req, res, session) {
    const body = await readJsonBody(req);
    const id = requireString(body.id, 'id');
    if (!SERVER_ACTIONS.has(body.action)) {
      throw new ApiError(400, "action must be 'stop' or 'restart'");
    }
    const servers = await coordinator.serversRaw();
    const server = Array.isArray(servers) ? servers.find((s) => s?.id === id) : null;
    if (!server) throw new ApiError(404, 'server not found');
    const payload = {
      agent: `devops-console:${session.email}`,
      project: server.project,
      name: server.name,
      reason:
        typeof body.reason === 'string' && body.reason.trim()
          ? body.reason.trim().slice(0, 300)
          : `${body.action} requested via DevOps Console`,
    };
    const result =
      body.action === 'stop'
        ? await coordinator.serverStop(payload)
        : await coordinator.serverRestart(payload);
    sendJson(res, 200, { server: result });
  }

  // Assign / change / remove the subdomain of a coordinator server in one call.
  // Body: { id, slug, auth? }. Empty slug unassigns. Reuses the route store, so
  // slug validation, reserved names, and the coordinator-port guard all apply.
  async function handleServerSubdomain(req, res, session) {
    const body = await readJsonBody(req);
    const id = requireString(body.id, 'id');
    // Fresh read: mapping a specific server must not miss one that started
    // within the raw-servers cache window.
    const servers = await coordinator.serversRaw({ maxAgeMs: 0 });
    const server = Array.isArray(servers) ? servers.find((s) => s?.id === id) : null;
    if (!server) throw new ApiError(404, 'server not found');
    if (!server.project || !server.name) {
      throw new ApiError(400, 'server is missing project/name and cannot be mapped to a subdomain');
    }
    const existing = findServerRoute(server);
    const rawSlug = typeof body.slug === 'string' ? body.slug.trim() : '';

    // Unassign: remove the mapped route (idempotent when none exists).
    if (!rawSlug) {
      if (existing) {
        await upstreamAuthStore?.remove(existing.slug);
        await routeStore.remove(existing.slug);
        await accessStore.clearResource(routeGrant(existing.slug));
      }
      clog?.info?.('server subdomain removed', { server: server.name, slug: existing?.slug ?? null });
      return sendJson(res, 200, { route: null });
    }

    const authGiven = Object.hasOwn(body, 'auth') ? body.auth : undefined;

    // Same slug already mapped: only the access level (or nothing) can change.
    if (existing && existing.slug === rawSlug) {
      const route =
        authGiven === undefined ? existing : await routeStore.update(existing.slug, { auth: authGiven });
      if (route.auth === 'public') await upstreamAuthStore?.remove(route.slug);
      return sendJson(res, 200, { route: toRouteView(route, await resolveSafe(route.slug)) });
    }

    // New or renamed mapping: create the new route (validates + enforces
    // uniqueness), then drop the old one so a server maps to a single subdomain.
    const occupied = routeStore.get(rawSlug);
    if (occupied && rawSlug === occupied.slug) throw new ApiError(409, `route '${rawSlug}' already exists`);
    if (!occupied) {
      await accessStore.clearResource(routeGrant(rawSlug));
      await upstreamAuthStore?.remove(rawSlug);
    }
    const route = await routeStore.create({
      slug: rawSlug,
      kind: 'server',
      project: server.project,
      serverName: server.name,
      auth: authGiven ?? existing?.auth,
      title: existing?.title,
    });
    if (existing) {
      if (route.auth === 'google') await upstreamAuthStore?.move(existing.slug, route.slug);
      else await upstreamAuthStore?.remove(existing.slug);
      await accessStore.moveResource(routeGrant(existing.slug), routeGrant(route.slug));
      await routeStore.remove(existing.slug);
    }
    clog?.info?.('server subdomain assigned', { server: server.name, slug: route.slug, auth: route.auth });
    return sendJson(res, 201, { route: toRouteView(route, await resolveSafe(route.slug)) });
  }

  // The existing kind:'docker' route publishing this container, if any.
  function findDockerRoute(name) {
    return routeStore.list().find((r) => r.kind === 'docker' && r.containerName === name) || null;
  }

  // Assign / change / remove the subdomain of a docker container in one call.
  // Body: { name, slug, auth?, port? }. Empty slug unassigns. `port` is the
  // container-side port and is only needed when the container publishes more
  // than one — the published host port is resolved live on every request.
  async function handleDockerSubdomain(req, res, session) {
    const body = await readJsonBody(req);
    const name = requireContainer(body.name);
    // Fresh read: mapping a container must not miss one that started within
    // the inventory cache window.
    const inventoryData = await coordinator.inventory({ maxAgeMs: 0 });
    const docker = inventoryData?.docker;
    if (!docker || docker.available === false) {
      throw new ApiError(400, 'docker is unavailable on this machine');
    }
    const container = (Array.isArray(docker.containers) ? docker.containers : [])
      .find((c) => c?.name === name);
    if (!container) throw new ApiError(404, 'container not found');
    const existing = findDockerRoute(name);
    const rawSlug = typeof body.slug === 'string' ? body.slug.trim() : '';

    // Unassign: remove the mapped route (idempotent when none exists).
    if (!rawSlug) {
      if (existing) {
        await upstreamAuthStore?.remove(existing.slug);
        await routeStore.remove(existing.slug);
        await accessStore.clearResource(routeGrant(existing.slug));
      }
      clog?.info?.('docker subdomain removed', { container: name, slug: existing?.slug ?? null });
      return sendJson(res, 200, { route: null });
    }

    const authGiven = Object.hasOwn(body, 'auth') ? body.auth : undefined;
    const options = publishedContainerPorts(container.ports);

    // An explicit container-side port must be currently published, so a typo
    // cannot silently create a route that never resolves — EXCEPT when it is
    // the route's existing port (auth changes and renames must keep working
    // while the container is stopped or republished elsewhere).
    let requestedPort;
    if (body.port !== undefined && body.port !== null && body.port !== '') {
      const p = Number(body.port);
      if (!Number.isInteger(p) || p < 1 || p > 65535) {
        throw new ApiError(400, 'port must be a container port between 1 and 65535');
      }
      if (p !== existing?.containerPort && !options.some((o) => o.containerPort === p)) {
        const published = options.map((o) => o.containerPort).join(', ') || 'none';
        throw new ApiError(400, `container does not publish port ${p} (published: ${published})`);
      }
      requestedPort = p;
    }

    // Same slug already mapped: only access level / container port can
    // change, and the port only when explicitly requested — never silently
    // repointed to whatever happens to be published right now.
    if (existing && existing.slug === rawSlug) {
      const patch = {};
      if (authGiven !== undefined) patch.auth = authGiven;
      if (requestedPort !== undefined && existing.containerPort !== requestedPort) {
        patch.containerPort = requestedPort;
      }
      const route = Object.keys(patch).length
        ? await routeStore.update(existing.slug, patch)
        : existing;
      if (route.auth === 'public') await upstreamAuthStore?.remove(route.slug);
      return sendJson(res, 200, { route: toRouteView(route, await resolveSafe(route.slug)) });
    }

    // Renames keep the existing port; a brand-new mapping picks the only
    // published port or demands an explicit choice.
    let containerPort = requestedPort ?? existing?.containerPort;
    if (containerPort === undefined) {
      if (options.length === 1) {
        containerPort = options[0].containerPort;
      } else if (options.length === 0) {
        throw new ApiError(400, 'container publishes no host ports — publish one (compose "ports:") and start the container, then try again');
      } else {
        const published = options.map((o) => o.containerPort).join(', ');
        throw new ApiError(400, `container publishes several ports (${published}) — pass "port" to choose one`);
      }
    }

    // New or renamed mapping: create the new route (validates + enforces
    // uniqueness), then drop the old one so a container maps to one subdomain.
    const occupied = routeStore.get(rawSlug);
    if (occupied && rawSlug === occupied.slug) throw new ApiError(409, `route '${rawSlug}' already exists`);
    if (!occupied) {
      await accessStore.clearResource(routeGrant(rawSlug));
      await upstreamAuthStore?.remove(rawSlug);
    }
    const route = await routeStore.create({
      slug: rawSlug,
      kind: 'docker',
      containerName: name,
      containerPort,
      auth: authGiven ?? existing?.auth,
      title: existing?.title,
    });
    if (existing) {
      if (route.auth === 'google') await upstreamAuthStore?.move(existing.slug, route.slug);
      else await upstreamAuthStore?.remove(existing.slug);
      await accessStore.moveResource(routeGrant(existing.slug), routeGrant(route.slug));
      await routeStore.remove(existing.slug);
    }
    clog?.info?.('docker subdomain assigned', { container: name, slug: route.slug, auth: route.auth, containerPort });
    return sendJson(res, 201, { route: toRouteView(route, await resolveSafe(route.slug)) });
  }

  function handleMetricsHistory(res, searchParams) {
    if (!metrics) return sendJson(res, 200, { entities: [], host: null, sampler: { running: false } });
    const rawLimit = searchParams.get('limit');
    let limit;
    if (rawLimit !== null) {
      limit = Number(rawLimit);
      if (!Number.isInteger(limit) || limit < 1) {
        throw new ApiError(400, 'limit must be a positive integer');
      }
    }
    return sendJson(res, 200, metrics.history(limit ? { limit } : undefined));
  }

  async function handlePortLease(req, res, session) {
    const body = await readJsonBody(req);
    const payload = {
      agent: `devops-console:${session.email}`,
      project:
        typeof body.project === 'string' && body.project.trim() ? body.project.trim() : config.projectRoot,
      purpose:
        typeof body.purpose === 'string' && body.purpose.trim()
          ? body.purpose.trim().slice(0, 120)
          : 'devops-console',
    };
    if (body.preferred !== undefined && body.preferred !== null && body.preferred !== '') {
      const preferred = Number(body.preferred);
      if (!Number.isInteger(preferred) || preferred < 1 || preferred > 65535) {
        throw new ApiError(400, 'preferred must be a port between 1 and 65535');
      }
      payload.preferred = preferred;
      // A preferred port outside the default 3000-3999 range would be rejected
      // by the coordinator, so pin the range to the requested port.
      payload.range = String(preferred);
    }
    if (body.ttl !== undefined && body.ttl !== null && body.ttl !== '') {
      const ttl = Number(body.ttl);
      if (!Number.isInteger(ttl)) throw new ApiError(400, 'ttl must be an integer number of seconds');
      payload.ttl = ttl; // ttl <= 0 means the lease never expires
    }
    const lease = await coordinator.leasePort(payload);
    sendJson(res, 201, { lease });
  }

  async function handlePortRelease(req, res, session) {
    const body = await readJsonBody(req);
    const leaseId = requireString(body.lease_id, 'lease_id');
    const inventoryData = await coordinator.inventory({ maxAgeMs: 0 });
    const ownedLease = (inventoryData?.leases || []).find((lease) => lease?.id === leaseId);
    if (!ownedLease?.project) throw new ApiError(400, 'matching lease not found');
    const lease = await coordinator.releasePort({
      lease_id: leaseId,
      agent: `devops-console:${session.email}`,
      project: ownedLease.project,
    });
    sendJson(res, 200, { lease });
  }

  // Remove a durable port assignment (the pin survives everything else, so
  // this is the only console path that frees a pinned port).
  async function handlePortUnassign(req, res, session) {
    const body = await readJsonBody(req);
    const payload = { agent: `devops-console:${session.email}` };
    if (typeof body.name === 'string' && body.name.trim()) {
      payload.name = body.name.trim();
      payload.project = requireString(body.project, 'project');
    } else {
      const port = Number(body.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new ApiError(400, 'unassign needs a server name + project, or a port');
      }
      payload.port = port;
      if (typeof body.project === 'string' && body.project.trim()) payload.project = body.project.trim();
      if (body.force === true) payload.force = true;
      if (!payload.project && !payload.force) {
        // A bare port with no project always names another project's pin from
        // the coordinator's perspective, so demand the explicit confirmation
        // it will require anyway instead of a guaranteed downstream refusal.
        throw new ApiError(400, 'unassigning by bare port removes another project\'s pin — pass force: true to confirm');
      }
    }
    const assignment = await coordinator.unassignPort(payload);
    sendJson(res, 200, { assignment });
  }

  async function handleServerLogs(req, res) {
    const body = await readJsonBody(req);
    const id = requireString(body.id, 'id');
    const tail = clampTail(body.tail, 200);
    const result = await coordinator.serverLogs({ server_id: id, tail });
    sendJson(res, 200, result);
  }

  // Whole-project runtime control (starts declared dependencies before web
  // servers, preserves pinned ports). Slow by nature: compose pulls and
  // health waits can take minutes; the coordinator client allows 300s.
  async function handleProjectAction(req, res, session) {
    const body = await readJsonBody(req);
    const project = requireString(body.project, 'project');
    if (!PROJECT_ACTIONS.has(body.action)) {
      throw new ApiError(400, "action must be 'start', 'stop' or 'restart'");
    }
    // Only repos the coordinator can vouch for may be acted on: either it
    // already tracks them (inventory) or they carry a declared runtime the
    // coordinator recognizes (first start of a new project). An arbitrary
    // path with neither must not become a command-execution vector.
    const inventoryData = await coordinator.inventory();
    let known = (inventoryData?.project_usage || []).some(
      (row) => row?.project && row.project === project,
    );
    if (!known) {
      try {
        const status = await coordinator.projectStatus({ project });
        // 'declared' means a runtime config exists; otherwise accept only
        // real services (the synthetic type:'runtime' placeholder that says
        // "nothing found here" does not count).
        known = status?.declared === true
          || (Array.isArray(status?.services)
            && status.services.some((svc) => svc?.type && svc.type !== 'runtime'));
      } catch {
        known = false;
      }
    }
    if (!known) throw new ApiError(404, 'unknown project — nothing registered and no declared runtime');
    const result = await coordinator.projectAction(body.action, {
      agent: `devops-console:${session.email}`,
      project,
    });
    sendJson(res, 200, { result });
  }

  function handlePrefsGet(res) {
    sendJson(res, 200, prefs.get());
  }

  async function handlePrefsPatch(req, res) {
    const body = await readJsonBody(req);
    // Deltas only: {hide:{kind:[keys]}, unhide:{kind:[keys]}}. Whole-list
    // replacement is deliberately unsupported — a stale client snapshot must
    // never be able to wipe hides made elsewhere.
    const updated = await prefs.applyHiddenDelta({ hide: body.hide, unhide: body.unhide });
    sendJson(res, 200, updated);
  }

  async function handleDockerAction(req, res, session) {
    const body = await readJsonBody(req);
    const name = requireContainer(body.name);
    if (!DOCKER_ACTIONS.has(body.action)) {
      throw new ApiError(400, "action must be 'start', 'stop' or 'restart'");
    }
    const inventoryData = await coordinator.inventory({ maxAgeMs: 0 });
    const container = (inventoryData?.docker?.containers || []).find((item) => item?.name === name);
    if (!container) throw new ApiError(404, 'container not found');
    if (!container.project || !['docker_labels', 'coordinator_sidecar'].includes(container.metadata_source)) {
      throw new ApiError(400, 'container has no verified project ownership; register it before mutation');
    }
    const result = await coordinator.dockerAction(name, body.action, {
      agent: `devops-console:${session.email}`,
      project: container.project,
    });
    sendJson(res, 200, result);
  }

  async function handleDockerLogs(req, res) {
    const body = await readJsonBody(req);
    const name = requireContainer(body.name);
    const tail = clampTail(body.tail, 120);
    const result = await coordinator.dockerLogs({ container: name, tail });
    // docker logs writes container output to stdout or stderr depending on
    // the image — return both, stdout first.
    const text = `${result?.stdout ?? ''}${result?.stderr ?? ''}`;
    sendJson(res, 200, { text });
  }

  function handleError(res, err) {
    let status = 500;
    let message = 'internal error';
    if (
      err instanceof ApiError
      || err instanceof RouteError
      || err instanceof PrefsError
      || err instanceof AccessError
      || err instanceof TelegramServiceError
      || err instanceof UpstreamAuthError
    ) {
      status = Number.isInteger(err.status) ? err.status : 500;
      // A 401 from Telegram means the submitted bot token is invalid; it is
      // not a Console-session failure. Returning 401 here would make the UI
      // reload into Google sign-in and hide the actionable token error.
      if (err instanceof TelegramServiceError && err.status === 401) status = 400;
      message = err.message;
    } else if (err instanceof CoordError) {
      // The coordinator answered with a client error (e.g. "matching lease
      // not found"): pass it through as 400. Lifecycle conflicts and
      // incomplete HTTP-200 reports preserve 409 so the reviewed operation is
      // never mistaken for a validation typo. Anything else — unreachable,
      // timeout, 5xx — is a gateway failure and stays 502.
      status = err.status === 409 ? 409 : err.status >= 400 && err.status < 500 ? 400 : 502;
      message = err.message;
    } else {
      clog?.error?.('console api internal error', { error: err?.stack ?? String(err) });
    }
    if (res.headersSent) {
      res.destroy();
      return;
    }
    const payload = { error: message };
    if (err instanceof TelegramServiceError && typeof err.code === 'string') payload.code = err.code;
    if (
      err instanceof TelegramServiceError
      && err.code === 'telegram_rate_limited'
      && Number.isFinite(err.retryAfter)
    ) payload.retryAfter = err.retryAfter;
    sendJson(res, status, payload);
  }

  function safeDecode(segment) {
    try {
      return decodeURIComponent(segment);
    } catch {
      throw new ApiError(404, 'not found');
    }
  }

  async function handle(req, res, session) {
    try {
      if (!session || !session.email) throw new ApiError(401, 'unauthenticated');
      const method = req.method ?? 'GET';
      let pathname;
      let searchParams;
      try {
        const parsed = new URL(req.url ?? '/', 'http://console.internal');
        pathname = parsed.pathname;
        searchParams = parsed.searchParams;
      } catch {
        throw new ApiError(400, 'invalid request path');
      }
      const mutating = method === 'POST' || method === 'PATCH' || method === 'DELETE';
      if (mutating && !guard.checkOrigin(req)) {
        throw new ApiError(403, 'cross-origin request rejected');
      }

      if (method === 'GET' && pathname === '/api/overview') {
        return await handleOverview(res);
      }
      if (method === 'GET' && pathname === '/api/metrics/history') {
        return handleMetricsHistory(res, searchParams);
      }
      if (method === 'GET' && pathname === '/api/session') {
        return sendJson(res, 200, {
          email: session.email,
          name: session.name ?? null,
          pic: session.pic ?? null,
          exp: session.exp ?? null,
          accessAdmin: accessStore.isAdmin(session.email),
        });
      }
      if (method === 'GET' && pathname === '/api/access') {
        return handleAccessGet(res, session);
      }
      if (method === 'GET' && pathname === '/api/access/requests') {
        return handleAccessRequestsGet(res, session, searchParams);
      }
      const accessRequestDecisionMatch = pathname.match(/^\/api\/access\/requests\/([^/]+)\/decision$/);
      if (accessRequestDecisionMatch && method === 'POST') {
        return await handleAccessRequestDecision(
          req,
          res,
          session,
          safeDecode(accessRequestDecisionMatch[1]),
        );
      }
      if (method === 'POST' && pathname === '/api/access/users') {
        return await handleAccessAdd(req, res, session);
      }
      const accessUserMatch = pathname.match(/^\/api\/access\/users\/([^/]+)$/);
      if (accessUserMatch && method === 'PATCH') {
        return await handleAccessGrant(req, res, session, safeDecode(accessUserMatch[1]));
      }
      if (accessUserMatch && method === 'DELETE') {
        return await handleAccessRemove(res, session, safeDecode(accessUserMatch[1]));
      }
      if (method === 'GET' && pathname === '/api/telegram') {
        return await handleTelegramGet(res, session);
      }
      if (method === 'POST' && pathname === '/api/telegram/bots') {
        return await handleTelegramRegister(req, res, session);
      }
      const telegramBotMatch = pathname.match(/^\/api\/telegram\/bots\/([^/]+)$/);
      if (telegramBotMatch && method === 'DELETE') {
        return await handleTelegramRemove(res, session, safeDecode(telegramBotMatch[1]));
      }
      const telegramProjectsMatch = pathname.match(/^\/api\/telegram\/bots\/([^/]+)\/projects$/);
      if (telegramProjectsMatch && method === 'PATCH') {
        return await handleTelegramProjects(req, res, session, safeDecode(telegramProjectsMatch[1]));
      }
      const telegramDecisionMatch = pathname.match(
        /^\/api\/telegram\/bots\/([^/]+)\/authorizations\/([^/]+)\/decision$/,
      );
      if (telegramDecisionMatch && method === 'POST') {
        return await handleTelegramAuthorizationDecision(
          req,
          res,
          session,
          safeDecode(telegramDecisionMatch[1]),
          safeDecode(telegramDecisionMatch[2]),
        );
      }
      if (method === 'POST' && pathname === '/api/routes') {
        return await handleRouteCreate(req, res);
      }
      const routeUpstreamAuthMatch = pathname.match(/^\/api\/routes\/([^/]+)\/upstream-auth$/);
      if (routeUpstreamAuthMatch && method === 'PATCH') {
        return await handleRouteUpstreamAuthSet(
          req,
          res,
          session,
          safeDecode(routeUpstreamAuthMatch[1]),
        );
      }
      if (routeUpstreamAuthMatch && method === 'DELETE') {
        return await handleRouteUpstreamAuthRemove(
          res,
          session,
          safeDecode(routeUpstreamAuthMatch[1]),
        );
      }
      const routeMatch = pathname.match(/^\/api\/routes\/([^/]+)$/);
      if (routeMatch && method === 'PATCH') {
        return await handleRoutePatch(req, res, safeDecode(routeMatch[1]));
      }
      if (routeMatch && method === 'DELETE') {
        return await handleRouteDelete(res, safeDecode(routeMatch[1]));
      }
      if (method === 'POST' && pathname === '/api/servers/action') {
        return await handleServerAction(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/servers/subdomain') {
        return await handleServerSubdomain(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/servers/logs') {
        return await handleServerLogs(req, res);
      }
      if (method === 'POST' && pathname === '/api/ports/lease') {
        return await handlePortLease(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/ports/release') {
        return await handlePortRelease(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/ports/unassign') {
        return await handlePortUnassign(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/docker/action') {
        return await handleDockerAction(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/docker/subdomain') {
        return await handleDockerSubdomain(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/docker/logs') {
        return await handleDockerLogs(req, res);
      }
      if (method === 'POST' && pathname === '/api/projects/action') {
        return await handleProjectAction(req, res, session);
      }
      if (method === 'GET' && pathname === '/api/lifecycle/list') {
        return await handleLifecycleList(res, session);
      }
      if (method === 'POST' && pathname === '/api/lifecycle/plan') {
        return await handleLifecyclePlan(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/lifecycle/apply') {
        return await handleLifecycleApply(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/lifecycle/restore') {
        return await handleLifecycleRestore(req, res, session);
      }
      if (method === 'GET' && pathname === '/api/prefs') {
        return handlePrefsGet(res);
      }
      if (method === 'PATCH' && pathname === '/api/prefs') {
        return await handlePrefsPatch(req, res);
      }
      throw new ApiError(404, 'not found');
    } catch (err) {
      handleError(res, err);
    }
  }

  return { handle };
}
