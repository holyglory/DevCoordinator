// Host-based dispatch for both plain requests and protocol upgrades:
// healthz → apex/www redirect → console app (auth endpoints, API, static UI)
// → <slug> reverse proxy (default-deny auth) → 421 for foreign hosts.
// Upgrades perform the SAME auth checks as requests.

import { AccessError, CONSOLE_GRANT, routeGrant } from './access.mjs';

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const FLOW_COOKIE_NAME = 'dc_flow';
const INVITE_TOKEN_TTL_MS = 10 * 60 * 1000;
const INVITE_BODY_LIMIT = 8 * 1024;

// Robust Host parsing: lowercases, splits an optional port, accepts bracketed
// IPv6 literals, rejects anything else malformed. Returns null on garbage.
function parseHostHeader(raw) {
  if (typeof raw !== 'string') return null;
  const lower = raw.trim().toLowerCase();
  if (lower.length === 0 || lower.length > 260) return null;

  let host;
  let port = '';
  if (lower.startsWith('[')) {
    const end = lower.indexOf(']');
    if (end === -1) return null;
    host = lower.slice(0, end + 1);
    const rest = lower.slice(end + 1);
    if (rest !== '') {
      if (!rest.startsWith(':')) return null;
      port = rest.slice(1);
    }
    if (!/^\[[0-9a-f:.%]+\]$/.test(host)) return null;
  } else {
    const colon = lower.indexOf(':');
    if (colon === -1) {
      host = lower;
    } else {
      host = lower.slice(0, colon);
      port = lower.slice(colon + 1);
    }
    if (host.length === 0 || !/^[a-z0-9.-]+$/.test(host)) return null;
  }
  if (port !== '' && !/^\d{1,5}$/.test(port)) return null;
  return { host, port, hostPort: port ? `${host}:${port}` : host };
}

function readCookie(req, name) {
  const header = req.headers.cookie;
  if (typeof header !== 'string') return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

export function createRouter(deps) {
  const {
    config,
    log,
    guard,
    oidc,
    sessions,
    pages,
    consoleApi,
    staticServer,
    routeStore,
    accessStore,
    upstreamAuthStore,
    coordinator,
    proxy,
  } = deps;

  function routeAccessResource(route) {
    if (!route) return null;
    let target;
    if (route.kind === 'server') target = `${route.serverName} · ${route.project}`;
    else if (route.kind === 'docker') target = `${route.containerName}:${route.containerPort}`;
    else target = `127.0.0.1:${route.port}`;
    const resource = routeGrant(route.slug);
    return {
      resource,
      resourceInstance: accessStore.resourceInstance(resource),
      host: `${route.slug}.${config.domain}`,
      title: route.title || route.serverName || route.containerName || route.slug,
      target,
    };
  }

  const consoleAccessResource = () => ({
    resource: CONSOLE_GRANT,
    resourceInstance: accessStore.resourceInstance(CONSOLE_GRANT),
    host: config.consoleHost,
    title: 'DevOps Console',
    target: 'Full server and route control',
  });

  const upstreamAuthorizationFor = (route) => (
    route?.auth === 'public' ? null : upstreamAuthStore?.authorizationFor(route.slug) ?? null
  );

  // Belt-and-suspenders for security invariant #1: even though routeStore now
  // screens every resolved port against the coordinator API port, the router
  // independently refuses to proxy to it. A route must NEVER hand public
  // traffic to the authenticated, loopback-only coordinator control API.
  let coordinatorPort = null;
  try {
    const u = new URL(config.coordinatorUrl);
    coordinatorPort = Number(u.port || (u.protocol === 'https:' ? 443 : 80));
  } catch {
    coordinatorPort = null;
  }
  const isCoordinatorPort = (port) =>
    coordinatorPort !== null && Number.isInteger(port) && port === coordinatorPort;

  const clearFlowCookie = () =>
    `${FLOW_COOKIE_NAME}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; SameSite=Lax` +
    (config.devInsecureHttp ? '' : '; Secure');

  // --- response helpers ------------------------------------------------------

  function redirect(res, status, location) {
    res.writeHead(status, { location, 'cache-control': 'no-store', 'content-length': '0' });
    res.end();
  }

  function sendText(res, status, body) {
    res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(body);
  }

  function sendJson(res, status, obj) {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(JSON.stringify(obj));
  }

  function sendPage(res, page, { status, fallbackStatus = 500, headers = {} } = {}) {
    const code = status ?? (Number.isInteger(page?.status) ? page.status : fallbackStatus);
    res.writeHead(code, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      ...headers,
    });
    res.end(page?.html ?? '');
  }

  async function readInviteForm(req) {
    const contentType = String(req.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
    if (contentType !== 'application/x-www-form-urlencoded') {
      throw new AccessError(400, 'request form has an invalid content type');
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > INVITE_BODY_LIMIT) throw new AccessError(400, 'request form is too large');
      chunks.push(chunk);
    }
    const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
    if ([...form.keys()].some((key) => key !== 'request_token') || form.getAll('request_token').length !== 1) {
      throw new AccessError(400, 'request form is invalid');
    }
    const token = form.get('request_token');
    if (!token) throw new AccessError(400, 'request token is required');
    return token;
  }

  function methodNotAllowed(res, allow) {
    res.setHeader('allow', allow);
    sendPage(res, pages.renderError({ status: 405, title: 'Method Not Allowed', detail: `Allowed: ${allow}` }), {
      fallbackStatus: 405,
    });
  }

  // Best-effort raw refusal on the upgrade path, then hard close.
  function refuseUpgrade(socket, status, reason) {
    try {
      if (!socket.destroyed && socket.writable) {
        socket.write(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\n\r\n`);
      }
    } catch {
      // socket already gone
    }
    socket.destroy();
  }

  function slugFor(host) {
    const suffix = '.' + config.domain;
    if (!host.endsWith(suffix)) return null;
    const label = host.slice(0, host.length - suffix.length);
    return SLUG_RE.test(label) ? label : null; // regex excludes dots → single label
  }

  function unauthenticated(req, res, pathname, loginUrl) {
    const apiLike =
      pathname === '/api' ||
      pathname.startsWith('/api/') ||
      String(req.headers.accept || '').includes('application/json');
    if (!apiLike && (req.method === 'GET' || req.method === 'HEAD') && guard.wantsHtml(req)) {
      redirect(res, 302, loginUrl);
    } else {
      sendJson(res, 401, { error: 'unauthenticated' });
    }
  }

  function inviteTokenFor(session, descriptor, requestHost) {
    if (!session || !descriptor?.resourceInstance) return '';
    return sessions.signBlob({
      purpose: 'access-request',
      sub: session.sub,
      email: session.email,
      resource: descriptor.resource,
      resourceInstance: descriptor.resourceInstance,
      requestHost,
    }, INVITE_TOKEN_TTL_MS);
  }

  function forbidden(req, res, pathname, session, descriptor, requestHost) {
    const apiLike =
      pathname === '/api' ||
      pathname.startsWith('/api/') ||
      String(req.headers.accept || '').includes('application/json');
    if (apiLike) return sendJson(res, 403, { error: 'forbidden' });
    return sendPage(res, pages.renderDenied({
      email: session?.email,
      resource: descriptor?.host || '',
      sessionSet: true,
      requestToken: inviteTokenFor(session, descriptor, requestHost),
    }), { fallbackStatus: 403 });
  }

  async function handleInviteRequest(req, res, descriptor, requestOrigin, requestHost) {
    if (req.method !== 'POST') return methodNotAllowed(res, 'POST');
    const identity = guard.identityFrom(req);
    if (!identity) return unauthenticated(req, res, '/auth/request-invite', guard.loginRedirectUrl(req));
    if (!guard.checkOriginFor(req, requestOrigin)) {
      return sendPage(res, pages.renderInviteResult({ status: 403, error: 'Cross-origin request rejected.' }), {
        fallbackStatus: 403,
      });
    }
    try {
      const token = await readInviteForm(req);
      const claim = sessions.verifyBlob(token);
      const valid = claim
        && claim.purpose === 'access-request'
        && claim.sub === identity.sub
        && claim.email === identity.email
        && claim.resource === descriptor?.resource
        && claim.resourceInstance === descriptor?.resourceInstance
        && claim.requestHost === requestHost;
      if (!valid) throw new AccessError(400, 'request token is invalid or expired');
      const request = await accessStore.requestAccess({
        email: identity.email,
        subject: `${config.oidcIssuer}\0${identity.sub}`,
        ...descriptor,
      });
      log.info('access invite requested', {
        email: identity.email,
        resource: descriptor.resource,
        requestId: request.id,
        duplicate: request.duplicate === true,
      });
      return sendPage(res, pages.renderInviteResult({ status: 202, duplicate: request.duplicate === true }), {
        fallbackStatus: 202,
      });
    } catch (error) {
      const status = error instanceof AccessError ? error.status : 500;
      if (!(error instanceof AccessError)) {
        log.error('access invite request failed', { error: error?.stack || String(error) });
      }
      const headers = error?.retryAfter ? { 'retry-after': String(error.retryAfter) } : {};
      return sendPage(res, pages.renderInviteResult({
        status,
        error: status === 500 ? 'The request could not be saved.' : error.message,
        retryAfter: error?.retryAfter ?? null,
      }), { fallbackStatus: status, headers });
    }
  }

  // --- auth endpoints (console host only) -------------------------------------

  async function handleAuth(req, res, pathname, searchParams, requestOrigin, requestHost) {
    switch (pathname) {
      case '/auth/login': {
        if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(res, 'GET, HEAD');
        const rt = guard.validateRt(searchParams.get('rt') || '');
        const session = guard.identityFrom(req);
        if (session) return redirect(res, 302, rt);
        return sendPage(res, pages.renderLogin({ rt, degraded: !oidc.configured }), { fallbackStatus: 200 });
      }

      case '/auth/start': {
        if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(res, 'GET, HEAD');
        const rt = guard.validateRt(searchParams.get('rt') || '');
        if (!oidc.configured) {
          // Degraded mode: bounce back to the login page's setup banner.
          return redirect(res, 302, `/auth/login?rt=${encodeURIComponent(rt)}`);
        }
        try {
          const { url, flowCookie } = await oidc.loginRedirect(rt);
          res.setHeader('set-cookie', flowCookie);
          return redirect(res, 302, url);
        } catch (err) {
          log.warn('oidc login redirect failed', { error: err.message });
          return sendPage(
            res,
            pages.renderLogin({
              rt,
              error: 'Could not reach the identity provider. Try again shortly.',
              degraded: false,
            }),
            { status: 502 },
          );
        }
      }

      case '/auth/callback': {
        if (req.method !== 'GET') return methodNotAllowed(res, 'GET');
        if (!oidc.configured) return redirect(res, 302, '/auth/login');
        const flowCookieValue = readCookie(req, FLOW_COOKIE_NAME);
        try {
          const { profile, rt } = await oidc.handleCallback(searchParams, flowCookieValue);
          const { cookie } = sessions.issue(profile);
          log.info('google identity verified', {
            email: profile.email,
            accessKnown: guard.isKnownEmail(profile.email),
          });
          res.setHeader('set-cookie', [cookie, clearFlowCookie()]);
          return redirect(res, 302, guard.validateRt(rt || ''));
        } catch (err) {
          log.warn('oidc callback failed', { code: err?.code || 'error', error: err?.message });
          return sendPage(
            res,
            pages.renderLogin({ rt: '/', error: err?.message || 'Sign-in failed.', degraded: false }),
            { status: 400, headers: { 'set-cookie': clearFlowCookie() } },
          );
        }
      }

      case '/auth/request-invite': {
        return handleInviteRequest(req, res, consoleAccessResource(), requestOrigin, requestHost);
      }

      case '/auth/logout': {
        if (req.method !== 'GET' && req.method !== 'POST') return methodNotAllowed(res, 'GET, POST');
        res.setHeader('set-cookie', sessions.clearCookie());
        return redirect(res, 302, '/auth/login');
      }

      default:
        return sendPage(res, pages.renderError({ status: 404, title: 'Not Found', detail: 'No such auth endpoint.' }), {
          fallbackStatus: 404,
        });
    }
  }

  // --- console host -----------------------------------------------------------

  async function handleConsole(req, res, pathname, rawUrl, hostPort) {
    const proto = config.devInsecureHttp ? 'http' : 'https';
    const requestOrigin = `${proto}://${hostPort}`;
    if (pathname === '/auth' || pathname.startsWith('/auth/')) {
      const searchParams = new URL(rawUrl, config.consoleOrigin).searchParams;
      return handleAuth(req, res, pathname, searchParams, requestOrigin, hostPort);
    }

    const session = guard.identityFrom(req);
    if (!session) return unauthenticated(req, res, pathname, guard.loginRedirectUrl(req));
    if (!guard.isKnownEmail(session.email) || !guard.hasAccess(session, CONSOLE_GRANT)) {
      return forbidden(req, res, pathname, session, consoleAccessResource(), hostPort);
    }

    if (pathname === '/api' || pathname.startsWith('/api/')) {
      return consoleApi.handle(req, res, session);
    }
    return staticServer.handle(req, res);
  }

  // --- slug hosts ---------------------------------------------------------------

  async function handleSlug(req, res, slug, hostPort, rawUrl) {
    const route = routeStore.get(slug);
    const pathname = String(rawUrl || '/').split('?', 1)[0];
    if (pathname === '/auth/request-invite') {
      if (!route || route.auth === 'public') {
        return sendPage(res, pages.renderNotFound({ slug }), { fallbackStatus: 404 });
      }
      const proto = config.devInsecureHttp ? 'http' : 'https';
      return handleInviteRequest(
        req,
        res,
        routeAccessResource(route),
        `${proto}://${hostPort}`,
        hostPort,
      );
    }
    // Unknown slugs behave exactly like protected ones for anonymous users so
    // route names cannot be enumerated (security invariant #2).
    const needAuth = !route || route.auth !== 'public';
    if (needAuth) {
      const session = guard.identityFrom(req);
      if (!session) {
        const proto = config.devInsecureHttp ? 'http' : 'https';
        const fullUrl = `${proto}://${hostPort}${rawUrl}`;
        const loginUrl = `${config.consoleOrigin}/auth/login?rt=${encodeURIComponent(fullUrl)}`;
        return unauthenticated(req, res, '/', loginUrl);
      }
      if (route && (!guard.isKnownEmail(session.email) || !guard.hasAccess(session, routeGrant(slug)))) {
        return forbidden(req, res, '/', session, routeAccessResource(route), hostPort);
      }
    }

    if (!route) {
      return sendPage(res, pages.renderNotFound({ slug }), { fallbackStatus: 404 });
    }

    const resolved = await routeStore.resolve(slug, coordinator);
    if (!resolved || !resolved.port || isCoordinatorPort(resolved.port)) {
      if (resolved && isCoordinatorPort(resolved.port)) {
        log.error('refusing to proxy: resolved port is the coordinator API port', { slug, port: resolved.port });
      }
      return sendPage(
        res,
        pages.renderUpstreamError({
          slug,
          kind: 'stopped',
          detail: resolved?.reason || 'no upstream port available',
          consoleUrl: config.consoleOrigin + '/',
        }),
        { fallbackStatus: 502 },
      );
    }

    proxy.forward(req, res, {
      port: resolved.port,
      slug,
      host: '127.0.0.1',
      publicHost: hostPort,
      route,
      upstreamAuthorization: upstreamAuthorizationFor(route),
    });
  }

  // --- request entry point -----------------------------------------------------

  async function dispatch(req, res) {
    const parsed = parseHostHeader(req.headers.host);
    if (!parsed) {
      return sendPage(
        res,
        pages.renderError({ status: 400, title: 'Bad Request', detail: 'Missing or malformed Host header.' }),
        { fallbackStatus: 400 },
      );
    }
    const { host, hostPort } = parsed;
    const rawUrl = req.url || '/';
    const q = rawUrl.indexOf('?');
    const pathname = q === -1 ? rawUrl : rawUrl.slice(0, q);

    if ((req.method === 'GET' || req.method === 'HEAD') && pathname === '/healthz') {
      return sendText(res, 200, 'ok');
    }

    if (host === config.domain || host === `www.${config.domain}`) {
      return redirect(res, 301, config.consoleOrigin + '/');
    }

    if (host === config.consoleHost) {
      return handleConsole(req, res, pathname, rawUrl, hostPort);
    }

    const slug = slugFor(host);
    if (slug) {
      return handleSlug(req, res, slug, hostPort, rawUrl);
    }

    return sendPage(
      res,
      pages.renderError({
        status: 421,
        title: 'Misdirected Request',
        detail: 'This server does not serve the requested host.',
      }),
      { fallbackStatus: 421 },
    );
  }

  function handleRequest(req, res) {
    // Keep stray stream errors (client aborts mid-write) from crashing the process.
    req.on('error', () => {});
    res.on('error', () => {});
    dispatch(req, res).catch((err) => {
      log.error('request handling failed', {
        method: req.method,
        url: String(req.url || '').slice(0, 200),
        error: err?.stack || String(err),
      });
      if (res.headersSent) {
        res.destroy();
        return;
      }
      try {
        sendPage(
          res,
          pages.renderError({ status: 500, title: 'Internal Server Error', detail: 'Unexpected error.' }),
          { fallbackStatus: 500 },
        );
      } catch {
        try {
          res.writeHead(500);
          res.end();
        } catch {
          res.destroy();
        }
      }
    });
  }

  // --- upgrade entry point -------------------------------------------------------

  async function dispatchUpgrade(req, socket, head) {
    const parsed = parseHostHeader(req.headers.host);
    if (!parsed) return refuseUpgrade(socket, 400, 'Bad Request');
    const { host, hostPort } = parsed;

    if (host === config.domain || host === `www.${config.domain}`) {
      return refuseUpgrade(socket, 421, 'Misdirected Request');
    }
    if (host === config.consoleHost) {
      // No WebSockets on the console in v1.
      return socket.destroy();
    }

    const slug = slugFor(host);
    if (!slug) return refuseUpgrade(socket, 421, 'Misdirected Request');

    const route = routeStore.get(slug);
    const needAuth = !route || route.auth !== 'public';
    if (needAuth) {
      // Same auth checks as plain requests — an upgrade must never bypass them.
      const session = guard.identityFrom(req);
      if (!session) return refuseUpgrade(socket, 401, 'Unauthorized');
      if (route && (!guard.isKnownEmail(session.email) || !guard.hasAccess(session, routeGrant(slug)))) {
        return refuseUpgrade(socket, 403, 'Forbidden');
      }
    }
    if (!route) return refuseUpgrade(socket, 404, 'Not Found');

    const resolved = await routeStore.resolve(slug, coordinator);
    if (!resolved || !resolved.port || isCoordinatorPort(resolved.port)) {
      if (resolved && isCoordinatorPort(resolved.port)) {
        log.error('refusing to proxy upgrade: resolved port is the coordinator API port', { slug, port: resolved.port });
      }
      return refuseUpgrade(socket, 502, 'Bad Gateway');
    }

    proxy.forwardUpgrade(req, socket, head, {
      port: resolved.port,
      slug,
      host: '127.0.0.1',
      publicHost: hostPort,
      route,
      upstreamAuthorization: upstreamAuthorizationFor(route),
    });
  }

  function handleUpgrade(req, socket, head) {
    socket.on('error', () => {});
    dispatchUpgrade(req, socket, head).catch((err) => {
      log.error('upgrade handling failed', {
        url: String(req.url || '').slice(0, 200),
        error: err?.stack || String(err),
      });
      socket.destroy();
    });
  }

  return { handleRequest, handleUpgrade };
}
