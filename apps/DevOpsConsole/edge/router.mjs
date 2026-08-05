// Stable public routing boundary.  It consumes only the retained publication;
// it never observes the host or calls the Coordinator in a request path.

import { createSessionManager } from '../src/auth/session.mjs';
import { createOidc } from '../src/auth/oidc.mjs';
import { createPages } from '../src/auth/pages.mjs';
import { createProxy } from '../src/proxy.mjs';
import { createStaticServer } from '../src/static.mjs';
import { isUnavailableRouteUpstream } from './publication.mjs';

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};
const FLOW_COOKIE_NAME = 'dc_flow';
const MAINTENANCE_MESSAGE = 'Coordinator control-plane maintenance is in progress; live controls will recover automatically. Please wait before retrying.';

function hostFromHeader(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 300 || /[\r\n\s]/.test(value)) return null;
  const lower = value.toLowerCase();
  if (lower.startsWith('[')) return null;
  const colon = lower.lastIndexOf(':');
  if (colon !== -1) {
    const port = lower.slice(colon + 1);
    if (!/^\d{1,5}$/.test(port) || Number(port) > 65535) return null;
    return { host: lower.slice(0, colon), hostPort: lower };
  }
  if (!/^[a-z0-9.-]+$/.test(lower)) return null;
  return { host: lower, hostPort: lower };
}

function wantsJson(req) {
  return String(req.url || '').startsWith('/api') || String(req.headers.accept || '').includes('application/json');
}

function writeJson(res, status, value, extra = {}) {
  const body = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  res.writeHead(status, { ...JSON_HEADERS, 'content-length': body.length, ...extra });
  res.end(body);
}

function redirect(res, location, status = 302) {
  res.writeHead(status, { location, 'cache-control': 'no-store', 'content-length': '0' });
  res.end();
}

function readCookie(req, name) {
  const header = req.headers.cookie;
  if (typeof header !== 'string') return null;
  for (const part of header.split(';')) {
    const equals = part.indexOf('=');
    if (equals !== -1 && part.slice(0, equals).trim() === name) {
      return part.slice(equals + 1).trim();
    }
  }
  return null;
}

function writePage(res, page, status = page?.status ?? 500, headers = {}) {
  const body = Buffer.from(page?.html ?? '', 'utf8');
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': body.length,
    ...headers,
  });
  res.end(body);
}

function refuseUpgrade(socket, status, reason) {
  if (!socket.destroyed && socket.writable) {
    try {
      socket.write(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    } catch {
      // best effort only
    }
  }
  socket.destroy();
}

function isStaticConsolePath(pathname) {
  return pathname === '/'
    || pathname === '/index.html'
    || pathname === '/app.js'
    || pathname === '/app.css'
    || pathname === '/favicon.ico';
}

function maintenanceResponse(req, res, snapshot) {
  const retry = snapshot.maintenance.retry_after_seconds;
  return writeJson(res, 503, {
    ok: false,
    classification: 'maintenance',
    code: 'maintenance_in_progress',
    message: MAINTENANCE_MESSAGE,
    retry_after_seconds: retry,
    generation: snapshot.generation,
  }, { 'retry-after': String(retry) });
}

export async function createEdgeRouter({
  publicationStore,
  sessionSecret,
  oidcIssuer = 'https://accounts.google.com',
  oidcClientId = '',
  oidcClientSecret = '',
  log,
} = {}) {
  if (!publicationStore || typeof publicationStore.current !== 'function') {
    throw new TypeError('createEdgeRouter requires a publication store');
  }
  const secret = Buffer.isBuffer(sessionSecret) ? sessionSecret : Buffer.from(sessionSecret ?? '');
  if (secret.length < 16) throw new TypeError('edge session secret must be at least 16 bytes');

  const sessionsByCookie = new Map();
  const staticByRoot = new Map();
  const first = publicationStore.current();

  function renderUpstreamUnavailable(_req, res, { target }) {
    return writeJson(res, 502, {
      ok: false,
      code: 'upstream_unavailable',
      resource: target?.slug === 'console' ? 'console' : `route:${target?.slug ?? 'unknown'}`,
      retryable: true,
    }, { 'retry-after': '2' });
  }

  const proxy = createProxy({
    log,
    sessionCookieName: first.session.cookie_name,
    renderBadGateway: renderUpstreamUnavailable,
    renderUpstreamAuthFailure: (_req, res, { target }) => writeJson(res, 502, {
      ok: false,
      code: 'upstream_authorization_unavailable',
      resource: `route:${target?.slug ?? 'unknown'}`,
      retryable: false,
    }),
  });

  function sessionsFor(snapshot) {
    const cookieName = snapshot.session.cookie_name;
    if (!sessionsByCookie.has(cookieName)) {
      sessionsByCookie.set(cookieName, createSessionManager({
        secret,
        ttlMs: 24 * 60 * 60 * 1000,
        cookieName,
        cookieDomain: `.${snapshot.domain}`,
        secure: true,
      }));
    }
    return sessionsByCookie.get(cookieName);
  }

  const consoleOrigin = `https://${first.console_host}`;
  const pages = createPages({
    config: { domain: first.domain, consoleOrigin },
  });
  const oidc = createOidc({
    issuer: oidcIssuer,
    clientId: oidcClientId,
    clientSecret: oidcClientSecret,
    redirectUri: `${consoleOrigin}/auth/callback`,
    sessions: sessionsFor(first),
    log,
  });

  function validateReturnTarget(value, snapshot) {
    if (typeof value !== 'string' || value === '') return '/';
    let target;
    try {
      target = new URL(value);
    } catch {
      return '/';
    }
    const hostname = target.hostname.toLowerCase();
    if (
      target.protocol !== 'https:'
      || (hostname !== snapshot.domain && !hostname.endsWith(`.${snapshot.domain}`))
    ) {
      return '/';
    }
    target.username = '';
    target.password = '';
    return target.href;
  }

  function clearFlowCookie() {
    return `${FLOW_COOKIE_NAME}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; `
      + 'Max-Age=0; HttpOnly; SameSite=Lax; Secure';
  }

  function methodNotAllowed(res, allow) {
    return writePage(
      res,
      pages.renderError({ status: 405, title: 'Method Not Allowed', detail: `Allowed: ${allow}` }),
      405,
      { allow },
    );
  }

  async function handleEdgeAuth(req, res, snapshot, pathname, searchParams) {
    const sessions = sessionsFor(snapshot);
    if (pathname === '/auth/login') {
      if (!['GET', 'HEAD'].includes(req.method || 'GET')) return methodNotAllowed(res, 'GET, HEAD');
      const rt = validateReturnTarget(searchParams.get('rt') || '', snapshot);
      if (sessions.parse(req.headers.cookie)) return redirect(res, rt);
      return writePage(res, pages.renderLogin({ rt, degraded: !oidc.configured }));
    }
    if (pathname === '/auth/start') {
      if (!['GET', 'HEAD'].includes(req.method || 'GET')) return methodNotAllowed(res, 'GET, HEAD');
      const rt = validateReturnTarget(searchParams.get('rt') || '', snapshot);
      if (!oidc.configured) return redirect(res, `/auth/login?rt=${encodeURIComponent(rt)}`);
      try {
        const { url, flowCookie } = await oidc.loginRedirect(rt);
        res.setHeader('set-cookie', flowCookie);
        return redirect(res, url);
      } catch (error) {
        log?.warn?.('edge oidc login redirect failed', { error: error?.message || String(error) });
        return writePage(res, pages.renderLogin({
          rt,
          error: 'Could not reach the identity provider. Try again shortly.',
          degraded: false,
        }), 502);
      }
    }
    if (pathname === '/auth/callback') {
      if (req.method !== 'GET') return methodNotAllowed(res, 'GET');
      if (!oidc.configured) return redirect(res, '/auth/login');
      try {
        const { profile, rt } = await oidc.handleCallback(
          searchParams,
          readCookie(req, FLOW_COOKIE_NAME),
        );
        const { cookie } = sessions.issue(profile);
        log?.info?.('edge google identity verified', { email: profile.email });
        res.setHeader('set-cookie', [cookie, clearFlowCookie()]);
        return redirect(res, validateReturnTarget(rt || '', snapshot));
      } catch (error) {
        log?.warn?.('edge oidc callback failed', {
          code: error?.code || 'error',
          error: error?.message || String(error),
        });
        return writePage(
          res,
          pages.renderLogin({ rt: '/', error: error?.message || 'Sign-in failed.', degraded: false }),
          400,
          { 'set-cookie': clearFlowCookie() },
        );
      }
    }
    if (pathname === '/auth/logout') {
      if (!['GET', 'POST'].includes(req.method || 'GET')) return methodNotAllowed(res, 'GET, POST');
      res.setHeader('set-cookie', sessions.clearCookie());
      return redirect(res, '/auth/login');
    }
    return false;
  }

  function staticFor(snapshot) {
    if (!staticByRoot.has(snapshot.console.asset_root)) {
      staticByRoot.set(snapshot.console.asset_root, createStaticServer({ dir: snapshot.console.asset_root, log }));
    }
    return staticByRoot.get(snapshot.console.asset_root);
  }

  function identity(req, snapshot) {
    return sessionsFor(snapshot).parse(req.headers.cookie);
  }

  function isOwner(email, snapshot) {
    return snapshot.access.owners.includes(String(email ?? '').toLowerCase());
  }

  function hasGrant(email, resource, snapshot) {
    const normalized = String(email ?? '').toLowerCase();
    return isOwner(normalized, snapshot) || snapshot.access.grants[normalized]?.includes(resource) === true;
  }

  function unauthenticated(req, res, snapshot) {
    if (wantsJson(req)) {
      writeJson(res, 401, { ok: false, code: 'authentication_required' });
      return;
    }
    const parsed = hostFromHeader(req.headers.host);
    const requestUrl = `https://${parsed?.hostPort ?? snapshot.console_host}${String(req.url || '/')}`;
    redirect(res, `https://${snapshot.console_host}/auth/login?rt=${encodeURIComponent(requestUrl)}`);
  }

  function forbidden(req, res, snapshot, resource) {
    if (wantsJson(req)) {
      writeJson(res, 403, { ok: false, code: 'invite_required', resource });
      return;
    }
    const parsed = hostFromHeader(req.headers.host);
    const requestUrl = `https://${parsed?.hostPort ?? snapshot.console_host}${String(req.url || '/')}`;
    redirect(
      res,
      `https://${parsed?.hostPort ?? snapshot.console_host}/auth/request-invite?rt=${encodeURIComponent(requestUrl)}`,
    );
  }

  function targetFromUpstream(snapshot, slug, upstream, extra = {}) {
    return {
      slug,
      port: upstream.port,
      publicHost: extra.publicHost,
      upstreamScheme: upstream.scheme,
      upstreamServerName: upstream.tls_server_name,
      upstreamTlsVerify: upstream.tls_verify,
      ...extra,
    };
  }

  function consoleTarget(snapshot, publicHost) {
    return targetFromUpstream(snapshot, 'console', snapshot.console.upstream, {
      publicHost,
      route: { auth: 'public' },
      trustDomain: 'console',
    });
  }

  function projectTarget(snapshot, slug, route, session, publicHost) {
    return targetFromUpstream(snapshot, slug, route.upstream, {
      publicHost,
      route: { auth: route.auth },
      upstreamAuthorization: route.upstream_authorization,
      localAttribution: {
        email: session?.email ?? null,
        routeId: route.instance_id,
      },
    });
  }

  async function dispatch(req, res) {
    const snapshot = publicationStore.current();
    const parsed = hostFromHeader(req.headers.host);
    if (!parsed) return writeJson(res, 400, { ok: false, code: 'host_invalid' });
    const rawUrl = String(req.url || '/');
    let requestUrl;
    try {
      requestUrl = new URL(rawUrl, `https://${parsed.hostPort}`);
    } catch {
      return writeJson(res, 400, { ok: false, code: 'url_invalid' });
    }
    const { pathname, searchParams } = requestUrl;

    if ((req.method === 'GET' || req.method === 'HEAD') && pathname === '/healthz') {
      return writeJson(res, 200, {
        ok: true,
        role: 'edge',
        generation: snapshot.generation,
        release: snapshot.release_digest,
      });
    }

    if (parsed.host === snapshot.domain || parsed.host === `www.${snapshot.domain}`) {
      return redirect(res, `https://${snapshot.console_host}/`, 301);
    }
    const suffix = `.${snapshot.domain}`;
    if (!parsed.host.endsWith(suffix)) {
      return writeJson(res, 421, { ok: false, code: 'host_misdirected' });
    }

    if (parsed.host === snapshot.console_host) {
      const authHandled = await handleEdgeAuth(req, res, snapshot, pathname, searchParams);
      if (authHandled !== false) return authHandled;
      if (pathname.startsWith('/auth/') || pathname === '/auth') {
        return proxy.forward(req, res, consoleTarget(snapshot, parsed.hostPort));
      }
      const session = identity(req, snapshot);
      if (!session) return unauthenticated(req, res, snapshot);
      if (!hasGrant(session.email, 'console', snapshot)) return forbidden(req, res, snapshot, 'console');
      if (isStaticConsolePath(pathname)) return staticFor(snapshot).handle(req, res);
      if (snapshot.maintenance.active && (pathname.startsWith('/api') || !['GET', 'HEAD', 'OPTIONS'].includes(req.method || 'GET'))) {
        return maintenanceResponse(req, res, snapshot);
      }
      return proxy.forward(req, res, consoleTarget(snapshot, parsed.hostPort));
    }

    const slug = parsed.host.slice(0, -suffix.length);
    if (!slug || slug.includes('.')) return writeJson(res, 421, { ok: false, code: 'host_misdirected' });
    const route = snapshot.routes[slug];
    const session = route?.auth === 'public' ? null : identity(req, snapshot);

    // Invite generation remains a Console-backend concern, but it is reached
    // through the stable listener and does not participate in project proxying.
    if (pathname === '/auth/request-invite') {
      return proxy.forward(req, res, consoleTarget(snapshot, parsed.hostPort));
    }
    if (!route || route.auth !== 'public') {
      if (!session) return unauthenticated(req, res, snapshot);
      if (route && !hasGrant(session.email, `route:${slug}`, snapshot)) {
        return forbidden(req, res, snapshot, `route:${slug}`);
      }
    }
    if (!route) return writeJson(res, 404, { ok: false, code: 'route_not_found' });
    if (isUnavailableRouteUpstream(route.upstream)) {
      return renderUpstreamUnavailable(req, res, { target: { slug } });
    }
    return proxy.forward(req, res, projectTarget(snapshot, slug, route, session, parsed.hostPort));
  }

  function handleRequest(req, res) {
    req.on('error', () => {});
    res.on('error', () => {});
    res.setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains');
    void dispatch(req, res).catch((error) => {
      log?.error?.('edge request failed', { error: error?.stack || String(error) });
      if (res.headersSent) return res.destroy();
      writeJson(res, 500, { ok: false, code: 'edge_internal_error' });
    });
  }

  function handleUpgrade(req, socket, head) {
    socket.on('error', () => {});
    try {
      const snapshot = publicationStore.current();
      const parsed = hostFromHeader(req.headers.host);
      if (!parsed) return refuseUpgrade(socket, 400, 'Bad Request');
      if (parsed.host === snapshot.console_host) {
        if (snapshot.maintenance.active) return refuseUpgrade(socket, 503, 'Service Unavailable');
        return proxy.forwardUpgrade(req, socket, head, consoleTarget(snapshot, parsed.hostPort));
      }
      const suffix = `.${snapshot.domain}`;
      if (!parsed.host.endsWith(suffix)) return refuseUpgrade(socket, 421, 'Misdirected Request');
      const slug = parsed.host.slice(0, -suffix.length);
      if (!slug || slug.includes('.')) return refuseUpgrade(socket, 421, 'Misdirected Request');
      const route = snapshot.routes[slug];
      const session = route?.auth === 'public' ? null : identity(req, snapshot);
      if (!route || (route.auth !== 'public' && (!session || !hasGrant(session.email, `route:${slug}`, snapshot)))) {
        return refuseUpgrade(socket, route ? 403 : 404, route ? 'Forbidden' : 'Not Found');
      }
      if (isUnavailableRouteUpstream(route.upstream)) {
        return refuseUpgrade(socket, 502, 'Bad Gateway');
      }
      return proxy.forwardUpgrade(
        req,
        socket,
        head,
        projectTarget(snapshot, slug, route, session, parsed.hostPort),
      );
    } catch (error) {
      log?.error?.('edge upgrade failed', { error: error?.stack || String(error) });
      return refuseUpgrade(socket, 500, 'Internal Server Error');
    }
  }

  return {
    handleRequest,
    handleUpgrade,
    close() {
      proxy.close();
    },
  };
}
