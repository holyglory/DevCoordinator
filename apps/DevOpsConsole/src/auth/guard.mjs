// Request-level auth guard: session extraction with live access-policy re-check,
// browser detection, login redirect construction, the `rt` open-redirect
// guard, and the Origin/Referer CSRF check for mutating console-API calls.

const HOST_RE = /^[a-z0-9.-]+(?::\d{1,5})?$/;

export function createGuard({ sessions, access, config, log }) {
  /** Parse and verify the Google identity cookie without granting anything. */
  function identityFrom(req) {
    return sessions.parse(req?.headers?.cookie);
  }

  /**
   * Parse + verify the session cookie AND re-check current policy membership
   * on every request, so removing an invited user revokes an already-issued
   * cookie immediately. Exact resource grants are checked separately.
   */
  function sessionFrom(req) {
    const session = identityFrom(req);
    if (!session) return null;
    const email = String(session.email || '').toLowerCase();
    if (!access?.isKnown(email)) {
      log?.debug?.('session rejected: email no longer approved', { email });
      return null;
    }
    return session;
  }

  const isKnownEmail = (email) => Boolean(access?.isKnown(email));
  const isAdmin = (sessionOrEmail) => Boolean(
    access?.isAdmin(typeof sessionOrEmail === 'string' ? sessionOrEmail : sessionOrEmail?.email),
  );
  const hasAccess = (sessionOrEmail, resource) => Boolean(
    access?.canAccess(typeof sessionOrEmail === 'string' ? sessionOrEmail : sessionOrEmail?.email, resource),
  );

  /**
   * Browser-navigation detection per the architecture contract: API/XHR
   * traffic is `/api/*` or an Accept header that names application/json —
   * those get JSON 401s. Everything else (real browsers sending text/html,
   * but also curl/fetch defaults with `Accept: * / *` or none) is treated as
   * a navigation and gets the login redirect.
   */
  function wantsHtml(req) {
    const url = String(req?.url || '');
    if (url === '/api' || url.startsWith('/api/') || url.startsWith('/api?')) return false;
    const accept = String(req?.headers?.accept || '');
    return !accept.includes('application/json');
  }

  /** Absolute console login URL carrying the request's own absolute URL as rt. */
  function loginRedirectUrl(req) {
    const proto = config.devInsecureHttp ? 'http' : 'https';
    let host = String(req?.headers?.host || '').toLowerCase();
    if (!HOST_RE.test(host)) host = config.consoleHost;
    let path = String(req?.url || '/');
    if (!path.startsWith('/')) path = `/${path}`;
    const rt = `${proto}://${host}${path}`;
    return `${config.consoleOrigin}/auth/login?rt=${encodeURIComponent(rt)}`;
  }

  /**
   * Open-redirect guard: rt must be an absolute URL whose scheme matches the
   * deployment (https unless devInsecureHttp) and whose hostname is the apex
   * domain or a subdomain of it. Anything else falls back to '/'.
   */
  function validateRt(rt) {
    if (typeof rt !== 'string' || rt === '') return '/';
    let url;
    try {
      url = new URL(rt);
    } catch {
      return '/';
    }
    const wantProtocol = config.devInsecureHttp ? 'http:' : 'https:';
    if (url.protocol !== wantProtocol) return '/';
    const hostname = url.hostname.toLowerCase();
    if (hostname !== config.domain && !hostname.endsWith(`.${config.domain}`)) return '/';
    // Strip any embedded credentials so we never redirect to user:pass@ URLs.
    url.username = '';
    url.password = '';
    return url.href;
  }

  /**
   * CSRF check for mutations: the Origin (preferred) or Referer header must
   * match the console origin exactly. Absent both headers → reject; every
   * legitimate caller is a browser on the console UI, which always sends
   * Origin on non-GET fetches.
   */
  function checkOriginFor(req, expectedOrigin) {
    const expected = String(expectedOrigin).toLowerCase();
    const origin = req?.headers?.origin;
    if (typeof origin === 'string' && origin !== '') {
      return origin.toLowerCase() === expected;
    }
    const referer = req?.headers?.referer;
    if (typeof referer === 'string' && referer !== '') {
      try {
        const url = new URL(referer);
        return `${url.protocol}//${url.host}`.toLowerCase() === expected;
      } catch {
        return false;
      }
    }
    return false;
  }

  const checkOrigin = (req) => checkOriginFor(req, config.consoleOrigin);

  return {
    identityFrom,
    sessionFrom,
    isKnownEmail,
    isAdmin,
    hasAccess,
    wantsHtml,
    loginRedirectUrl,
    validateRt,
    checkOrigin,
    checkOriginFor,
  };
}
