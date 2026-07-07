// Request-level auth guard: session extraction with allowlist re-check,
// browser detection, login redirect construction, the `rt` open-redirect
// guard, and the Origin/Referer CSRF check for mutating console-API calls.

const HOST_RE = /^[a-z0-9.-]+(?::\d{1,5})?$/;

export function createGuard({ sessions, allowedEmails, config, log }) {
  /**
   * Parse + verify the session cookie AND re-check the email allowlist on
   * every request, so removing an email from ALLOWED_EMAILS revokes access
   * immediately even for already-issued cookies.
   */
  function sessionFrom(req) {
    const session = sessions.parse(req?.headers?.cookie);
    if (!session) return null;
    const email = String(session.email || '').toLowerCase();
    if (!allowedEmails || !allowedEmails.has(email)) {
      log?.debug?.('session rejected: email not on allowlist', { email });
      return null;
    }
    return session;
  }

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
  function checkOrigin(req) {
    const expected = String(config.consoleOrigin).toLowerCase();
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

  return { sessionFrom, wantsHtml, loginRedirectUrl, validateRt, checkOrigin };
}
