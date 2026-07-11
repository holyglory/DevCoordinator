// Unit tests for src/auth/guard.mjs — the rt open-redirect guard, the
// Origin/Referer CSRF check (exact-origin only), wantsHtml heuristics, and
// sessionFrom's allowlist re-check. Uses a REAL session manager (only config
// data objects are stubbed — no module mocks).

import test from 'node:test';
import assert from 'node:assert/strict';

import { createGuard } from '../src/auth/guard.mjs';
import { createSessionManager } from '../src/auth/session.mjs';

const SECRET = Buffer.from('ab'.repeat(32), 'hex'); // public-artifact-guard: allow text-secret -- deterministic test-only HMAC key bytes

const PROD_CONFIG = {
  domain: 'vr.ae',
  consoleHost: 'console.vr.ae',
  consoleOrigin: 'https://console.vr.ae',
  devInsecureHttp: false,
};

const DEV_CONFIG = {
  domain: 'vr.ae',
  consoleHost: 'console.vr.ae',
  consoleOrigin: 'http://console.vr.ae:8080',
  devInsecureHttp: true,
};

function makeSessions() {
  return createSessionManager({
    secret: SECRET,
    ttlMs: 3_600_000,
    cookieName: 'dc_session',
    cookieDomain: 'vr.ae',
    secure: true,
  });
}

function makeGuard({ config = PROD_CONFIG, allowedEmails = new Set(['admin@vr.ae']) } = {}) {
  return createGuard({ sessions: makeSessions(), allowedEmails, config });
}

test('validateRt accepts same-deployment absolute URLs (apex + subdomains)', () => {
  const guard = makeGuard();

  assert.equal(guard.validateRt('https://x.vr.ae/p?q'), 'https://x.vr.ae/p?q');
  assert.equal(guard.validateRt('https://vr.ae/'), 'https://vr.ae/');
  assert.equal(guard.validateRt('https://vr.ae'), 'https://vr.ae/'); // URL-normalized
  assert.equal(guard.validateRt('https://console.vr.ae/routes#frag'), 'https://console.vr.ae/routes#frag');
  assert.equal(guard.validateRt('https://VR.AE/'), 'https://vr.ae/'); // hostname case-folded
  // Embedded credentials are stripped, never echoed into a redirect.
  assert.equal(guard.validateRt('https://user:pass@app.vr.ae/x'), 'https://app.vr.ae/x');
});

test('validateRt rejects everything else → falls back to "/"', () => {
  const guard = makeGuard();

  const rejected = [
    'http://x.vr.ae/p', // wrong scheme outside dev mode
    'https://evil.com', // foreign host
    'https://evilvr.ae', // suffix trick without the dot boundary
    'https://vr.ae.evil.com', // our domain as a foreign subdomain prefix
    'javascript:alert(1)', // dangerous scheme
    'javascript://vr.ae/%0aalert(1)', // dangerous scheme dressed as ours
    '//evil.com', // protocol-relative (not an absolute URL)
    '/relative/path', // relative (not an absolute URL)
    'garbage not a url',
    'https://', // unparseable
    '',
  ];
  for (const rt of rejected) {
    assert.equal(guard.validateRt(rt), '/', `expected fallback for ${JSON.stringify(rt)}`);
  }
  assert.equal(guard.validateRt(undefined), '/');
  assert.equal(guard.validateRt(null), '/');
  assert.equal(guard.validateRt(42), '/');
});

test('validateRt in dev mode: scheme must match the deployment exactly', () => {
  const guard = makeGuard({ config: DEV_CONFIG });
  assert.equal(guard.validateRt('http://x.vr.ae:5173/p'), 'http://x.vr.ae:5173/p');
  assert.equal(guard.validateRt('https://x.vr.ae/p'), '/'); // https rejected when deployment is http
});

test('checkOrigin: exact console-origin match only (Origin preferred)', () => {
  const guard = makeGuard();
  const withOrigin = (origin) => ({ headers: { origin } });

  assert.equal(guard.checkOrigin(withOrigin('https://console.vr.ae')), true);
  assert.equal(guard.checkOrigin(withOrigin('HTTPS://CONSOLE.VR.AE')), true); // case-insensitive

  assert.equal(guard.checkOrigin(withOrigin('https://x.vr.ae')), false, 'sibling subdomain must be rejected');
  assert.equal(guard.checkOrigin(withOrigin('https://vr.ae')), false, 'apex must be rejected');
  assert.equal(guard.checkOrigin(withOrigin('https://console.vr.ae.evil.com')), false);
  assert.equal(guard.checkOrigin(withOrigin('https://evilconsole.vr.ae')), false);
  assert.equal(guard.checkOrigin(withOrigin('http://console.vr.ae')), false, 'scheme downgrade rejected');
  assert.equal(guard.checkOrigin(withOrigin('https://console.vr.ae:8443')), false, 'foreign port rejected');
  assert.equal(guard.checkOrigin(withOrigin('null')), false, 'opaque origin rejected');

  // A bad Origin is final — a matching Referer must NOT rescue it.
  assert.equal(
    guard.checkOrigin({ headers: { origin: 'https://evil.com', referer: 'https://console.vr.ae/x' } }),
    false,
  );
});

test('checkOrigin: Referer fallback, and absent-both rejects', () => {
  const guard = makeGuard();
  const withReferer = (referer) => ({ headers: { referer } });

  assert.equal(guard.checkOrigin(withReferer('https://console.vr.ae/routes?x=1')), true);
  assert.equal(guard.checkOrigin(withReferer('https://x.vr.ae/page')), false);
  assert.equal(guard.checkOrigin(withReferer('https://console.vr.ae.evil.com/x')), false);
  assert.equal(guard.checkOrigin(withReferer('not a url')), false);
  assert.equal(guard.checkOrigin({ headers: {} }), false, 'no Origin, no Referer → reject');

  // Dev origin includes the port — must match exactly there too.
  const devGuard = makeGuard({ config: DEV_CONFIG });
  assert.equal(devGuard.checkOrigin({ headers: { origin: 'http://console.vr.ae:8080' } }), true);
  assert.equal(devGuard.checkOrigin({ headers: { origin: 'http://console.vr.ae' } }), false);
});

test('wantsHtml heuristics: /api/* and JSON accept are API, everything else is navigation', () => {
  const guard = makeGuard();
  const req = (url, accept) => ({ url, headers: accept === undefined ? {} : { accept } });

  // API-shaped → false regardless of Accept.
  assert.equal(guard.wantsHtml(req('/api/overview', 'text/html')), false);
  assert.equal(guard.wantsHtml(req('/api', undefined)), false);
  assert.equal(guard.wantsHtml(req('/api?x=1', undefined)), false);
  assert.equal(guard.wantsHtml(req('/api/routes/x', undefined)), false);

  // JSON accept → false.
  assert.equal(guard.wantsHtml(req('/', 'application/json')), false);
  assert.equal(guard.wantsHtml(req('/x', 'application/json, text/plain')), false);

  // Navigations → true: browsers, curl-style */* and missing Accept.
  assert.equal(guard.wantsHtml(req('/', 'text/html,application/xhtml+xml;q=0.9')), true);
  assert.equal(guard.wantsHtml(req('/', '*/*')), true);
  assert.equal(guard.wantsHtml(req('/', undefined)), true);
  // Prefix look-alike is NOT the api tree.
  assert.equal(guard.wantsHtml(req('/apifoo', undefined)), true);
});

test('sessionFrom: valid session accepted, allowlist re-checked on EVERY request', () => {
  const sessions = makeSessions();
  const allowedEmails = new Set(['admin@vr.ae']);
  const guard = createGuard({ sessions, allowedEmails, config: PROD_CONFIG });

  const { cookie } = sessions.issue({ sub: '1', email: 'ADMIN@vr.ae' });
  const cookieHeader = cookie.slice(0, cookie.indexOf(';'));

  const ok = guard.sessionFrom({ headers: { cookie: cookieHeader } });
  assert.ok(ok);
  assert.equal(ok.email, 'admin@vr.ae');

  // Same valid cookie, but email no longer allowlisted → revoked immediately.
  allowedEmails.delete('admin@vr.ae');
  assert.equal(guard.sessionFrom({ headers: { cookie: cookieHeader } }), null);

  // Cookie signed for an email that was never allowlisted.
  const { cookie: strangerCookie } = sessions.issue({ sub: '2', email: 'stranger@evil.com' });
  const guard2 = createGuard({ sessions, allowedEmails: new Set(['admin@vr.ae']), config: PROD_CONFIG });
  assert.equal(guard2.sessionFrom({ headers: { cookie: strangerCookie.slice(0, strangerCookie.indexOf(';')) } }), null);

  // No cookie / tampered cookie.
  assert.equal(guard2.sessionFrom({ headers: {} }), null);
  const tampered = cookieHeader.slice(0, -2) + (cookieHeader.endsWith('A') ? 'B' : 'A') + cookieHeader.slice(-1);
  assert.equal(guard2.sessionFrom({ headers: { cookie: tampered } }), null);
});

test('loginRedirectUrl builds an absolute rt from the request, host sanitized', () => {
  const guard = makeGuard();

  assert.equal(
    guard.loginRedirectUrl({ headers: { host: 'APP.vr.ae' }, url: '/x?y=1' }),
    `https://console.vr.ae/auth/login?rt=${encodeURIComponent('https://app.vr.ae/x?y=1')}`,
  );

  // Malformed Host header falls back to the console host.
  assert.equal(
    guard.loginRedirectUrl({ headers: { host: 'bad host!!' }, url: '/p' }),
    `https://console.vr.ae/auth/login?rt=${encodeURIComponent('https://console.vr.ae/p')}`,
  );
});
