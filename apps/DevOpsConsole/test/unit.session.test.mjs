// Unit tests for src/auth/session.mjs — issue/parse round-trip, expiry,
// tamper rejection (payload byte + signature byte), wrong-length signatures,
// exact cookie attribute strings, and signBlob/verifyBlob TTL. Real module.
//
// Expiry tests shift the wall clock by temporarily overriding the global
// Date.now during ISSUANCE only (the module under test is never mocked);
// verification then runs against the real clock, so results are deterministic
// without sleeping.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createSessionManager, parseCookies } from '../src/auth/session.mjs';

const SECRET = Buffer.from('ab'.repeat(32), 'hex'); // public-artifact-guard: allow text-secret -- deterministic test-only HMAC key bytes
const PROFILE = {
  sub: '107691503500061507151',
  email: 'Admin@VR.AE',
  name: 'Admin Person',
  pic: 'https://example.test/p.png',
};

function makeManager(overrides = {}) {
  return createSessionManager({
    secret: SECRET,
    ttlMs: 3_600_000, // 1h
    cookieName: 'dc_session',
    cookieDomain: 'vr.ae',
    secure: true,
    ...overrides,
  });
}

function tokenFromCookie(cookie) {
  return cookie.slice(cookie.indexOf('=') + 1, cookie.indexOf(';'));
}

// Replace the character at `index` with a different valid base64url character.
function flipChar(str, index) {
  const replacement = str[index] === 'A' ? 'B' : 'A';
  return str.slice(0, index) + replacement + str.slice(index + 1);
}

function withNowOffset(offsetMs, fn) {
  const realNow = Date.now;
  Date.now = () => realNow() + offsetMs;
  try {
    return fn();
  } finally {
    Date.now = realNow;
  }
}

test('issue → parse round-trip: signature verified, email lowercased, iat/exp coherent', () => {
  const mgr = makeManager();
  const { cookie, session } = mgr.issue(PROFILE);
  assert.equal(session.email, 'admin@vr.ae');
  assert.equal(session.exp - session.iat, 3600);

  const parsed = mgr.parse(`dc_session=${tokenFromCookie(cookie)}`);
  assert.ok(parsed, 'freshly issued token must parse');
  assert.equal(parsed.v, 1);
  assert.equal(parsed.sub, PROFILE.sub);
  assert.equal(parsed.email, 'admin@vr.ae');
  assert.equal(parsed.name, PROFILE.name);
  assert.equal(parsed.pic, PROFILE.pic);
  assert.equal(parsed.iat, session.iat);
  assert.equal(parsed.exp, session.exp);

  // parse also works from a real multi-cookie header.
  const multi = mgr.parse(`other=1; dc_session=${tokenFromCookie(cookie)}; last=z`);
  assert.equal(multi.sub, PROFILE.sub);
});

test('cookie attribute string is exact: Domain, Path, HttpOnly, SameSite=Lax, Max-Age, Secure', () => {
  const secureMgr = makeManager({ secure: true });
  const { cookie } = secureMgr.issue(PROFILE);
  const token = tokenFromCookie(cookie);
  assert.match(token, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, 'token must be b64url.b64url');
  assert.equal(
    cookie,
    `dc_session=${token}; Domain=.vr.ae; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600; Secure`,
  );

  const insecureMgr = makeManager({ secure: false });
  const { cookie: devCookie } = insecureMgr.issue(PROFILE);
  assert.equal(
    devCookie,
    `dc_session=${tokenFromCookie(devCookie)}; Domain=.vr.ae; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600`,
  );

  // A cookieDomain given with a leading dot must not double the dot.
  const dotted = makeManager({ cookieDomain: '.vr.ae' });
  const { cookie: dottedCookie } = dotted.issue(PROFILE);
  assert.ok(dottedCookie.includes('; Domain=.vr.ae; '), dottedCookie);
  assert.ok(!dottedCookie.includes('..vr.ae'), dottedCookie);

  assert.equal(
    secureMgr.clearCookie(),
    'dc_session=; Domain=.vr.ae; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure',
  );
  assert.equal(
    insecureMgr.clearCookie(),
    'dc_session=; Domain=.vr.ae; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  );
});

test('expired session is rejected', () => {
  const mgr = makeManager(); // 1h ttl

  // Issued two hours ago → expired one hour ago.
  const { cookie: oldCookie } = withNowOffset(-2 * 3_600_000, () => mgr.issue(PROFILE));
  assert.equal(mgr.parse(`dc_session=${tokenFromCookie(oldCookie)}`), null);

  // Boundary: issued exactly ttl ago → exp === now → rejected (>= comparison).
  const { cookie: edgeCookie } = withNowOffset(-3_600_000, () => mgr.issue(PROFILE));
  assert.equal(mgr.parse(`dc_session=${tokenFromCookie(edgeCookie)}`), null);

  // Sanity: a fresh one still parses with the same manager.
  const { cookie: freshCookie } = mgr.issue(PROFILE);
  assert.ok(mgr.parse(`dc_session=${tokenFromCookie(freshCookie)}`));
});

test('tampering with one payload byte invalidates the token', () => {
  const mgr = makeManager();
  const token = tokenFromCookie(mgr.issue(PROFILE).cookie);
  const [body, sig] = token.split('.');

  const tamperedBody = flipChar(body, Math.floor(body.length / 2));
  assert.notEqual(tamperedBody, body);
  assert.equal(mgr.parse(`dc_session=${tamperedBody}.${sig}`), null);
});

test('tampering with one signature byte invalidates the token', () => {
  const mgr = makeManager();
  const token = tokenFromCookie(mgr.issue(PROFILE).cookie);
  const [body, sig] = token.split('.');

  // Flip the FIRST signature char (the last char's low bits can be discarded
  // by base64url decoding, which would not change the decoded bytes).
  const tamperedSig = flipChar(sig, 0);
  assert.notEqual(tamperedSig, sig);
  assert.equal(mgr.parse(`dc_session=${body}.${tamperedSig}`), null);
});

test('wrong-length or malformed signatures return null and never throw', () => {
  const mgr = makeManager();
  const token = tokenFromCookie(mgr.issue(PROFILE).cookie);
  const [body, sig] = token.split('.');

  const badTokens = [
    `${body}.AAAA`, // sig decodes to 3 bytes, not 32 — timingSafeEqual length guard
    `${body}.${'A'.repeat(200)}`, // sig far too long
    `${body}.A`, // 1-char sig
    body, // no dot at all
    `${body}.`, // empty sig
    `.${sig}`, // empty body
    `${body}.${sig}.extra`, // two dots
    `${'A'.repeat(9000)}.${sig}`, // over MAX_TOKEN_LENGTH
    'not!base64url.%%%', // invalid alphabet
    '..', // dots only
  ];
  for (const bad of badTokens) {
    let result;
    assert.doesNotThrow(() => {
      result = mgr.parse(`dc_session=${bad}`);
    }, `token ${JSON.stringify(bad.slice(0, 40))} must not throw`);
    assert.equal(result, null, `token ${JSON.stringify(bad.slice(0, 40))} must be rejected`);
  }

  // Malformed cookie headers as a whole.
  assert.equal(mgr.parse(undefined), null);
  assert.equal(mgr.parse(''), null);
  assert.equal(mgr.parse('dc_session'), null); // no '='
  assert.equal(mgr.parse('other=zzz'), null); // our cookie absent
});

test('session and blob tokens are not interchangeable despite the shared secret', () => {
  const mgr = makeManager();

  // A signed blob must never parse as a session…
  const blobToken = mgr.signBlob({ sub: 'x', email: 'admin@vr.ae' }, 60_000);
  assert.equal(mgr.parse(`dc_session=${blobToken}`), null);

  // …and a session token must never verify as a blob.
  const sessionToken = tokenFromCookie(mgr.issue(PROFILE).cookie);
  assert.equal(mgr.verifyBlob(sessionToken), null);
});

test('signBlob/verifyBlob: round-trip, TTL expiry, wrong secret', () => {
  const mgr = makeManager();
  const data = { state: 'st_123', nonce: 'n_456', verifier: 'v_789', rt: 'https://x.vr.ae/p' };

  // Round-trip.
  const blob = mgr.signBlob(data, 60_000);
  assert.deepEqual(mgr.verifyBlob(blob), data);

  // Zero TTL → expired immediately (exp === iat, >= comparison).
  assert.equal(mgr.verifyBlob(mgr.signBlob(data, 0)), null);

  // Signed 10 minutes ago with a 1 minute TTL → expired now.
  const stale = withNowOffset(-600_000, () => mgr.signBlob(data, 60_000));
  assert.equal(mgr.verifyBlob(stale), null);

  // Default TTL falls back to the manager ttlMs (1h) → still valid.
  assert.deepEqual(mgr.verifyBlob(mgr.signBlob(data)), data);

  // A different secret must reject the blob outright.
  const otherMgr = makeManager({ secret: Buffer.from('cd'.repeat(32), 'hex') });
  assert.equal(otherMgr.verifyBlob(blob), null);

  // Tampered blob payload rejected too.
  const [bBody, bSig] = blob.split('.');
  assert.equal(mgr.verifyBlob(`${flipChar(bBody, 3)}.${bSig}`), null);
});

test('parseCookies: first occurrence wins, quotes unwrapped, arrays joined, never throws', () => {
  const jar = parseCookies('a=1; a=2; b="quoted"; malformed; c=%20x');
  assert.equal(jar.a, '1');
  assert.equal(jar.b, 'quoted');
  assert.equal(jar.c, ' x'); // percent-decoded
  assert.ok(!('malformed' in jar));

  // Null-prototype result (defensive against prototype pollution) — compare contents.
  assert.deepEqual({ ...parseCookies(undefined) }, {});
  assert.equal(Object.getPrototypeOf(jar), null);
  assert.equal(parseCookies(['x=1', 'y=2']).y, '2'); // array header form
  assert.equal(parseCookies('bad=%E0%A4%A')['bad'], '%E0%A4%A'); // undecodable stays raw
});

test('constructor guards: weak secret and invalid cookie name throw at construction', () => {
  assert.throws(() => makeManager({ secret: 'short' }), /at least 16 bytes/);
  assert.throws(() => makeManager({ cookieName: 'bad name;' }), /invalid session cookie name/);
});
