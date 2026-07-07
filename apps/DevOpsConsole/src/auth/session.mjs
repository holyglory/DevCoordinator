// HMAC-signed cookie sessions + generic signed-blob helpers (flow cookie).
//
// Token format (both sessions and blobs):
//   base64url(JSON payload) + '.' + base64url(HMAC-SHA256(secret, payloadB64))
//
// Session payload: { v: 1, sub, email, name, pic, iat, exp }  (iat/exp seconds)
// Blob payload:    { v: 1, iat, exp, d: <caller object> }
// The `d` wrapper keeps blob tokens structurally distinct from session tokens,
// so one can never be replayed as the other even though both share the secret.

import crypto from 'node:crypto';

const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const MAX_TOKEN_LENGTH = 8192;

/**
 * Minimal, defensive Cookie-header parser. First occurrence of a name wins
 * (browsers send the most specific cookie first). Never throws.
 */
export function parseCookies(cookieHeader) {
  const out = Object.create(null);
  const header = Array.isArray(cookieHeader) ? cookieHeader.join('; ') : cookieHeader;
  if (typeof header !== 'string' || header === '') return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    if (!name || name in out) continue;
    let value = part.slice(eq + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    try {
      value = decodeURIComponent(value);
    } catch {
      // Keep the raw value; our own tokens are never percent-encoded.
    }
    out[name] = value;
  }
  return out;
}

function hmacSha256(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest();
}

function signToken(secret, payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = hmacSha256(secret, body).toString('base64url');
  return `${body}.${sig}`;
}

/** Verify signature + expiry. Returns the payload object or null. Never throws. */
function verifyToken(secret, token) {
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH) return null;
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1 || token.indexOf('.', dot + 1) !== -1) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!B64URL_RE.test(body) || !B64URL_RE.test(sig)) return null;
  const expected = hmacSha256(secret, body);
  const given = Buffer.from(sig, 'base64url');
  // Length guard: timingSafeEqual throws on unequal lengths.
  if (given.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(given, expected)) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return null;
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) return null;
  if (Math.floor(Date.now() / 1000) >= payload.exp) return null;
  return payload;
}

export function createSessionManager({ secret, ttlMs, cookieName, cookieDomain, secure }) {
  const key = Buffer.isBuffer(secret) ? secret : Buffer.from(String(secret ?? ''), 'utf8');
  if (key.length < 16) {
    throw new Error('session secret must be at least 16 bytes');
  }
  if (typeof cookieName !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(cookieName)) {
    throw new Error(`invalid session cookie name: ${JSON.stringify(cookieName)}`);
  }
  const ttlSeconds = Math.max(1, Math.floor(Number(ttlMs) / 1000));
  const domainAttr = cookieDomain
    ? `Domain=${String(cookieDomain).startsWith('.') ? cookieDomain : `.${cookieDomain}`}; `
    : '';
  const baseAttrs = `${domainAttr}Path=/; HttpOnly; SameSite=Lax`;
  const secureAttr = secure ? '; Secure' : '';

  function issue(profile) {
    const iat = Math.floor(Date.now() / 1000);
    const session = {
      v: 1,
      sub: String(profile.sub),
      email: String(profile.email).toLowerCase(),
      name: profile.name == null ? undefined : String(profile.name),
      pic: profile.pic == null ? undefined : String(profile.pic),
      iat,
      exp: iat + ttlSeconds,
    };
    const token = signToken(key, session);
    const cookie = `${cookieName}=${token}; ${baseAttrs}; Max-Age=${ttlSeconds}${secureAttr}`;
    return { cookie, session };
  }

  function parse(cookieHeader) {
    const token = parseCookies(cookieHeader)[cookieName];
    if (!token) return null;
    const payload = verifyToken(key, token);
    if (
      !payload ||
      payload.v !== 1 ||
      typeof payload.sub !== 'string' || payload.sub === '' ||
      typeof payload.email !== 'string' || payload.email === ''
    ) {
      return null;
    }
    return payload;
  }

  function clearCookie() {
    return `${cookieName}=; ${baseAttrs}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secureAttr}`;
  }

  function signBlob(obj, blobTtlMs = ttlMs) {
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + Math.floor(Number(blobTtlMs) / 1000);
    return signToken(key, { v: 1, iat, exp, d: { ...obj } });
  }

  function verifyBlob(str) {
    const payload = verifyToken(key, str);
    if (!payload || payload.v !== 1) return null;
    if (payload.d === null || typeof payload.d !== 'object' || Array.isArray(payload.d)) return null;
    return payload.d;
  }

  return { issue, parse, clearCookie, signBlob, verifyBlob };
}
