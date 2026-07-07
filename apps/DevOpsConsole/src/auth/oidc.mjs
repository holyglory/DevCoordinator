// OIDC authorization-code + PKCE client (Google or any spec-compliant issuer,
// e.g. the local test fixture issuer). Zero dependencies: discovery + token
// exchange via global fetch, RS256 ID-token verification via node:crypto.
//
// Flow state ({ state, nonce, verifier, rt }) lives entirely in a signed,
// host-only, short-lived cookie ('dc_flow') — nothing is stored server-side.

import crypto from 'node:crypto';

const FLOW_COOKIE_NAME = 'dc_flow';
const FLOW_TTL_MS = 10 * 60 * 1000;
const DISCOVERY_TTL_MS = 24 * 60 * 60 * 1000;
const JWKS_TTL_MS = 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 10_000;
const CLOCK_SKEW_S = 300;

export class OidcError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'OidcError';
    this.code = code;
  }
}

function isLoopbackHost(hostname) {
  return (
    hostname === 'localhost' ||
    hostname === '::1' ||
    hostname === '[::1]' ||
    /^127(?:\.\d{1,3}){3}$/.test(hostname)
  );
}

function timingEq(a, b) {
  const bufA = Buffer.from(String(a), 'utf8');
  const bufB = Buffer.from(String(b), 'utf8');
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

function decodeJwtSegment(b64url) {
  try {
    const obj = JSON.parse(Buffer.from(b64url, 'base64url').toString('utf8'));
    if (obj !== null && typeof obj === 'object' && !Array.isArray(obj)) return obj;
  } catch {
    // fall through
  }
  throw new OidcError('bad_id_token', 'malformed id_token segment');
}

export function createOidc({ issuer, clientId, clientSecret, redirectUri, sessions, log }) {
  const issuerUrl = new URL(issuer); // throws on malformed issuer — fatal misconfig
  if (issuerUrl.protocol !== 'https:') {
    if (issuerUrl.protocol !== 'http:') {
      throw new OidcError('bad_issuer', `unsupported OIDC issuer protocol: ${issuerUrl.protocol}`);
    }
    if (!isLoopbackHost(issuerUrl.hostname)) {
      throw new OidcError(
        'insecure_issuer',
        `plain-http OIDC issuer is only allowed on loopback hosts, got ${issuerUrl.hostname}`,
      );
    }
  }
  const normalizedIssuer = String(issuer).replace(/\/+$/, '');
  const discoveryUrl = `${normalizedIssuer}/.well-known/openid-configuration`;
  const configured = Boolean(clientId) && Boolean(clientSecret);
  // Flow cookie must be Secure exactly when the deployment is https-facing;
  // the redirect URI scheme is the authoritative signal for that.
  const secureCookies = new URL(redirectUri).protocol === 'https:';

  let discoveryCache = { doc: null, at: 0, promise: null };
  let jwksCache = { keys: null, at: 0, promise: null };

  async function discover() {
    if (discoveryCache.doc && Date.now() - discoveryCache.at < DISCOVERY_TTL_MS) {
      return discoveryCache.doc;
    }
    const inFlight = discoveryCache.promise ?? (discoveryCache.promise = (async () => {
      const res = await fetch(discoveryUrl, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!res.ok) throw new OidcError('discovery_failed', `OIDC discovery returned HTTP ${res.status}`);
      const doc = await res.json();
      for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
        if (typeof doc?.[field] !== 'string' || doc[field] === '') {
          throw new OidcError('discovery_failed', `OIDC discovery document is missing ${field}`);
        }
      }
      return doc;
    })());
    try {
      const doc = await inFlight;
      discoveryCache = { doc, at: Date.now(), promise: null };
      return doc;
    } catch (err) {
      if (discoveryCache.promise === inFlight) discoveryCache.promise = null;
      if (discoveryCache.doc) {
        // Refresh failed but we have a (possibly stale) doc — keep serving it.
        log?.warn?.('oidc discovery refresh failed, using cached document', {
          error: String(err?.message || err),
        });
        return discoveryCache.doc;
      }
      if (err instanceof OidcError) throw err;
      throw new OidcError('discovery_failed', `OIDC discovery fetch failed: ${err?.message || err}`);
    }
  }

  async function loadJwks(doc, force) {
    if (!force && jwksCache.keys && Date.now() - jwksCache.at < JWKS_TTL_MS) {
      return jwksCache.keys;
    }
    const inFlight = jwksCache.promise ?? (jwksCache.promise = (async () => {
      const res = await fetch(doc.jwks_uri, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!res.ok) throw new OidcError('bad_id_token', `JWKS fetch returned HTTP ${res.status}`);
      const body = await res.json();
      if (!Array.isArray(body?.keys)) throw new OidcError('bad_id_token', 'JWKS document has no keys array');
      return body.keys;
    })());
    try {
      const keys = await inFlight;
      jwksCache = { keys, at: Date.now(), promise: null };
      return keys;
    } catch (err) {
      if (jwksCache.promise === inFlight) jwksCache.promise = null;
      if (err instanceof OidcError) throw err;
      throw new OidcError('bad_id_token', `JWKS fetch failed: ${err?.message || err}`);
    }
  }

  function selectKey(keys, kid) {
    const candidates = keys.filter(
      (k) => k && k.kty === 'RSA' && (!k.use || k.use === 'sig') && (!k.alg || k.alg === 'RS256'),
    );
    if (kid != null) return candidates.find((k) => k.kid === kid) ?? null;
    // No kid in the token header: unambiguous only if the set has one RSA key.
    return candidates.length === 1 ? candidates[0] : null;
  }

  async function verifyIdToken(idToken, doc, expectedNonce) {
    const parts = idToken.split('.');
    if (parts.length !== 3) throw new OidcError('bad_id_token', 'id_token is not a compact JWT');
    const [headerB64, payloadB64, sigB64] = parts;
    const header = decodeJwtSegment(headerB64);
    if (header.alg !== 'RS256') {
      throw new OidcError('bad_id_token', `unsupported id_token alg ${JSON.stringify(header.alg)} (only RS256)`);
    }
    const payload = decodeJwtSegment(payloadB64);

    let jwk = selectKey(await loadJwks(doc, false), header.kid);
    if (!jwk) jwk = selectKey(await loadJwks(doc, true), header.kid); // single refetch on unknown kid
    if (!jwk) throw new OidcError('bad_id_token', 'no JWKS key matches the id_token kid');
    let publicKey;
    try {
      publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    } catch {
      throw new OidcError('bad_id_token', 'JWKS key could not be loaded as an RSA public key');
    }
    const signature = Buffer.from(sigB64, 'base64url');
    const signedData = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
    if (signature.length === 0 || !crypto.verify('RSA-SHA256', signedData, publicKey, signature)) {
      throw new OidcError('bad_id_token', 'id_token signature verification failed');
    }

    const expectedIss = typeof doc.issuer === 'string' && doc.issuer !== '' ? doc.issuer : normalizedIssuer;
    if (payload.iss !== expectedIss) throw new OidcError('bad_id_token', 'id_token issuer mismatch');
    const audOk = payload.aud === clientId || (Array.isArray(payload.aud) && payload.aud.includes(clientId));
    if (!audOk) throw new OidcError('bad_id_token', 'id_token audience mismatch');
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp) || now > payload.exp + CLOCK_SKEW_S) {
      throw new OidcError('bad_id_token', 'id_token is expired');
    }
    if (typeof payload.iat !== 'number' || !Number.isFinite(payload.iat) || payload.iat > now + CLOCK_SKEW_S) {
      throw new OidcError('bad_id_token', 'id_token issued-at is in the future');
    }
    if (typeof payload.nonce !== 'string' || !timingEq(payload.nonce, expectedNonce)) {
      throw new OidcError('bad_id_token', 'id_token nonce mismatch');
    }
    if (payload.email_verified !== true) {
      throw new OidcError('bad_id_token', 'Google account email is not verified');
    }
    if (typeof payload.sub !== 'string' || payload.sub === '' || typeof payload.email !== 'string' || payload.email === '') {
      throw new OidcError('bad_id_token', 'id_token is missing sub or email');
    }
    return {
      sub: payload.sub,
      email: payload.email.toLowerCase(),
      name: typeof payload.name === 'string' ? payload.name : '',
      pic: typeof payload.picture === 'string' ? payload.picture : '',
    };
  }

  async function exchangeCode(doc, code, verifier) {
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
      code_verifier: verifier,
    });
    let res;
    let text;
    try {
      res = await fetch(doc.token_endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: form.toString(),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      text = await res.text();
    } catch (err) {
      throw new OidcError('exchange_failed', `token endpoint request failed: ${err?.message || err}`);
    }
    let tokens = null;
    try {
      tokens = JSON.parse(text);
    } catch {
      // handled below
    }
    if (!res.ok) {
      const hint = tokens?.error
        ? `${tokens.error}${tokens.error_description ? `: ${tokens.error_description}` : ''}`
        : String(text).slice(0, 200);
      throw new OidcError('exchange_failed', `token endpoint returned HTTP ${res.status} (${hint})`);
    }
    if (!tokens || typeof tokens.id_token !== 'string' || tokens.id_token === '') {
      // Google returns id_token alongside access_token; its absence is fatal.
      throw new OidcError('exchange_failed', 'token endpoint response did not include an id_token');
    }
    return tokens;
  }

  async function loginRedirect(rt) {
    if (!configured) {
      throw new OidcError('not_configured', 'Google OAuth client is not configured (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET)');
    }
    const doc = await discover();
    const state = crypto.randomBytes(32).toString('base64url');
    const nonce = crypto.randomBytes(32).toString('base64url');
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier, 'utf8').digest('base64url');
    const blob = sessions.signBlob({ state, nonce, verifier, rt: typeof rt === 'string' ? rt : '' }, FLOW_TTL_MS);
    // Host-only on purpose (no Domain attribute): the flow never leaves the console host.
    const flowCookie =
      `${FLOW_COOKIE_NAME}=${blob}; Path=/; HttpOnly; SameSite=Lax; ` +
      `Max-Age=${Math.floor(FLOW_TTL_MS / 1000)}${secureCookies ? '; Secure' : ''}`;
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'openid email profile',
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      access_type: 'online',
      prompt: 'select_account',
    });
    const sep = doc.authorization_endpoint.includes('?') ? '&' : '?';
    return { url: `${doc.authorization_endpoint}${sep}${params.toString()}`, flowCookie };
  }

  async function handleCallback(searchParams, flowCookieValue) {
    if (!configured) {
      throw new OidcError('not_configured', 'Google OAuth client is not configured (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET)');
    }
    const getParam = (name) => {
      if (searchParams && typeof searchParams.get === 'function') return searchParams.get(name);
      const value = searchParams?.[name];
      return value == null ? null : String(value);
    };

    const flow = sessions.verifyBlob(typeof flowCookieValue === 'string' ? flowCookieValue : '');
    if (
      !flow ||
      typeof flow.state !== 'string' || flow.state === '' ||
      typeof flow.nonce !== 'string' || flow.nonce === '' ||
      typeof flow.verifier !== 'string' || flow.verifier === ''
    ) {
      throw new OidcError('state_mismatch', 'sign-in flow cookie is missing or expired — start the sign-in again');
    }
    const providerError = getParam('error');
    if (providerError) {
      const description = getParam('error_description');
      throw new OidcError('provider_error', `sign-in was not completed: ${providerError}${description ? ` (${description})` : ''}`);
    }
    const state = getParam('state');
    if (typeof state !== 'string' || !timingEq(state, flow.state)) {
      throw new OidcError('state_mismatch', 'state parameter does not match the sign-in flow');
    }
    const code = getParam('code');
    if (typeof code !== 'string' || code === '') {
      throw new OidcError('exchange_failed', 'authorization code is missing from the callback');
    }

    const doc = await discover();
    const tokens = await exchangeCode(doc, code, flow.verifier);
    const profile = await verifyIdToken(tokens.id_token, doc, flow.nonce);
    log?.debug?.('oidc callback verified', { email: profile.email, sub: profile.sub });
    return { profile, rt: typeof flow.rt === 'string' ? flow.rt : '' };
  }

  return { configured, loginRedirect, handleCallback };
}
