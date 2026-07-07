// Minimal but REAL OIDC issuer for tests (architecture.md "Test fixtures").
//
// Implements exactly what the console's oidc.mjs consumes:
//   GET  /.well-known/openid-configuration  discovery document
//   GET  /authorize   auto-approves and 302s straight back to redirect_uri
//                     with code & state (no consent screen)
//   POST /token       single-use code exchange; enforces client credentials,
//                     redirect_uri match and PKCE S256; returns an RS256-signed
//                     id_token built by hand (JWS over base64url segments)
//                     honoring the nonce from the authorize request
//   GET  /jwks        RSA public key as a JWK
//
// Claims { sub, email, name, email_verified } are configurable at construction
// and switchable per test via setClaims().

import crypto from 'node:crypto';
import http from 'node:http';

const b64url = (input) => Buffer.from(input).toString('base64url');

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

export async function startIssuer({
  clientId = 'test-client',
  clientSecret = 'test-secret',
  claims = {},
} = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = `fixture-${crypto.randomBytes(6).toString('hex')}`;

  let currentClaims = {
    sub: 'fixture-sub-0001',
    email: 'ja@vr.ae',
    name: 'Fixture User',
    email_verified: true,
    ...claims,
  };

  // code -> { nonce, challenge, challengeMethod, redirectUri, claims } (single use)
  const codes = new Map();
  const tokenRequests = []; // recorded for assertions

  let baseUrl = ''; // set after listen

  function signIdToken({ aud, nonce, claims: c }) {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'RS256', typ: 'JWT', kid };
    const payload = {
      iss: baseUrl,
      aud,
      sub: c.sub,
      email: c.email,
      name: c.name,
      email_verified: c.email_verified,
      iat: now,
      exp: now + 3600,
    };
    if (nonce != null) payload.nonce = nonce;
    const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
    const signature = crypto
      .sign('RSA-SHA256', Buffer.from(signingInput, 'utf8'), privateKey)
      .toString('base64url');
    return `${signingInput}.${signature}`;
  }

  function handleAuthorize(url, res) {
    const q = url.searchParams;
    if (q.get('client_id') !== clientId) return sendJson(res, 400, { error: 'invalid_client' });
    if (q.get('response_type') !== 'code') return sendJson(res, 400, { error: 'unsupported_response_type' });
    const redirectUri = q.get('redirect_uri');
    if (!redirectUri) return sendJson(res, 400, { error: 'invalid_request' });

    const code = crypto.randomBytes(16).toString('base64url');
    codes.set(code, {
      nonce: q.get('nonce'),
      challenge: q.get('code_challenge'),
      challengeMethod: q.get('code_challenge_method'),
      redirectUri,
      claims: { ...currentClaims }, // snapshot at authorize time, like a real IdP session
    });

    const location = new URL(redirectUri);
    location.searchParams.set('code', code);
    const state = q.get('state');
    if (state != null) location.searchParams.set('state', state);
    res.writeHead(302, { location: location.href, 'cache-control': 'no-store' });
    res.end();
  }

  async function handleToken(req, res) {
    const form = new URLSearchParams(await readBody(req));
    tokenRequests.push(Object.fromEntries(form.entries()));

    if (form.get('client_id') !== clientId || form.get('client_secret') !== clientSecret) {
      return sendJson(res, 401, { error: 'invalid_client' });
    }
    if (form.get('grant_type') !== 'authorization_code') {
      return sendJson(res, 400, { error: 'unsupported_grant_type' });
    }
    const grant = codes.get(form.get('code'));
    codes.delete(form.get('code')); // single use
    if (!grant) return sendJson(res, 400, { error: 'invalid_grant' });
    if (form.get('redirect_uri') !== grant.redirectUri) {
      return sendJson(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
    }
    if (grant.challenge) {
      if (grant.challengeMethod !== 'S256') {
        return sendJson(res, 400, { error: 'invalid_request', error_description: 'unsupported code_challenge_method' });
      }
      const verifier = form.get('code_verifier') || '';
      const computed = crypto.createHash('sha256').update(verifier, 'utf8').digest('base64url');
      if (computed !== grant.challenge) {
        return sendJson(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
      }
    }
    sendJson(res, 200, {
      access_token: `fixture-access-${crypto.randomBytes(8).toString('hex')}`,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'openid email profile',
      id_token: signIdToken({ aud: form.get('client_id'), nonce: grant.nonce, claims: grant.claims }),
    });
  }

  const server = http.createServer((req, res) => {
    (async () => {
      const url = new URL(req.url ?? '/', baseUrl);
      if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
        return sendJson(res, 200, {
          issuer: baseUrl,
          authorization_endpoint: `${baseUrl}/authorize`,
          token_endpoint: `${baseUrl}/token`,
          jwks_uri: `${baseUrl}/jwks`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          code_challenge_methods_supported: ['S256'],
        });
      }
      if (req.method === 'GET' && url.pathname === '/authorize') return handleAuthorize(url, res);
      if (req.method === 'POST' && url.pathname === '/token') return handleToken(req, res);
      if (req.method === 'GET' && url.pathname === '/jwks') {
        return sendJson(res, 200, {
          keys: [{ ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' }],
        });
      }
      sendJson(res, 404, { error: 'not_found' });
    })().catch((err) => {
      if (!res.headersSent) sendJson(res, 500, { error: String(err?.message ?? err) });
      else res.destroy();
    });
  });

  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;

  return {
    url: baseUrl,
    port,
    kid,
    setClaims(partial) {
      currentClaims = { ...currentClaims, ...partial };
      return { ...currentClaims };
    },
    getClaims: () => ({ ...currentClaims }),
    tokenRequests,
    close: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}
