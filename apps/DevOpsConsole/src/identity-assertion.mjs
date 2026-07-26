// Short-lived, route-bound identity assertions for independently authorized
// loopback applications. The private Ed25519 key never leaves Console state;
// upstreams fetch only the public JWKS document.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign as signBytes,
} from 'node:crypto';
import { promises as fsp } from 'node:fs';
import path from 'node:path';

const PRIVATE_NAME = 'identity-assertion-private.pem';
const PUBLIC_NAME = 'identity-assertion-public.json';
const ASSERTION_TTL_SECONDS = 15;
const EMAIL_RE = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const AUDIENCE_RE = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::\d{1,5})?$/;
const RESOURCE_RE = /^route:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const METHOD_RE = /^[A-Z]{3,16}$/;

function encodedJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

async function privateRegularFile(file) {
  const stat = await fsp.lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`identity assertion key must be a regular file: ${file}`);
  }
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new Error(`identity assertion key must be owned by the Console account: ${file}`);
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(`identity assertion key must not be group/world accessible: ${file}`);
  }
}

async function atomicWrite(file, value, mode) {
  const temporary = `${file}.tmp-${process.pid}-${randomUUID()}`;
  try {
    await fsp.writeFile(temporary, value, { encoding: 'utf8', mode, flag: 'wx' });
    await fsp.chmod(temporary, mode);
    await fsp.rename(temporary, file);
  } finally {
    await fsp.unlink(temporary).catch(() => {});
  }
}

function normalizedIssuer(value) {
  const parsed = new URL(value);
  if (
    !['http:', 'https:'].includes(parsed.protocol)
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.pathname !== '/'
    || parsed.search !== ''
    || parsed.hash !== ''
  ) {
    throw new TypeError('identity assertion issuer must be one HTTP(S) origin');
  }
  return parsed.origin;
}

export function createIdentityAssertionSigner({ stateDir, issuer, clock = Date.now } = {}) {
  if (typeof stateDir !== 'string' || stateDir === '') {
    throw new TypeError('createIdentityAssertionSigner requires a state directory');
  }
  const canonicalIssuer = normalizedIssuer(issuer);
  const privateFile = path.join(stateDir, PRIVATE_NAME);
  const publicFile = path.join(stateDir, PUBLIC_NAME);
  let privateKey = null;
  let publicJwk = null;

  async function load() {
    await fsp.mkdir(stateDir, { recursive: true, mode: 0o700 });
    let privatePem;
    try {
      await privateRegularFile(privateFile);
      privatePem = await fsp.readFile(privateFile, 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      const generated = generateKeyPairSync('ed25519');
      privatePem = generated.privateKey.export({ type: 'pkcs8', format: 'pem' });
      await atomicWrite(privateFile, privatePem, 0o600);
    }
    privateKey = createPrivateKey(privatePem);
    if (privateKey.asymmetricKeyType !== 'ed25519') {
      throw new Error('identity assertion private key must be Ed25519');
    }
    const exported = createPublicKey(privateKey).export({ format: 'jwk' });
    const keyIdentity = JSON.stringify({ crv: exported.crv, kty: exported.kty, x: exported.x });
    const kid = createHash('sha256').update(keyIdentity, 'utf8').digest('hex');
    publicJwk = { ...exported, alg: 'EdDSA', kid, use: 'sig' };
    const payload = `${JSON.stringify({ keys: [publicJwk] })}\n`;
    let current = null;
    try {
      const stat = await fsp.lstat(publicFile);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        throw new Error(`identity assertion public key must be a regular file: ${publicFile}`);
      }
      current = await fsp.readFile(publicFile, 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    if (current !== payload) await atomicWrite(publicFile, payload, 0o644);
    else await fsp.chmod(publicFile, 0o644);
  }

  function publicJwks() {
    if (!publicJwk) throw new Error('identity assertion signer is not loaded');
    return { keys: [{ ...publicJwk }] };
  }

  function sign({ subject, audience, resource, method }) {
    if (!privateKey || !publicJwk) throw new Error('identity assertion signer is not loaded');
    const normalizedSubject = typeof subject === 'string' ? subject.trim().toLowerCase() : '';
    if (normalizedSubject.length > 254 || !EMAIL_RE.test(normalizedSubject)) {
      throw new TypeError('identity assertion subject must be one normalized email address');
    }
    if (typeof audience !== 'string' || !AUDIENCE_RE.test(audience)) {
      throw new TypeError('identity assertion audience must be one exact public host');
    }
    if (typeof resource !== 'string' || !RESOURCE_RE.test(resource)) {
      throw new TypeError('identity assertion resource must be one exact route grant');
    }
    const normalizedMethod = typeof method === 'string' ? method.toUpperCase() : '';
    if (!METHOD_RE.test(normalizedMethod)) {
      throw new TypeError('identity assertion method is invalid');
    }
    const issuedAt = Math.floor(clock() / 1000);
    const header = encodedJson({ alg: 'EdDSA', kid: publicJwk.kid, typ: 'JWT' });
    const payload = encodedJson({
      iss: canonicalIssuer,
      aud: audience,
      sub: normalizedSubject,
      resource,
      method: normalizedMethod,
      iat: issuedAt,
      exp: issuedAt + ASSERTION_TTL_SECONDS,
      jti: randomUUID(),
    });
    const input = `${header}.${payload}`;
    const signature = signBytes(null, Buffer.from(input, 'ascii'), privateKey).toString('base64url');
    return `${input}.${signature}`;
  }

  return { load, publicJwks, sign };
}
