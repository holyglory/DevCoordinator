import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createIdentityAssertionSigner } from '../src/identity-assertion.mjs';

function decode(segment) {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

test('route assertions carry the verified Console actor and are signed by a private stable key', async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-identity-assertion-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const clock = () => 1_774_694_400_000;
  const signer = createIdentityAssertionSigner({ stateDir: dir, issuer: 'https://console.vr.ae', clock });
  await signer.load();

  const token = signer.sign({
    subject: 'Owner@Example.com',
    audience: 'gf2.vr.ae',
    resource: 'route:gf2',
    method: 'PATCH',
  });
  const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
  const header = decode(encodedHeader);
  const payload = decode(encodedPayload);
  const jwks = signer.publicJwks();

  assert.deepEqual(header, { alg: 'EdDSA', kid: jwks.keys[0].kid, typ: 'JWT' });
  assert.equal(payload.iss, 'https://console.vr.ae');
  assert.equal(payload.aud, 'gf2.vr.ae');
  assert.equal(payload.sub, 'owner@example.com');
  assert.equal(payload.resource, 'route:gf2');
  assert.equal(payload.method, 'PATCH');
  assert.equal(payload.iat, 1_774_694_400);
  assert.equal(payload.exp, 1_774_694_415);
  assert.match(payload.jti, /^[0-9a-f-]{36}$/);
  assert.equal(jwks.keys[0].d, undefined);
  assert.equal(
    verify(
      null,
      Buffer.from(`${encodedHeader}.${encodedPayload}`, 'ascii'),
      createPublicKey({ key: jwks.keys[0], format: 'jwk' }),
      Buffer.from(encodedSignature, 'base64url'),
    ),
    true,
  );
  assert.equal((await fsp.stat(path.join(dir, 'identity-assertion-private.pem'))).mode & 0o777, 0o600);
  assert.equal((await fsp.stat(path.join(dir, 'identity-assertion-public.json'))).mode & 0o777, 0o600);

  const reloaded = createIdentityAssertionSigner({ stateDir: dir, issuer: 'https://console.vr.ae', clock });
  await reloaded.load();
  assert.equal(reloaded.publicJwks().keys[0].kid, jwks.keys[0].kid);
});

test('assertion inputs reject caller-shaped identity and routing ambiguity', async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-identity-input-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const signer = createIdentityAssertionSigner({ stateDir: dir, issuer: 'https://console.vr.ae' });
  await signer.load();

  assert.throws(() => signer.sign({
    subject: 'not-an-email', audience: 'gf2.vr.ae', resource: 'route:gf2', method: 'GET',
  }), /subject/);
  assert.throws(() => signer.sign({
    subject: 'owner@example.com', audience: 'other host', resource: 'route:gf2', method: 'GET',
  }), /audience/);
  assert.throws(() => signer.sign({
    subject: 'owner@example.com', audience: 'gf2.vr.ae', resource: 'route:other/../gf2', method: 'GET',
  }), /resource/);
  assert.throws(() => signer.sign({
    subject: 'owner@example.com', audience: 'gf2.vr.ae', resource: 'route:gf2', method: 'GET\nPOST',
  }), /method/);
});
