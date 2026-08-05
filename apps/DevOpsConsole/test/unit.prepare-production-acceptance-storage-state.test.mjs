import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createSessionManager } from '../src/auth/session.mjs';
import {
  DEFAULT_ENV_FILE,
  DEFAULT_OUTPUT,
  MAX_ACCEPTANCE_SESSION_TTL_MS,
  PRODUCTION_CREDENTIAL_FILES,
  atomicWriteStorageState,
  buildStorageState,
  loadProductionConsoleConfig,
  parseArgs,
  prepareProductionAcceptanceSession,
  productionCredentialEnvironment,
  selectConfiguredOwner,
} from '../Tools/prepare-production-acceptance-storage-state.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONSOLE_UNIT = path.resolve(APP_ROOT, '..', '..', 'deploy', 'devcoordinator-console@.service');

function config() {
  return {
    allowedEmails: new Set(['z-owner@example.test', 'a-owner@example.test']),
    sessionSecret: Buffer.alloc(32, 7),
    sessionTtlMs: 7 * 24 * 60 * 60 * 1000,
    cookieName: 'dc_session',
    domain: 'example.test',
    devInsecureHttp: false,
  };
}

test('production browser session arguments default to protected host paths', () => {
  assert.deepEqual(parseArgs([]), {
    envFile: DEFAULT_ENV_FILE,
    output: DEFAULT_OUTPUT,
  });
  assert.deepEqual(parseArgs([
    '--env-file', '/tmp/console.env',
    '--output', '/tmp/browser/storage.json',
  ]), {
    envFile: '/tmp/console.env',
    output: '/tmp/browser/storage.json',
  });
  assert.throws(() => parseArgs(['--output', 'relative.json']), /absolute path/);
  assert.throws(() => parseArgs(['--unknown', '/tmp/value']), /usage/);
  assert.throws(() => parseArgs(['--output', '/tmp/a', '--output', '/tmp/b']), /more than once/);
});

test('production browser sessions use the exact Console slot credential sources', () => {
  assert.deepEqual(productionCredentialEnvironment(), {
    SESSION_SECRET_FILE: '/etc/devcoordinator/edge/session-secret',
    TLS_CERT_FILE: '/etc/letsencrypt/live/vr.ae/fullchain.pem',
    TLS_KEY_FILE: '/etc/letsencrypt/live/vr.ae/privkey.pem',
  });
  const unit = fs.readFileSync(CONSOLE_UNIT, 'utf8');
  for (const [name, source] of [
    ['session-secret', PRODUCTION_CREDENTIAL_FILES.sessionSecret],
    ['tls-cert', PRODUCTION_CREDENTIAL_FILES.tlsCert],
    ['tls-key', PRODUCTION_CREDENTIAL_FILES.tlsKey],
  ]) {
    assert.match(unit, new RegExp(`^LoadCredential=${name}:${source.replaceAll('.', '\\.')}$`, 'm'));
  }
});

test('production Console config loads externalized credentials without env secrets', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'console-browser-credentials-'));
  try {
    const envFile = path.join(root, 'console.env');
    const stateDir = path.join(root, 'state');
    const acmeWebroot = path.join(root, 'acme');
    const sessionSecret = path.join(root, 'session-secret');
    const tlsCert = path.join(root, 'tls-cert');
    const tlsKey = path.join(root, 'tls-key');
    fs.writeFileSync(envFile, [
      'DOMAIN=example.test',
      'ALLOWED_EMAILS=owner@example.test',
      `STATE_DIR=${stateDir}`,
      `ACME_WEBROOT=${acmeWebroot}`,
      '',
    ].join('\n'));
    fs.writeFileSync(sessionSecret, `${'ab'.repeat(32)}\n`, { mode: 0o600 });
    fs.writeFileSync(tlsCert, 'fixture certificate\n', { mode: 0o600 });
    fs.writeFileSync(tlsKey, 'fixture key\n', { mode: 0o600 });

    const loaded = loadProductionConsoleConfig({
      envFile,
      credentialFiles: { sessionSecret, tlsCert, tlsKey },
    });
    assert.equal(loaded.tlsCertFile, tlsCert);
    assert.equal(loaded.tlsKeyFile, tlsKey);
    assert.equal(loaded.sessionSecret.toString('hex'), 'ab'.repeat(32));
    assert.deepEqual(loaded.allowedEmails, new Set(['owner@example.test']));
    assert.equal(fs.existsSync(stateDir), false);
    assert.equal(fs.existsSync(acmeWebroot), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('production browser state selects one owner and creates a one-hour signed session', () => {
  assert.equal(selectConfiguredOwner(config().allowedEmails), 'a-owner@example.test');
  assert.throws(() => selectConfiguredOwner(new Set()), /at least one configured owner/);

  const before = Math.floor(Date.now() / 1000);
  const issued = buildStorageState(config());
  const after = Math.floor(Date.now() / 1000);
  assert.equal(issued.storageState.cookies.length, 1);
  const cookie = issued.storageState.cookies[0];
  assert.deepEqual({
    name: cookie.name,
    domain: cookie.domain,
    path: cookie.path,
    httpOnly: cookie.httpOnly,
    secure: cookie.secure,
    sameSite: cookie.sameSite,
  }, {
    name: 'dc_session',
    domain: '.example.test',
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
  });
  assert.ok(cookie.expires >= before + (MAX_ACCEPTANCE_SESSION_TTL_MS / 1000));
  assert.ok(cookie.expires <= after + (MAX_ACCEPTANCE_SESSION_TTL_MS / 1000));
  assert.deepEqual(issued.storageState.origins, []);

  const sessions = createSessionManager({
    secret: config().sessionSecret, // public-artifact-guard: allow text-secret -- synthetic in-memory test value
    ttlMs: MAX_ACCEPTANCE_SESSION_TTL_MS,
    cookieName: 'dc_session',
    cookieDomain: '.example.test',
    secure: true,
  });
  assert.equal(sessions.parse(`dc_session=${cookie.value}`).email, 'a-owner@example.test');
});

test('storage state publication atomically replaces the file with mode 0600', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'console-browser-session-'));
  try {
    const output = path.join(root, 'private', 'storage-state.json');
    atomicWriteStorageState(output, { cookies: [], origins: [] });
    atomicWriteStorageState(output, { cookies: [{ name: 'replacement' }], origins: [] });
    assert.equal(fs.statSync(output).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(fs.readFileSync(output, 'utf8')), {
      cookies: [{ name: 'replacement' }],
      origins: [],
    });
    assert.deepEqual(
      fs.readdirSync(path.dirname(output)).filter((name) => name.endsWith('.partial')),
      [],
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('session preparation returns only a non-sensitive publication receipt', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'console-browser-session-receipt-'));
  try {
    const output = path.join(root, 'storage-state.json');
    const receipt = prepareProductionAcceptanceSession({ config: config(), output });
    assert.deepEqual(Object.keys(receipt).sort(), ['expires_at', 'ok', 'storage_state']);
    const serialized = JSON.stringify(receipt);
    assert.doesNotMatch(serialized, /owner@example|dc_session|local-production|eyJ/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
