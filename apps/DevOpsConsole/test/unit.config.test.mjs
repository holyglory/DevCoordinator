// Unit tests for src/config.mjs — .env parsing (quotes, comments, CRLF),
// process.env precedence, degraded Google mode, aggregated fatal errors, and
// HTTP_PORT=0 semantics. Real module, real temp files, no mocks.

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadConfig, ConfigError } from '../src/config.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const HEX64 = 'ab'.repeat(32);

async function makeTmp(t) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-config-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  return dir;
}

async function writeEnvFile(dir, lines, eol = '\n') {
  const file = path.join(dir, 'test.env');
  await fsp.writeFile(file, lines.join(eol) + eol, 'utf8');
  return file;
}

async function emptyEnvFile(dir) {
  return writeEnvFile(dir, []);
}

// Minimal valid configuration via the `env` parameter (DEV_HTTP avoids TLS).
function minimalEnv(dir, extra = {}) {
  return {
    DOMAIN: 'vr.ae',
    SESSION_SECRET: HEX64,
    DEV_HTTP: '1',
    HTTP_PORT: '8080',
    STATE_DIR: path.join(dir, 'state'),
    ...extra,
  };
}

test('.env parsing: comments, blank lines, CRLF, quotes, export prefix, = in values', async (t) => {
  const dir = await makeTmp(t);
  const envFile = await writeEnvFile(
    dir,
    [
      '# top comment',
      '   # indented comment',
      '',
      'DOMAIN="vr.ae"',
      "export CONSOLE_SUBDOMAIN='panel'",
      `SESSION_SECRET=${HEX64}`,
      'DEV_HTTP=1',
      'HTTP_PORT = 8080',
      `STATE_DIR=${path.join(dir, 'state')}`,
      'ALLOWED_EMAILS="  Admin@VR.AE ,second@vr.ae  "',
      'SESSION_TTL_HOURS=24',
      'GOOGLE_CLIENT_SECRET=fixture-abc=def==',
      "LOG_LEVEL='debug'",
      'SESSION_COOKIE_NAME=my_cookie',
      'COORDINATOR_TOKEN_FILE=~/.codex/test-console-token',
      'this line has no equals sign and is ignored',
    ],
    '\r\n', // CRLF file, as produced by Windows editors
  );

  const cfg = loadConfig({ envFile, env: {} });

  assert.equal(cfg.domain, 'vr.ae'); // double quotes stripped, CRLF trimmed
  assert.equal(cfg.consoleHost, 'panel.vr.ae'); // single quotes + export prefix
  assert.equal(cfg.consoleOrigin, 'http://panel.vr.ae:8080');
  assert.equal(cfg.httpPort, 8080); // spaces around '=' tolerated
  assert.equal(cfg.httpsPort, 443); // default
  assert.equal(cfg.devInsecureHttp, true);
  assert.deepEqual(cfg.allowedEmails, new Set(['admin@vr.ae', 'second@vr.ae'])); // lowercased + trimmed
  assert.equal(cfg.sessionTtlMs, 24 * 3_600_000);
  assert.equal(cfg.google.clientSecret, 'fixture-abc=def=='); // '=' inside values preserved
  assert.equal(cfg.google.clientId, ''); // untouched by the garbage line
  assert.equal(cfg.logLevel, 'debug');
  assert.equal(cfg.cookieName, 'my_cookie');
  assert.equal(cfg.coordinatorTokenFile, path.join(os.homedir(), '.codex', 'test-console-token'));
  assert.ok(Buffer.isBuffer(cfg.sessionSecret));
  assert.deepEqual(cfg.sessionSecret, Buffer.from(HEX64, 'hex'));
  assert.equal(cfg.stateDir, path.join(dir, 'state'));
});

test('process.env wins over the .env file', async (t) => {
  const dir = await makeTmp(t);
  const envFile = await writeEnvFile(dir, [
    'DOMAIN=file.example',
    'GOOGLE_CLIENT_ID=from-file',
    'GOOGLE_CLIENT_SECRET=fixture-file-secret',
    'LOG_LEVEL=warn',
  ]);

  const cfg = loadConfig({ envFile, env: minimalEnv(dir, { GOOGLE_CLIENT_ID: 'from-env' }) });

  assert.equal(cfg.domain, 'vr.ae'); // env overrode the file
  assert.equal(cfg.google.clientId, 'from-env'); // env overrode the file
  assert.equal(cfg.google.clientSecret, 'fixture-file-secret'); // file used when env misses
  assert.equal(cfg.logLevel, 'warn'); // file used when env misses
});

test('degraded mode: missing Google OAuth credentials still boots', async (t) => {
  const dir = await makeTmp(t);
  const envFile = await emptyEnvFile(dir);

  const cfg = loadConfig({ envFile, env: minimalEnv(dir) });

  assert.deepEqual(cfg.google, { clientId: '', clientSecret: '' });
  assert.deepEqual(cfg.allowedEmails, new Set());
  assert.equal(cfg.oidcIssuer, 'https://accounts.google.com');
});

test('fatal: missing DOMAIN and bad SESSION_SECRET throw one AggregateError listing ALL problems', async (t) => {
  const dir = await makeTmp(t);
  const envFile = await emptyEnvFile(dir);
  const env = {
    DEV_HTTP: '1',
    HTTP_PORT: '8080',
    STATE_DIR: path.join(dir, 'state'),
    SESSION_SECRET: 'deadbeef', // far too short
  };

  assert.throws(
    () => loadConfig({ envFile, env }),
    (err) => {
      assert.ok(err instanceof AggregateError, `expected AggregateError, got ${err?.constructor?.name}: ${err?.message}`);
      assert.equal(err.errors.length, 2, `expected exactly 2 problems, got: ${err.message}`);
      for (const e of err.errors) assert.ok(e instanceof ConfigError);
      const keys = err.errors.map((e) => e.key).sort();
      assert.deepEqual(keys, ['DOMAIN', 'SESSION_SECRET']);
      // The top-level message itself must list every problem for the operator.
      assert.match(err.message, /DOMAIN/);
      assert.match(err.message, /SESSION_SECRET/);
      return true;
    },
  );
});

test('fatal: SESSION_SECRET must be exactly 64 hex characters', async (t) => {
  const dir = await makeTmp(t);
  const envFile = await emptyEnvFile(dir);

  for (const bad of [HEX64.slice(0, 63), `${HEX64}ab`, 'g'.repeat(64), 'zz'.repeat(32)]) {
    assert.throws(
      () => loadConfig({ envFile, env: minimalEnv(dir, { SESSION_SECRET: bad }) }),
      (err) => {
        assert.ok(err instanceof AggregateError);
        const secretErr = err.errors.find((e) => e.key === 'SESSION_SECRET');
        assert.ok(secretErr, `expected a SESSION_SECRET problem for ${JSON.stringify(bad)}`);
        assert.match(secretErr.message, /64 hex/);
        return true;
      },
    );
  }

  // Missing entirely is fatal too (its own message).
  assert.throws(
    () => loadConfig({ envFile, env: minimalEnv(dir, { SESSION_SECRET: undefined }) }),
    (err) => {
      const secretErr = err.errors.find((e) => e.key === 'SESSION_SECRET');
      assert.ok(secretErr);
      assert.match(secretErr.message, /required/);
      return true;
    },
  );
});

test('HTTP_PORT=0 is valid outside dev mode: plain listener disabled, TLS still required', async (t) => {
  const dir = await makeTmp(t);
  const envFile = await emptyEnvFile(dir);
  const cfg = loadConfig({
    envFile,
    env: {
      DOMAIN: 'vr.ae',
      SESSION_SECRET: HEX64,
      HTTP_PORT: '0',
      TLS_CERT_FILE: 'certs/dev/wildcard.vr.ae.crt', // relative → resolved from appRoot
      TLS_KEY_FILE: 'certs/dev/wildcard.vr.ae.key',
      STATE_DIR: path.join(dir, 'state'),
    },
  });

  assert.equal(cfg.httpPort, 0);
  assert.equal(cfg.httpsPort, 443);
  assert.equal(cfg.devInsecureHttp, false);
  assert.equal(cfg.tlsCertFile, path.join(APP_ROOT, 'certs/dev/wildcard.vr.ae.crt'));
  assert.equal(cfg.tlsKeyFile, path.join(APP_ROOT, 'certs/dev/wildcard.vr.ae.key'));
  assert.equal(cfg.consoleOrigin, 'https://console.vr.ae'); // no :443 suffix
});

test('HTTP_PORT=0 with DEV_HTTP=1 is fatal (it would be the only listener)', async (t) => {
  const dir = await makeTmp(t);
  const envFile = await emptyEnvFile(dir);

  assert.throws(
    () => loadConfig({ envFile, env: minimalEnv(dir, { HTTP_PORT: '0' }) }),
    (err) => {
      assert.ok(err instanceof AggregateError);
      const portErr = err.errors.find((e) => e.key === 'HTTP_PORT');
      assert.ok(portErr);
      assert.match(portErr.message, /DEV_HTTP/);
      return true;
    },
  );
});

test('invalid ports are each reported', async (t) => {
  const dir = await makeTmp(t);
  const envFile = await emptyEnvFile(dir);

  assert.throws(
    () => loadConfig({ envFile, env: minimalEnv(dir, { HTTP_PORT: 'abc', HTTPS_PORT: '70000' }) }),
    (err) => {
      const keys = err.errors.map((e) => e.key);
      assert.ok(keys.includes('HTTP_PORT'));
      assert.ok(keys.includes('HTTPS_PORT'));
      return true;
    },
  );

  // HTTPS_PORT may never be 0 (allowZero is HTTP-only semantics).
  assert.throws(
    () => loadConfig({ envFile, env: minimalEnv(dir, { HTTPS_PORT: '0' }) }),
    (err) => {
      const httpsErr = err.errors.find((e) => e.key === 'HTTPS_PORT');
      assert.ok(httpsErr);
      return true;
    },
  );
});

test('explicitly requested env file that does not exist is fatal', async (t) => {
  const dir = await makeTmp(t);
  assert.throws(
    () => loadConfig({ envFile: path.join(dir, 'missing.env'), env: minimalEnv(dir) }),
    (err) => {
      assert.ok(err instanceof AggregateError);
      assert.match(err.message, /env file not found/);
      return true;
    },
  );
});

test('missing/unreadable TLS files outside dev mode are fatal and both listed', async (t) => {
  const dir = await makeTmp(t);
  const envFile = await emptyEnvFile(dir);
  const base = {
    DOMAIN: 'vr.ae',
    SESSION_SECRET: HEX64,
    STATE_DIR: path.join(dir, 'state'),
  };

  // Not provided at all → both reported in ONE throw.
  assert.throws(
    () => loadConfig({ envFile, env: base }),
    (err) => {
      const keys = err.errors.map((e) => e.key);
      assert.ok(keys.includes('TLS_CERT_FILE'));
      assert.ok(keys.includes('TLS_KEY_FILE'));
      return true;
    },
  );

  // Provided but unreadable → "is not readable".
  assert.throws(
    () =>
      loadConfig({
        envFile,
        env: {
          ...base,
          TLS_CERT_FILE: path.join(dir, 'nope.crt'),
          TLS_KEY_FILE: path.join(dir, 'nope.key'),
        },
      }),
    (err) => {
      assert.equal(err.errors.filter((e) => /is not readable/.test(e.message)).length, 2);
      return true;
    },
  );
});

test('SESSION_TTL_HOURS and SESSION_COOKIE_NAME validation', async (t) => {
  const dir = await makeTmp(t);
  const envFile = await emptyEnvFile(dir);

  const half = loadConfig({ envFile, env: minimalEnv(dir, { SESSION_TTL_HOURS: '0.5' }) });
  assert.equal(half.sessionTtlMs, 1_800_000);

  assert.throws(
    () => loadConfig({ envFile, env: minimalEnv(dir, { SESSION_TTL_HOURS: '-1' }) }),
    (err) => Boolean(err.errors.find((e) => e.key === 'SESSION_TTL_HOURS')),
  );

  assert.throws(
    () => loadConfig({ envFile, env: minimalEnv(dir, { SESSION_COOKIE_NAME: 'bad name;' }) }),
    (err) => Boolean(err.errors.find((e) => e.key === 'SESSION_COOKIE_NAME')),
  );
});
