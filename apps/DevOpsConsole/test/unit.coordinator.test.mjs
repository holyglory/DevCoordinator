import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { CoordError, createCoordinator } from '../src/coordinator.mjs';

const TOKEN = 'fixture-coordinator-token-0123456789abcdef';

async function fixture(t, { tokenOnDisk = TOKEN, expectedToken = TOKEN } = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-coordinator-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const tokenFile = path.join(dir, 'api-token');
  if (tokenOnDisk !== null) {
    await fsp.writeFile(tokenFile, `${tokenOnDisk}\n`, { mode: 0o600 });
    await fsp.chmod(tokenFile, 0o600);
  }
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    requests.push({
      path: req.url,
      authorization: req.headers.authorization ?? null,
      body: Buffer.concat(chunks).toString('utf8'),
    });
    if (req.url === '/healthz') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, service: 'codex-dev-coordinator', version: 2 }));
      return;
    }
    if (req.headers.authorization !== `Bearer ${expectedToken}`) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }
    if (req.url === '/v1/projects/start') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        ok: false,
        partial: false,
        preflight_failed: true,
        classification: 'missing_dependency',
        action_errors: [{ error: 'Docker daemon unavailable' }],
      }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ leases: [], servers: [], project_usage: [] }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;
  const client = createCoordinator({
    config: {
      coordinatorUrl: `http://127.0.0.1:${port}`,
      coordinatorTokenFile: tokenFile,
      coordinatorAutostart: false,
      coordinatorScript: '/unused/dev_coordinator.py',
      coordinatorHome: dir,
      stateDir: dir,
    },
    log: null,
  });
  t.after(() => client.close());
  return { client, requests, tokenFile };
}

test('coordinator probe is anonymous while every protected request uses the private bearer token', async (t) => {
  const { client, requests } = await fixture(t);
  assert.equal(await client.probe(), true);
  await client.inventory({ maxAgeMs: 0 });
  assert.equal(requests[0].path, '/healthz');
  assert.equal(requests[0].authorization, null);
  assert.equal(requests[1].path, '/v1/inventory');
  assert.equal(requests[1].authorization, `Bearer ${TOKEN}`);
});

for (const [label, tokenOnDisk] of [['missing', null], ['wrong', `${TOKEN}-wrong`]]) {
  test(`${label} coordinator credential fails closed without leaking token material`, async (t) => {
    const { client } = await fixture(t, { tokenOnDisk });
    await assert.rejects(
      () => client.inventory({ maxAgeMs: 0 }),
      (err) => {
        assert.ok(err instanceof CoordError);
        assert.equal(err.status, 401);
        assert.match(err.message, /authentication failed/);
        assert.doesNotMatch(err.message, /0123456789abcdef/);
        return true;
      },
    );
    assert.doesNotMatch(String(client.status().lastError), /0123456789abcdef/);
  });
}

for (const mode of [0o644, 0o700]) {
  test(`token-file mode ${mode.toString(8)} is rejected before a protected request is sent`, async (t) => {
    const { client, tokenFile, requests } = await fixture(t);
    fs.chmodSync(tokenFile, mode);
    await assert.rejects(
      () => client.inventory({ maxAgeMs: 0 }),
      (err) => err instanceof CoordError && err.status === 503 && /permissions are unsafe/.test(err.message),
    );
    assert.equal(requests.length, 0);
  });
}

test('symlink token file is rejected before its target can become an Authorization header', async (t) => {
  const { client, tokenFile, requests } = await fixture(t);
  const target = path.join(path.dirname(tokenFile), 'symlink-target-token');
  const targetToken = 'symlink-target-secret-0123456789abcdef';
  fs.writeFileSync(target, `${targetToken}\n`, { mode: 0o600 });
  fs.unlinkSync(tokenFile);
  fs.symlinkSync(target, tokenFile);

  await assert.rejects(
    () => client.inventory({ maxAgeMs: 0 }),
    (err) => {
      assert.ok(err instanceof CoordError);
      assert.equal(err.status, 503);
      assert.match(err.message, /regular non-symlink file/);
      assert.doesNotMatch(err.message, new RegExp(targetToken));
      return true;
    },
  );
  assert.equal(requests.length, 0);
  assert.doesNotMatch(String(client.status().lastError), new RegExp(targetToken));
});

test('non-regular token file is rejected without attempting to read it', async (t) => {
  const { client, tokenFile, requests } = await fixture(t);
  fs.unlinkSync(tokenFile);
  fs.mkdirSync(tokenFile, { mode: 0o700 });

  await assert.rejects(
    () => client.inventory({ maxAgeMs: 0 }),
    (err) => err instanceof CoordError && err.status === 503 && /regular non-symlink file/.test(err.message),
  );
  assert.equal(requests.length, 0);
});

test('oversized token file is rejected before token material is read or sent', async (t) => {
  const { client, tokenFile, requests } = await fixture(t);
  const oversizedSecret = `oversized-secret-${'x'.repeat(4097)}`;
  fs.writeFileSync(tokenFile, oversizedSecret, { mode: 0o600 });

  await assert.rejects(
    () => client.inventory({ maxAgeMs: 0 }),
    (err) => {
      assert.ok(err instanceof CoordError);
      assert.equal(err.status, 503);
      assert.match(err.message, /oversized/);
      assert.doesNotMatch(err.message, /oversized-secret/);
      return true;
    },
  );
  assert.equal(requests.length, 0);
  assert.doesNotMatch(String(client.status().lastError), /oversized-secret/);
});

test('token path replacement at open time fails closed instead of following the replacement', async (t) => {
  const { client, tokenFile, requests } = await fixture(t);
  const replacement = path.join(path.dirname(tokenFile), 'replacement-token');
  const replacementToken = 'replacement-secret-0123456789abcdef';
  fs.writeFileSync(replacement, `${replacementToken}\n`, { mode: 0o600 });

  const originalOpenSync = fs.openSync;
  let replacementInjected = false;
  fs.openSync = function guardedOpenSync(file, flags, ...rest) {
    if (!replacementInjected && path.resolve(String(file)) === path.resolve(tokenFile)) {
      replacementInjected = true;
      fs.unlinkSync(tokenFile);
      fs.symlinkSync(replacement, tokenFile);
    }
    return originalOpenSync.call(this, file, flags, ...rest);
  };
  try {
    await assert.rejects(
      () => client.inventory({ maxAgeMs: 0 }),
      (err) => {
        assert.ok(err instanceof CoordError);
        assert.equal(err.status, 503);
        assert.match(err.message, /regular non-symlink file/);
        assert.doesNotMatch(err.message, new RegExp(replacementToken));
        return true;
      },
    );
  } finally {
    fs.openSync = originalOpenSync;
  }
  assert.equal(replacementInjected, true, 'fixture must replace the path immediately before the credential open');
  assert.equal(requests.length, 0);
  assert.doesNotMatch(String(client.status().lastError), new RegExp(replacementToken));
});

test('HTTP 200 project reports with ok=false remain failures with structured evidence', async (t) => {
  const { client } = await fixture(t);
  await assert.rejects(
    () => client.projectAction('start', { agent: 'console-test', project: '/repo' }),
    (err) => {
      assert.ok(err instanceof CoordError);
      assert.equal(err.status, 409);
      assert.equal(err.body?.preflight_failed, true);
      assert.match(err.message, /failed preflight/);
      assert.match(err.message, /Docker daemon unavailable/);
      return true;
    },
  );
});
