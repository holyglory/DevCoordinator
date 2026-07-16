import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createUpstreamAuthStore, UpstreamAuthError } from '../src/upstream-auth.mjs';

const CLI = fileURLToPath(new URL('../bin/devops-console-upstream-auth.mjs', import.meta.url));

function runCli(args, input = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { PATH: process.env.PATH ?? '' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code, signal) => resolve({
      code,
      signal,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8'),
    }));
    child.stdin.end(input);
  });
}

async function makeStore(t) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-upstream-auth-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'upstream-auth.json');
  const store = createUpstreamAuthStore({ file });
  await store.load();
  return { dir, file, store };
}

test('bearer and basic credentials persist privately while descriptions stay redacted', async (t) => {
  const { file, store } = await makeStore(t);
  const bearerSecret = 'fixture-bearer-token';
  const basicSecret = 'fixture-basic-password';

  assert.deepEqual(await store.set('prtzn', { scheme: 'bearer', secret: bearerSecret }), {
    configured: true,
    scheme: 'bearer',
  });
  assert.deepEqual(await store.set('legacy', {
    scheme: 'basic', username: 'operator', secret: basicSecret,
  }), {
    configured: true,
    scheme: 'basic',
  });
  assert.deepEqual(store.describe('prtzn'), { configured: true, scheme: 'bearer' });
  assert.deepEqual(store.describe('missing'), { configured: false });
  assert.equal(store.authorizationFor('prtzn'), `Bearer ${bearerSecret}`);
  assert.equal(
    store.authorizationFor('legacy'),
    `Basic ${Buffer.from(`operator:${basicSecret}`, 'utf8').toString('base64')}`,
  );

  const mode = (await fsp.stat(file)).mode & 0o777;
  assert.equal(mode, 0o600);

  const reloaded = createUpstreamAuthStore({ file });
  await reloaded.load();
  assert.deepEqual(reloaded.describe('prtzn'), { configured: true, scheme: 'bearer' });
  assert.equal(reloaded.authorizationFor('prtzn'), `Bearer ${bearerSecret}`);

  const descriptionText = JSON.stringify(reloaded.describe('prtzn'));
  assert.doesNotMatch(descriptionText, new RegExp(bearerSecret));
});

test('move and remove keep route credential lifecycle aligned with route renames and deletion', async (t) => {
  const { store } = await makeStore(t);
  await store.set('old-name', { scheme: 'bearer', secret: 'fixture-move-token' });

  assert.deepEqual(await store.move('old-name', 'new-name'), {
    configured: true,
    scheme: 'bearer',
  });
  assert.equal(store.authorizationFor('old-name'), null);
  assert.equal(store.authorizationFor('new-name'), 'Bearer fixture-move-token');

  assert.equal(await store.remove('new-name'), true);
  assert.equal(await store.remove('new-name'), false);
  assert.deepEqual(store.describe('new-name'), { configured: false });
});

test('concurrent mutations serialize without losing unrelated route credentials', async (t) => {
  const { file, store } = await makeStore(t);
  await Promise.all([
    store.set('first', { scheme: 'bearer', secret: 'fixture-first-token' }),
    store.set('second', { scheme: 'bearer', secret: 'fixture-second-token' }),
    store.remove('first'),
  ]);

  assert.equal(store.authorizationFor('first'), null);
  assert.equal(store.authorizationFor('second'), 'Bearer fixture-second-token');
  const persisted = JSON.parse(await fsp.readFile(file, 'utf8'));
  assert.deepEqual(Object.keys(persisted.routes), ['second']);
});

test('persistence failure leaves the live authorization map unchanged', async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-upstream-auth-failure-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const stateDir = path.join(dir, 'state');
  const file = path.join(stateDir, 'upstream-auth.json');
  const store = createUpstreamAuthStore({ file });
  await store.load();

  await fsp.writeFile(stateDir, 'not a directory', 'utf8');
  await assert.rejects(
    store.set('app', { scheme: 'bearer', secret: 'fixture-never-committed-token' }),
    /EEXIST|ENOTDIR/,
  );
  assert.deepEqual(store.describe('app'), { configured: false });
  assert.equal(store.authorizationFor('app'), null);
});

test('invalid credentials fail before persistence', async (t) => {
  const { file, store } = await makeStore(t);
  const invalid = [
    ['bad slug', { scheme: 'bearer', secret: 'abc' }],
    ['app', { scheme: 'bearer', secret: 'contains whitespace' }],
    ['app', { scheme: 'basic', username: 'bad:name', secret: 'abc' }],
    ['app', { scheme: 'basic', username: 'operator', secret: 'line\nbreak' }],
    ['app', { scheme: 'digest', secret: 'abc' }],
  ];
  for (const [slug, definition] of invalid) {
    await assert.rejects(store.set(slug, definition), UpstreamAuthError);
  }
  await assert.rejects(fsp.stat(file), { code: 'ENOENT' });
});

test('permissive credential files fail closed and are not read', async (t) => {
  const { file } = await makeStore(t);
  const secret = 'fixture-permission-token';
  await fsp.writeFile(file, JSON.stringify({
    version: 1,
    routes: { app: { scheme: 'bearer', secret } },
  }), { encoding: 'utf8', mode: 0o644 });
  await fsp.chmod(file, 0o644);

  const store = createUpstreamAuthStore({ file });
  await assert.rejects(store.load(), /must not be group\/world accessible/);
});

test('credential state symlinks are rejected instead of followed', async (t) => {
  const { dir, file } = await makeStore(t);
  const outside = path.join(dir, 'outside.json');
  await fsp.writeFile(outside, JSON.stringify({
    version: 1,
    routes: { app: { scheme: 'bearer', secret: 'fixture-outside-token' } },
  }), { encoding: 'utf8', mode: 0o600 });
  await fsp.symlink(outside, file);

  const store = createUpstreamAuthStore({ file });
  await assert.rejects(store.load(), /must be a regular file/);
});

test('malformed state is preserved and disabled instead of partially trusted', async (t) => {
  const { dir, file } = await makeStore(t);
  await fsp.writeFile(file, '{not-json', { encoding: 'utf8', mode: 0o600 });

  const store = createUpstreamAuthStore({ file });
  await store.load();
  assert.deepEqual(store.describe('app'), { configured: false });
  const names = await fsp.readdir(dir);
  assert.ok(names.some((name) => name.startsWith('upstream-auth.json.corrupt-')));
});

test('operator CLI accepts secrets only on stdin and emits redacted set/list/remove results', async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-upstream-auth-cli-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const stateDir = path.join(dir, 'state');
  const envFile = path.join(dir, 'console.env');
  await fsp.writeFile(envFile, [
    'DOMAIN=vr.ae',
    `SESSION_SECRET=${'ab'.repeat(32)}`,
    'DEV_HTTP=1',
    'HTTP_PORT=8080',
    `STATE_DIR=${stateDir}`,
  ].join('\n') + '\n', 'utf8');

  const secret = 'fixture-cli-upstream-token';
  const setResult = await runCli([
    '--env-file', envFile, 'set', 'prtzn', '--scheme', 'bearer', '--secret-stdin',
  ], `${secret}\n`);
  assert.equal(setResult.code, 0, setResult.stderr);
  assert.deepEqual(JSON.parse(setResult.stdout), {
    slug: 'prtzn', configured: true, scheme: 'bearer',
  });
  assert.doesNotMatch(setResult.stdout + setResult.stderr, new RegExp(secret));

  const listResult = await runCli(['--env-file', envFile, 'list']);
  assert.equal(listResult.code, 0, listResult.stderr);
  assert.deepEqual(JSON.parse(listResult.stdout), {
    routes: [{ slug: 'prtzn', configured: true, scheme: 'bearer' }],
  });
  assert.doesNotMatch(listResult.stdout + listResult.stderr, new RegExp(secret));

  const stateFile = path.join(stateDir, 'upstream-auth.json');
  assert.equal((await fsp.stat(stateFile)).mode & 0o777, 0o600);

  const removeResult = await runCli(['--env-file', envFile, 'remove', 'prtzn']);
  assert.equal(removeResult.code, 0, removeResult.stderr);
  assert.deepEqual(JSON.parse(removeResult.stdout), { slug: 'prtzn', removed: true });
});
