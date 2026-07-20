// Unit tests for the access policy store: configured-owner recovery,
// per-resource grants, durability/privacy, concurrent mutation merging,
// fail-closed recovery, and write-failure rollback.

import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import {
  AccessError,
  CONSOLE_GRANT,
  createAccessStore,
  routeGrant,
} from '../src/access.mjs';

async function fixture({ routes = ['app', 'echo'], admins = ['owner@gmail.com'] } = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-access-'));
  const file = path.join(dir, 'access-control.json');
  const currentRoutes = new Set(routes);
  const routeStore = {
    get: (slug) => currentRoutes.has(slug) ? { slug, instanceId: `instance-${slug}` } : null,
  };
  const store = createAccessStore({ file, adminEmails: admins, routeStore, log: null });
  await store.load();
  return { dir, file, currentRoutes, routeStore, store };
}

describe('access policy store', () => {
  it('keeps configured owners immutable and persists invited users with exact live grants', async () => {
    const { file, routeStore, store } = await fixture();

    assert.equal(store.isAdmin('OWNER@gmail.com'), true);
    assert.equal(store.isKnown('owner@gmail.com'), true);
    assert.equal(store.canAccess('owner@gmail.com', CONSOLE_GRANT), true);
    assert.equal(store.canAccess('owner@gmail.com', routeGrant('anything')), true);

    await store.addUser({ email: ' Viewer@Gmail.com ', grants: [routeGrant('app')] });
    assert.equal(store.isKnown('viewer@gmail.com'), true);
    assert.equal(store.isAdmin('viewer@gmail.com'), false);
    assert.equal(store.canAccess('viewer@gmail.com', routeGrant('app')), true);
    assert.equal(store.canAccess('viewer@gmail.com', routeGrant('echo')), false);
    assert.equal(store.canAccess('viewer@gmail.com', CONSOLE_GRANT), false);

    const onDisk = JSON.parse(await fsp.readFile(file, 'utf8'));
    assert.deepEqual(onDisk.users['viewer@gmail.com'].grants, ['route:app']);
    assert.equal((await fsp.stat(file)).mode & 0o777, 0o600, 'email policy is private on disk');

    const reloaded = createAccessStore({
      file, adminEmails: ['owner@gmail.com'], routeStore, log: null,
    });
    await reloaded.load();
    assert.equal(reloaded.canAccess('viewer@gmail.com', 'route:app'), true);

    await reloaded.setGrant('viewer@gmail.com', CONSOLE_GRANT, true);
    await reloaded.setGrant('viewer@gmail.com', 'route:app', false);
    assert.equal(reloaded.canAccess('viewer@gmail.com', CONSOLE_GRANT), true);
    assert.equal(reloaded.canAccess('viewer@gmail.com', 'route:app'), false);

    await reloaded.removeUser('viewer@gmail.com');
    assert.equal(reloaded.isKnown('viewer@gmail.com'), false, 'existing sessions are revoked by membership lookup');
    await assert.rejects(() => reloaded.removeUser('owner@gmail.com'), /only be changed in ALLOWED_EMAILS/);
  });

  it('rejects unsafe access-policy ownership, permissions, and symlinks before loading identities', async () => {
    const { file, routeStore, store } = await fixture();
    await store.addUser({ email: 'viewer@gmail.com', grants: [routeGrant('app')] });
    const makeReload = () => createAccessStore({
      file,
      adminEmails: ['owner@gmail.com'],
      routeStore,
      log: null,
    });

    await fsp.chmod(file, 0o644);
    await assert.rejects(
      makeReload().load(),
      (error) => error instanceof AccessError
        && error.status === 500
        && /group\/world/.test(error.message),
    );

    await fsp.chmod(file, 0o600);
    const originalGetuid = process.getuid;
    const fileOwner = (await fsp.stat(file)).uid;
    try {
      process.getuid = () => fileOwner + 1;
      await assert.rejects(
        makeReload().load(),
        (error) => error instanceof AccessError
          && error.status === 500
          && /owned by the Console account/.test(error.message),
      );
    } finally {
      process.getuid = originalGetuid;
    }

    const outside = `${file}.outside`;
    await fsp.rename(file, outside);
    await fsp.symlink(outside, file);
    await assert.rejects(
      makeReload().load(),
      (error) => error instanceof AccessError
        && error.status === 500
        && /symlink/.test(error.message),
    );
    assert.equal((await fsp.lstat(file)).isSymbolicLink(), true);
  });

  it('rejects invalid users, duplicates, owners, malformed grants, and nonexistent resources', async () => {
    const { store } = await fixture();
    for (const email of ['', 'not-an-email', 'a@b', 'space person@gmail.com']) {
      await assert.rejects(() => store.addUser({ email }), AccessError);
    }
    await assert.rejects(
      () => store.addUser({ email: 'owner@gmail.com' }),
      (error) => error instanceof AccessError && error.status === 409,
    );
    await assert.rejects(
      () => store.addUser({ email: 'viewer@gmail.com', grants: ['route:missing'] }),
      /does not exist/,
    );
    await assert.rejects(
      () => store.addUser({ email: 'viewer@gmail.com', grants: ['wildcard'] }),
      /unknown access resource/,
    );
    await store.addUser({ email: 'viewer@gmail.com' });
    await assert.rejects(() => store.addUser({ email: 'VIEWER@gmail.com' }), /already invited/);
    await assert.rejects(() => store.setGrant('viewer@gmail.com', 'route:app', 'yes'), /allowed must be true or false/);
  });

  it('serializes concurrent grant deltas so independent changes merge instead of clobbering', async () => {
    const { store } = await fixture();
    await store.addUser({ email: 'viewer@gmail.com' });

    await Promise.all([
      store.setGrant('viewer@gmail.com', CONSOLE_GRANT, true),
      store.setGrant('viewer@gmail.com', routeGrant('app'), true),
      store.setGrant('viewer@gmail.com', routeGrant('echo'), true),
    ]);

    assert.deepEqual(
      store.list().find((user) => user.email === 'viewer@gmail.com').grants,
      ['console', 'route:app', 'route:echo'],
    );
  });

  it('moves grants with a renamed domain and clears deleted resources', async () => {
    const { currentRoutes, store } = await fixture({ routes: ['old'] });
    await store.addUser({ email: 'viewer@gmail.com', grants: ['route:old'] });
    currentRoutes.add('new');

    await store.moveResource('route:old', 'route:new');
    assert.equal(store.canAccess('viewer@gmail.com', 'route:old'), false);
    assert.equal(store.canAccess('viewer@gmail.com', 'route:new'), true);

    await store.clearResource('route:new');
    assert.equal(store.canAccess('viewer@gmail.com', 'route:new'), false);
  });

  it('propagates disk failures and leaves the in-memory authorization unchanged', async () => {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-access-fail-'));
    const blocker = path.join(dir, 'not-a-directory');
    await fsp.writeFile(blocker, 'block');
    const store = createAccessStore({
      file: path.join(blocker, 'access-control.json'),
      adminEmails: ['owner@gmail.com'],
      routeStore: { get: (slug) => slug === 'app' ? { slug } : null },
      log: null,
    });

    await assert.rejects(
      () => store.addUser({ email: 'viewer@gmail.com', grants: ['route:app'] }),
      (error) => error instanceof AccessError && error.status === 500,
    );
    assert.equal(store.isKnown('viewer@gmail.com'), false);
    assert.equal(store.list().length, 1, 'only the configured owner remains after rollback');
  });

  it('backs up corrupt policy and fails closed to configured owners only', async () => {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-access-corrupt-'));
    const file = path.join(dir, 'access-control.json');
    await fsp.writeFile(file, '{not json', { encoding: 'utf8', mode: 0o600 });
    const store = createAccessStore({
      file,
      adminEmails: ['owner@gmail.com'],
      routeStore: { get: () => null },
      log: null,
    });
    await store.load();

    assert.deepEqual(store.list(), [{ email: 'owner@gmail.com', owner: true, grants: [] }]);
    assert.equal(store.isKnown('viewer@gmail.com'), false);
    const names = await fsp.readdir(dir);
    assert.ok(names.some((name) => name.startsWith('access-control.json.corrupt-')));
  });

  it('prunes grants for routes that no longer exist so a later slug reuse cannot restore access', async () => {
    const { file, routeStore } = await fixture();
    await fsp.writeFile(file, `${JSON.stringify({
      version: 1,
      users: { 'viewer@gmail.com': { grants: ['console', 'route:deleted'] } },
    })}\n`, { encoding: 'utf8', mode: 0o600 });
    const store = createAccessStore({
      file, adminEmails: ['owner@gmail.com'], routeStore, log: null,
    });
    await store.load();

    assert.deepEqual(store.list().find((user) => !user.owner).grants, ['console']);
    const onDisk = JSON.parse(await fsp.readFile(file, 'utf8'));
    assert.deepEqual(onDisk.users['viewer@gmail.com'].grants, ['console']);
  });

  it('migrates schema v1 to v2 without changing users or grants', async () => {
    const { file, routeStore } = await fixture();
    await fsp.writeFile(file, `${JSON.stringify({
      version: 1,
      users: { 'viewer@gmail.com': { grants: ['route:app'] } },
    })}\n`, { encoding: 'utf8', mode: 0o600 });
    const store = createAccessStore({ file, adminEmails: ['owner@gmail.com'], routeStore, log: null });
    await store.load();

    assert.equal(store.canAccess('viewer@gmail.com', 'route:app'), true);
    const migrated = JSON.parse(await fsp.readFile(file, 'utf8'));
    assert.equal(migrated.version, 2);
    assert.deepEqual(migrated.requests, {});
    assert.deepEqual(migrated.users['viewer@gmail.com'].grants, ['route:app']);
  });

  it('deduplicates exact requests and atomically approves a new user plus grant', async () => {
    const { file, routeStore, store } = await fixture();
    const descriptor = {
      email: 'requester@gmail.com',
      subject: 'issuer\0google-subject-1',
      resource: 'route:app',
      resourceInstance: store.resourceInstance('route:app'),
      host: 'app.vr.ae',
      title: 'App',
      target: 'web · /repo/app',
    };

    const first = await store.requestAccess(descriptor);
    const duplicate = await store.requestAccess(descriptor);
    assert.equal(duplicate.id, first.id);
    assert.equal(duplicate.duplicate, true);
    assert.equal(store.pendingRequestCount(), 1);
    assert.equal(store.listRequests()[0].subjectHash, undefined, 'private subject hash is never exposed');

    const approved = await store.decideRequest(first.id, 'approve', 'owner@gmail.com');
    assert.equal(approved.status, 'approved');
    assert.equal(store.canAccess('requester@gmail.com', 'route:app'), true);
    assert.equal(store.pendingRequestCount(), 0);
    assert.equal((await store.decideRequest(first.id, 'approve', 'owner@gmail.com')).status, 'approved');
    await assert.rejects(
      () => store.decideRequest(first.id, 'deny', 'owner@gmail.com'),
      (error) => error instanceof AccessError && error.status === 409,
    );

    const persisted = JSON.parse(await fsp.readFile(file, 'utf8'));
    assert.deepEqual(persisted.users['requester@gmail.com'].grants, ['route:app']);
    assert.equal(persisted.requests[first.id].status, 'approved');

    const reloaded = createAccessStore({
      file, adminEmails: ['owner@gmail.com'], routeStore, log: null,
    });
    await reloaded.load();
    assert.equal(reloaded.canAccess('requester@gmail.com', 'route:app'), true);
    assert.equal(reloaded.listRequests({ status: 'approved' })[0].id, first.id);
  });

  it('denies without granting, applies a retry cooldown, and stales pending requests on resource removal', async () => {
    let clock = Date.parse('2026-07-18T00:00:00.000Z');
    const { file, routeStore } = await fixture();
    const store = createAccessStore({
      file, adminEmails: ['owner@gmail.com'], routeStore, log: null, now: () => clock,
    });
    await store.load();
    const base = {
      email: 'requester@gmail.com',
      subject: 'issuer\0google-subject-2',
      resource: 'route:app',
      resourceInstance: store.resourceInstance('route:app'),
      host: 'app.vr.ae',
      title: 'App',
      target: 'web · /repo/app',
    };
    const denied = await store.requestAccess(base);
    await store.decideRequest(denied.id, 'deny', 'owner@gmail.com');
    assert.equal(store.canAccess(base.email, base.resource), false);
    await assert.rejects(
      () => store.requestAccess(base),
      (error) => error instanceof AccessError && error.status === 429 && error.retryAfter > 0,
    );

    clock += 24 * 60 * 60 * 1000 + 1;
    const pending = await store.requestAccess(base);
    await store.clearResource('route:app');
    assert.equal(store.listRequests({ status: 'stale' }).some((row) => row.id === pending.id), true);
    await assert.rejects(
      () => store.decideRequest(pending.id, 'approve', 'owner@gmail.com'),
      (error) => error instanceof AccessError && error.status === 409,
    );
  });

  it('rolls back both request and grant when request persistence fails', async () => {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-request-fail-'));
    const blocker = path.join(dir, 'not-a-directory');
    await fsp.writeFile(blocker, 'block');
    const store = createAccessStore({
      file: path.join(blocker, 'access-control.json'),
      adminEmails: ['owner@gmail.com'],
      routeStore: { get: (slug) => slug === 'app' ? { slug, instanceId: 'instance-app' } : null },
      log: null,
    });
    await assert.rejects(() => store.requestAccess({
      email: 'requester@gmail.com',
      subject: 'issuer\0google-subject-3',
      resource: 'route:app',
      resourceInstance: 'instance-app',
      host: 'app.vr.ae',
      title: 'App',
      target: 'web · /repo/app',
    }), (error) => error instanceof AccessError && error.status === 500);
    assert.equal(store.pendingRequestCount(), 0);
    assert.equal(store.isKnown('requester@gmail.com'), false);
  });
});
