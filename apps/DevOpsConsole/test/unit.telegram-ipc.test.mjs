import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  createTelegramIpcClient,
  createTelegramIpcServer,
  TELEGRAM_IPC_MAX_FRAME_BYTES,
} from '../src/telegram-ipc.mjs';
import { TelegramServiceError } from '../src/telegram.mjs';
import {
  loadNotificationConfig,
  runNotificationWorker,
} from '../bin/devops-console-notifications.mjs';

async function fixture(t, service) {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-notification-ipc-'));
  await fsp.chmod(directory, 0o700);
  const socketPath = path.join(directory, 'notifications.sock');
  const server = createTelegramIpcServer({ socketPath, service });
  await server.start();
  assert.equal((await fsp.stat(socketPath)).mode & 0o777, 0o666);
  t.after(async () => {
    await server.close();
    await fsp.rm(directory, { recursive: true, force: true });
  });
  return {
    socketPath,
    client: createTelegramIpcClient({ socketPath, timeoutMs: 1_000 }),
  };
}

test('notification IPC admits only fixed operations and preserves exact arguments', async (t) => {
  const calls = [];
  const service = {
    status: async () => ({ bots: 1 }),
    listBots: async (args) => { calls.push(args); return [{ id: 'bot-1' }]; },
    registerBot: async (args) => args,
    removeBot: async () => true,
    setProjects: async () => true,
    listAuthorizationQueue: async () => [],
    decideAuthorization: async () => true,
  };
  const { client } = await fixture(t, service);

  assert.deepEqual(await client.status(), { bots: 1 });
  assert.deepEqual(await client.listBots({ email: 'owner@example.test' }), [{ id: 'bot-1' }]);
  assert.deepEqual(calls, [{ email: 'owner@example.test' }]);
  await assert.rejects(
    () => client.listBots({ email: 'owner@example.test', injected: true }),
    (error) => error instanceof TelegramServiceError
      && error.status === 500
      && error.code === 'notification_ipc_error',
  );
  assert.equal(client.ownsBackgroundLoops, false);
  assert.equal(TELEGRAM_IPC_MAX_FRAME_BYTES, 256 * 1024);
});

test('notification IPC retains browser-safe typed Telegram failures', async (t) => {
  const service = Object.fromEntries(
    ['status', 'registerBot', 'removeBot', 'setProjects', 'listAuthorizationQueue', 'decideAuthorization']
      .map((name) => [name, async () => ({ name })]),
  );
  service.listBots = async () => {
    throw new TelegramServiceError(429, 'telegram_rate_limited', 'Telegram rate limited this bot', {
      retryAfter: 17,
    });
  };
  const { client } = await fixture(t, service);
  await assert.rejects(
    () => client.listBots({ email: 'owner@example.test' }),
    (error) => error instanceof TelegramServiceError
      && error.status === 429
      && error.code === 'telegram_rate_limited'
      && error.retryAfter === 17,
  );
});

test('an absent notification worker fails closed as typed local unavailability', async (t) => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-notification-absent-'));
  await fsp.chmod(directory, 0o700);
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const absent = createTelegramIpcClient({
    socketPath: path.join(directory, 'absent.sock'),
    timeoutMs: 100,
  });
  await assert.rejects(
    () => absent.listBots({ email: 'owner@example.test' }),
    (error) => error instanceof TelegramServiceError
      && error.status === 503
      && error.code === 'notification_unavailable',
  );
});

test('notification worker topology is background-owned and Console is never coupled by Requires', async () => {
  const root = path.resolve(import.meta.dirname, '..', '..', '..');
  const [consoleUnit, notificationUnit, consoleSource] = await Promise.all([
    fsp.readFile(path.join(root, 'deploy/devcoordinator-console@.service'), 'utf8'),
    fsp.readFile(path.join(root, 'deploy/devcoordinator-notifications.service'), 'utf8'),
    fsp.readFile(path.join(root, 'apps/DevOpsConsole/bin/devops-console.mjs'), 'utf8'),
  ]);
  assert.match(notificationUnit, /^Slice=devcoordinator-background\.slice$/m);
  assert.match(notificationUnit, /^User=devcoordinator-notifications$/m);
  assert.match(notificationUnit, /^ConditionPathExists=\/var\/lib\/devcoordinator-notifications\/telegram-control\.json$/m);
  assert.match(notificationUnit, /^KillMode=control-group$/m);
  assert.match(notificationUnit, /^Restart=always$/m);
  assert.match(notificationUnit, /^EnvironmentFile=\/etc\/devcoordinator\/notifications\.env$/m);
  assert.doesNotMatch(notificationUnit, /console\.env|session-secret|tls-key|tls-cert/);
  assert.match(
    consoleUnit,
    /^Wants=.*(?:^|\s)devcoordinator-notifications\.service(?:\s|$)/m,
  );
  assert.doesNotMatch(consoleUnit, /^Requires=.*devcoordinator-notifications\.service$/m);
  assert.match(consoleUnit, /^Environment=DEVCOORDINATOR_NOTIFICATION_SOCKET=/m);
  assert.match(consoleSource, /if \(notificationSocket\) \{[\s\S]*createTelegramIpcClient/);
});

test('notification worker check validates private inputs without starting polling or creating state', async (t) => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-notification-check-'));
  await fsp.chmod(directory, 0o700);
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const stateFile = path.join(directory, 'telegram-control.json');
  const env = {
    COORDINATOR_URL: 'http://127.0.0.1:29876',
    DEVCOORDINATOR_NOTIFICATION_PROJECT: '/srv/devcoordinator',
    DEVCOORDINATOR_NOTIFICATION_STATE: stateFile,
    DEVCOORDINATOR_NOTIFICATION_SOCKET: path.join(directory, 'notifications.sock'),
    DEVCOORDINATOR_NOTIFICATION_ADMIN_EMAILS: 'Owner@Example.test',
    LOG_LEVEL: 'error',
  };
  const config = loadNotificationConfig(env);
  assert.deepEqual([...config.allowedEmails], ['owner@example.test']);
  assert.deepEqual(
    await runNotificationWorker({ env, argv: ['--check'] }),
    { checked: true, running: false },
  );
  await assert.rejects(fsp.lstat(stateFile), (error) => error?.code === 'ENOENT');
  assert.throws(
    () => loadNotificationConfig({ ...env, DEVCOORDINATOR_NOTIFICATION_SOCKET: 'relative.sock' }),
    /must be an absolute path/,
  );
  assert.throws(
    () => loadNotificationConfig({ ...env, DEVCOORDINATOR_NOTIFICATION_ADMIN_EMAILS: '' }),
    /must contain an administrator/,
  );
  assert.throws(
    () => loadNotificationConfig({ ...env, LOG_LEVEL: 'verbose' }),
    /must be one of debug\|info\|warn\|error/,
  );
});
