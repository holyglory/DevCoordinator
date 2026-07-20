import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createTelegramService, TelegramServiceError } from '../src/telegram.mjs';

const OWNER = 'owner@example.com';
const ADMIN = 'admin@example.com';
const OUTSIDER = 'outside@example.com';
const TOKEN_A = `123456:${'A'.repeat(36)}`;
const TOKEN_B = `234567:${'B'.repeat(36)}`;
const BOT_A = '123456';
const BOT_B = '234567';

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

class FakeTelegram {
  constructor() {
    this.calls = [];
    this.webhooks = new Map();
    this.updateQueues = new Map();
    this.sendHandler = null;
    this.pollHandler = null;
  }

  identity(token) {
    if (token === TOKEN_A) return { id: Number(BOT_A), is_bot: true, username: 'console_bot_a', first_name: 'Console A' };
    if (token === TOKEN_B) return { id: Number(BOT_B), is_bot: true, username: 'console_bot_b', first_name: 'Console B' };
    return null;
  }

  fetch = async (url, options) => {
    const match = String(url).match(/^https:\/\/api\.telegram\.org\/bot([^/]+)\/([^/]+)$/);
    assert.ok(match, `unexpected Telegram URL ${url}`);
    const [, token, method] = match;
    const body = JSON.parse(options.body);
    this.calls.push({ token, method, body, signal: options.signal });
    if (method === 'getMe') {
      const identity = this.identity(token);
      return identity
        ? jsonResponse({ ok: true, result: identity })
        : jsonResponse({ ok: false, error_code: 401, description: 'Unauthorized' }, 401);
    }
    if (method === 'getWebhookInfo') {
      return jsonResponse({ ok: true, result: { url: this.webhooks.get(token) ?? '' } });
    }
    if (method === 'deleteWebhook') {
      this.webhooks.set(token, '');
      return jsonResponse({ ok: true, result: true });
    }
    if (method === 'getUpdates') {
      if (this.pollHandler) return this.pollHandler({ token, method, body, signal: options.signal });
      const queue = this.updateQueues.get(token) ?? [];
      return jsonResponse({ ok: true, result: queue });
    }
    if (method === 'sendMessage') {
      if (this.sendHandler) return this.sendHandler({ token, method, body, signal: options.signal });
      return jsonResponse({ ok: true, result: { message_id: this.calls.length } });
    }
    throw new Error(`unexpected Telegram method ${method}`);
  };
}

function privateStart(updateId, { userId = 7001, chatId = userId, username = 'telegram_user' } = {}) {
  return {
    update_id: updateId,
    message: {
      message_id: updateId,
      text: '/start',
      from: {
        id: userId,
        is_bot: false,
        username,
        first_name: 'Telegram',
        last_name: 'User',
        language_code: 'en',
      },
      chat: { id: chatId, type: 'private' },
    },
  };
}

async function fixture(t, overrides = {}) {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-telegram-'));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'telegram.json');
  const telegram = overrides.telegram ?? new FakeTelegram();
  const clock = overrides.clock ?? { value: Date.parse('2026-07-18T12:00:00Z') };
  const projects = overrides.projects ?? new Set(['repo-alpha', 'repo-beta']);
  const feed = overrides.feed ?? { events: [] };
  const cursorFor = (event) => `cursor:${event.event_id}`;
  const coordinator = overrides.coordinator ?? {
    hasProject: async (repoId) => projects.has(repoId),
    readEvents: async ({ after, limit }) => {
      const start = after === null
        ? 0
        : Math.max(0, feed.events.findIndex((event) => cursorFor(event) === after) + 1);
      const events = feed.events.slice(start, start + limit);
      return {
        schema_version: 1,
        events,
        next_cursor: events.length ? cursorFor(events.at(-1)) : after,
        has_more: start + events.length < feed.events.length,
      };
    },
  };
  const logs = [];
  const log = {
    child: () => log,
    warn: (message, fields) => logs.push({ level: 'warn', message, fields }),
    error: (message, fields) => logs.push({ level: 'error', message, fields }),
  };
  const service = createTelegramService({
    file,
    fetchImpl: telegram.fetch,
    coordinator,
    isAdmin: async (email) => email === ADMIN,
    now: () => clock.value,
    log,
    pollTimeoutSeconds: overrides.pollTimeoutSeconds ?? 0,
    pollRefreshMs: overrides.pollRefreshMs ?? 50,
    dispatcherIntervalMs: overrides.dispatcherIntervalMs ?? 50,
    observationIntervalMs: overrides.observationIntervalMs ?? 5_000,
    requestTimeoutMs: 2_000,
  });
  await service.load();
  return { directory, file, telegram, clock, projects, feed, coordinator, logs, service };
}

async function registerA(service, options = {}) {
  return service.registerBot({ email: OWNER, token: TOKEN_A, ...options });
}

async function waitUntil(predicate, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail('condition was not reached before timeout');
}

test('bot tokens persist only in an atomic private state file and every public view is redacted', async (t) => {
  const { file, service } = await fixture(t);
  const registered = await registerA(service, { label: 'Operations alerts' });

  assert.equal(registered.id, BOT_A);
  assert.equal(registered.ownerEmail, OWNER);
  assert.equal(registered.label, 'Operations alerts');
  assert.equal(registered.hasToken, true);
  assert.doesNotMatch(JSON.stringify(registered), new RegExp(TOKEN_A));
  assert.doesNotMatch(JSON.stringify(await service.listBots({ email: OWNER })), new RegExp(TOKEN_A));
  assert.doesNotMatch(JSON.stringify(await service.status({ email: OWNER })), new RegExp(TOKEN_A));

  const stat = await fsp.lstat(file);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.mode & 0o777, 0o600);
  const privateState = await fsp.readFile(file, 'utf8');
  assert.match(privateState, new RegExp(TOKEN_A));
  const files = await fsp.readdir(path.dirname(file));
  assert.deepEqual(files, ['telegram.json']);

  const reloaded = createTelegramService({
    file,
    fetchImpl: () => assert.fail('reload should not contact Telegram'),
    isAdmin: () => false,
  });
  await reloaded.load();
  assert.equal((await reloaded.listBots({ email: OWNER }))[0].username, 'console_bot_a');
  assert.doesNotMatch(JSON.stringify(await reloaded.status({ email: OWNER })), new RegExp(TOKEN_A));
});

test('state loading rejects permissive files and symlinks before reading bot secrets', async (t) => {
  const { file, service } = await fixture(t);
  await registerA(service);
  const makeReload = () => createTelegramService({
    file,
    fetchImpl: () => assert.fail('unsafe state must fail before Telegram access'),
    isAdmin: () => false,
  });

  await fsp.chmod(file, 0o644);
  await assert.rejects(
    makeReload().load(),
    (error) => error.code === 'unsafe_state_file' && /group\/world/.test(error.message),
  );

  await fsp.chmod(file, 0o600);
  const outside = `${file}.outside`;
  await fsp.rename(file, outside);
  await fsp.symlink(outside, file);
  await assert.rejects(
    makeReload().load(),
    (error) => error.code === 'unsafe_state_file' && /symlink/.test(error.message),
  );
});

test('registration refuses active webhooks unless explicit takeover preserves pending updates', async (t) => {
  const telegram = new FakeTelegram();
  telegram.webhooks.set(TOKEN_A, 'https://elsewhere.example/hook');
  const { service } = await fixture(t, { telegram });

  await assert.rejects(
    registerA(service),
    (error) => error instanceof TelegramServiceError
      && error.status === 409
      && error.code === 'telegram_webhook_active',
  );
  assert.deepEqual(await service.listBots({ email: OWNER }), []);

  const registered = await registerA(service, { takeoverWebhook: true });
  assert.equal(registered.id, BOT_A);
  const deletion = telegram.calls.find((call) => call.method === 'deleteWebhook');
  assert.deepEqual(deletion.body, { drop_pending_updates: false });
  const methods = telegram.calls.map((call) => call.method);
  assert.deepEqual(methods.slice(-4), ['getMe', 'getWebhookInfo', 'deleteWebhook', 'getWebhookInfo']);
});

test('bot ownership is per Console email, admins may override, and assignments use exact repo_id', async (t) => {
  const { service } = await fixture(t);
  await registerA(service);

  assert.deepEqual(await service.listBots({ email: OUTSIDER }), []);
  await assert.rejects(
    service.assignProject({ email: OUTSIDER, botId: BOT_A, repoId: 'repo-alpha' }),
    (error) => error.status === 403 && error.code === 'bot_forbidden',
  );
  await assert.rejects(
    service.assignProject({ email: ADMIN, botId: BOT_A, repoId: 'Repo-Alpha' }),
    (error) => error.status === 404 && error.code === 'project_not_found',
  );
  const assigned = await service.assignProject({
    email: ADMIN,
    botId: BOT_A,
    repoId: 'repo-alpha',
  });
  assert.deepEqual(assigned.projects, ['repo-alpha']);
  const completeSet = await service.setProjects({
    email: ADMIN,
    botId: BOT_A,
    repoIds: ['repo-beta', 'repo-alpha'],
  });
  assert.deepEqual(completeSet.projects, ['repo-alpha', 'repo-beta']);
  await assert.rejects(
    service.setProjects({ email: ADMIN, botId: BOT_A, repoIds: ['repo-missing'] }),
    (error) => error.status === 404 && error.code === 'project_not_found',
  );
  assert.deepEqual((await service.listBots({ email: OWNER }))[0].projects, ['repo-alpha', 'repo-beta']);
  assert.equal((await service.listBots({ email: ADMIN }))[0].ownerEmail, OWNER);
});

test('long polling advances offset atomically and queues one private /start identity despite replay', async (t) => {
  const telegram = new FakeTelegram();
  telegram.updateQueues.set(TOKEN_A, [
    privateStart(100),
    { ...privateStart(101), message: { ...privateStart(101).message, chat: { id: -99, type: 'group' } } },
  ]);
  const { service } = await fixture(t, { telegram });
  await registerA(service);

  assert.deepEqual(await service.processBotUpdates(BOT_A), {
    updates: 2,
    requests: 1,
    nextUpdateId: 102,
  });
  const requests = await service.listAuthorizationQueue({ email: OWNER });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].telegramUserId, '7001');
  assert.equal(requests[0].status, 'pending');

  assert.deepEqual(await service.processBotUpdates(BOT_A), {
    updates: 0,
    requests: 0,
    nextUpdateId: 102,
  });
  assert.equal((await service.listAuthorizationQueue({ email: OWNER })).length, 1);
  const polls = telegram.calls.filter((call) => call.method === 'getUpdates');
  assert.deepEqual(polls.map((call) => call.body.offset), [0, 102]);
});

test('approval starts after the opaque backlog cursor and exact-project fanout is durable across pages', async (t) => {
  const telegram = new FakeTelegram();
  telegram.updateQueues.set(TOKEN_A, [privateStart(1)]);
  const feed = {
    events: [
      {
        event_id: 'old-event',
        repo_id: 'repo-alpha',
        event_kind: 'server_started',
        message: 'Already happened',
        occurred_at: '2026-07-18T11:00:00Z',
      },
    ],
  };
  const first = await fixture(t, { telegram, feed });
  await registerA(first.service);
  await first.service.assignProject({ email: OWNER, botId: BOT_A, repoId: 'repo-alpha' });
  await first.service.processBotUpdates(BOT_A);
  const [pending] = await first.service.listAuthorizationQueue({ email: OWNER });
  const approved = await first.service.decideAuthorization({
    email: OWNER,
    requestId: pending.id,
    decision: 'approve',
  });
  assert.equal(approved.status, 'approved');

  feed.events.push(
    {
      event_id: 'server-crash-11',
      repo_id: 'repo-alpha',
      event_kind: 'server_crashed',
      resource_name: 'api',
      message: 'Process exited unexpectedly',
      occurred_at: '2026-07-18T12:01:00Z',
    },
    {
      event_id: 'other-project-12',
      repo_id: 'repo-beta',
      event_kind: 'docker_stopped',
      message: 'Container stopped',
      occurred_at: '2026-07-18T12:02:00Z',
    },
  );
  assert.deepEqual(await first.service.ingestEvents({ limit: 1 }), {
    events: 1,
    deliveries: 1,
    cursor: 'cursor:server-crash-11',
    hasMore: true,
  });
  assert.deepEqual(await first.service.ingestEvents({ limit: 1 }), {
    events: 1,
    deliveries: 0,
    cursor: 'cursor:other-project-12',
    hasMore: false,
  });
  const persisted = JSON.parse(await fsp.readFile(first.file, 'utf8'));
  const eventDeliveries = Object.values(persisted.outbox).filter((item) => item.kind === 'event');
  assert.equal(eventDeliveries.length, 1);
  assert.equal(eventDeliveries[0].event.event_id, 'server-crash-11');
  assert.equal(eventDeliveries[0].repoId, 'repo-alpha');
  assert.equal(persisted.authorizationRequests[pending.id].approvalCursor, 'cursor:old-event');

  // A separate service instance proves the unsent outbox and cursor survive a
  // process restart. Advance the clock between sends to honor per-chat pacing.
  const reloaded = createTelegramService({
    file: first.file,
    fetchImpl: telegram.fetch,
    coordinator: first.coordinator,
    isAdmin: (email) => email === ADMIN,
    now: () => first.clock.value,
    pollTimeoutSeconds: 0,
  });
  await reloaded.load();
  for (let pass = 0; pass < 4; pass += 1) {
    await reloaded.deliverDue({ limit: 10 });
    first.clock.value += 1_000;
  }
  const sends = telegram.calls.filter((call) => call.method === 'sendMessage');
  assert.ok(sends.some((call) => call.body.text.includes('server-crash-11')));
  assert.ok(sends.every((call) => !call.body.text.includes('old-event')));
  assert.ok(sends.every((call) => !call.body.text.includes('other-project-12')));
  assert.equal((await reloaded.status({ email: OWNER })).eventCursor, 'cursor:other-project-12');
});

test('assigned projects that vanish from coordinator inventory receive no new event deliveries', async (t) => {
  const telegram = new FakeTelegram();
  telegram.updateQueues.set(TOKEN_A, [privateStart(4)]);
  const feed = { events: [] };
  const { service, projects, file } = await fixture(t, { telegram, feed });
  await registerA(service);
  await service.assignProject({ email: OWNER, botId: BOT_A, repoId: 'repo-alpha' });
  await service.processBotUpdates(BOT_A);
  const [request] = await service.listAuthorizationQueue({ email: OWNER });
  await service.decideAuthorization({ email: OWNER, requestId: request.id, decision: 'approve' });

  projects.delete('repo-alpha');
  feed.events.push({
    event_id: 'event-after-project-vanished',
    repo_id: 'repo-alpha',
    event_kind: 'server_started',
    message: 'This archived project must not fan out',
  });
  assert.deepEqual(await service.ingestEvents(), {
    events: 1,
    deliveries: 0,
    cursor: 'cursor:event-after-project-vanished',
    hasMore: false,
  });

  const persisted = JSON.parse(await fsp.readFile(file, 'utf8'));
  const eventDeliveries = Object.values(persisted.outbox)
    .filter((delivery) => delivery.kind === 'event');
  assert.deepEqual(eventDeliveries, []);
});

test('denial and revocation cancel event deliveries before they can be sent', async (t) => {
  const telegram = new FakeTelegram();
  telegram.updateQueues.set(TOKEN_A, [privateStart(5)]);
  const feed = { events: [] };
  const { service, clock } = await fixture(t, { telegram, feed });
  await registerA(service);
  await service.assignProject({ email: OWNER, botId: BOT_A, repoId: 'repo-alpha' });
  await service.processBotUpdates(BOT_A);
  let [request] = await service.listAuthorizationQueue({ email: OWNER });
  await service.decideAuthorization({ email: OWNER, requestId: request.id, decision: 'deny' });
  assert.equal((await service.listAuthorizationQueue({ email: OWNER, status: 'denied' }))[0].status, 'denied');

  telegram.updateQueues.set(TOKEN_A, [privateStart(6)]);
  await service.processBotUpdates(BOT_A);
  [request] = await service.listAuthorizationQueue({ email: OWNER });
  await service.decideAuthorization({ email: OWNER, requestId: request.id, decision: 'approve' });
  feed.events = [{
    event_id: 'pending-before-revoke',
    repo_id: 'repo-alpha',
    event_kind: 'docker_failed',
    message: 'Container failed',
  }];
  assert.equal((await service.ingestEvents()).deliveries, 1);
  await service.revokeAuthorization({ email: OWNER, requestId: request.id });
  for (let pass = 0; pass < 5; pass += 1) {
    await service.deliverDue({ limit: 20 });
    clock.value += 1_000;
  }
  const sends = telegram.calls.filter((call) => call.method === 'sendMessage');
  assert.ok(sends.every((call) => !call.body.text.includes('pending-before-revoke')));
});

test('sendMessage honors retry_after and later delivers without losing the durable outbox item', async (t) => {
  const telegram = new FakeTelegram();
  telegram.updateQueues.set(TOKEN_A, [privateStart(7)]);
  let sends = 0;
  telegram.sendHandler = async () => {
    sends += 1;
    if (sends === 1) {
      return jsonResponse({
        ok: false,
        error_code: 429,
        description: 'Too Many Requests',
        parameters: { retry_after: 3 },
      }, 429);
    }
    return jsonResponse({ ok: true, result: { message_id: sends } });
  };
  const { service, clock, file } = await fixture(t, { telegram });
  await registerA(service);
  await service.processBotUpdates(BOT_A);

  assert.deepEqual(await service.deliverDue(), { attempted: 1, delivered: 0, failed: 1 });
  let state = JSON.parse(await fsp.readFile(file, 'utf8'));
  let delivery = Object.values(state.outbox)[0];
  assert.equal(delivery.status, 'retry');
  assert.equal(delivery.nextAttemptAt, clock.value + 3_000);

  clock.value += 2_999;
  assert.deepEqual(await service.deliverDue(), { attempted: 0, delivered: 0, failed: 0 });
  clock.value += 1;
  assert.deepEqual(await service.deliverDue(), { attempted: 1, delivered: 1, failed: 0 });
  state = JSON.parse(await fsp.readFile(file, 'utf8'));
  delivery = Object.values(state.outbox)[0];
  assert.equal(delivery.status, 'delivered');
  assert.equal(delivery.attempts, 2);
});

test('Telegram authentication failures disable polling and redact tokens from errors, state, and logs', async (t) => {
  const telegram = new FakeTelegram();
  telegram.pollHandler = async ({ token }) => jsonResponse({
    ok: false,
    error_code: 401,
    description: `Unauthorized token ${token} at https://api.telegram.org/bot${token}/getUpdates`,
  }, 401);
  const { service, logs, file } = await fixture(t, { telegram });
  await registerA(service);

  await assert.rejects(
    service.processBotUpdates(BOT_A),
    (error) => error.status === 401 && !error.message.includes(TOKEN_A),
  );
  const [bot] = await service.listBots({ email: OWNER });
  assert.equal(bot.enabled, false);
  assert.doesNotMatch(bot.lastError, new RegExp(TOKEN_A));
  assert.doesNotMatch(JSON.stringify(logs), new RegExp(TOKEN_A));
  const persisted = JSON.parse(await fsp.readFile(file, 'utf8'));
  assert.doesNotMatch(persisted.bots[BOT_A].lastError, new RegExp(TOKEN_A));
});

test('start and stop abort an in-flight long poll and leave no live background loop', async (t) => {
  const telegram = new FakeTelegram();
  let pollStarted;
  const started = new Promise((resolve) => { pollStarted = resolve; });
  let pollAborted = false;
  telegram.pollHandler = ({ signal }) => new Promise((resolve, reject) => {
    pollStarted();
    signal.addEventListener('abort', () => {
      pollAborted = true;
      reject(signal.reason);
    }, { once: true });
  });
  const { service } = await fixture(t, {
    telegram,
    pollTimeoutSeconds: 25,
    pollRefreshMs: 10,
    dispatcherIntervalMs: 10,
  });
  await registerA(service);

  assert.equal(await service.start(), true);
  await started;
  assert.equal((await service.status({ email: OWNER })).running, true);
  assert.equal(await service.stop(), true);
  assert.equal(pollAborted, true);
  assert.equal((await service.status({ email: OWNER })).running, false);
  assert.equal(await service.stop(), false);
});

test('background dispatch delivers system messages without observing or reading events when no recipient is eligible', async (t) => {
  const telegram = new FakeTelegram();
  telegram.updateQueues.set(TOKEN_A, [privateStart(50)]);
  const calls = { observe: 0, read: 0 };
  const coordinator = {
    hasProject: async () => true,
    observeHost: async () => { calls.observe += 1; },
    readEvents: async ({ after }) => {
      calls.read += 1;
      return { schema_version: 1, events: [], next_cursor: after, has_more: false };
    },
  };
  const { service } = await fixture(t, {
    telegram,
    coordinator,
    pollRefreshMs: 10,
    dispatcherIntervalMs: 10,
  });
  await registerA(service);
  await service.processBotUpdates(BOT_A);
  telegram.updateQueues.set(TOKEN_A, []);

  await service.start();
  await waitUntil(() => telegram.calls.some((call) => call.method === 'sendMessage'));
  await service.stop();
  assert.deepEqual(calls, { observe: 0, read: 0 });
});

test('eligible event polling is frequent while expensive host observation is independently throttled', async (t) => {
  const telegram = new FakeTelegram();
  telegram.updateQueues.set(TOKEN_A, [privateStart(60)]);
  const calls = { observe: 0, read: 0 };
  const coordinator = {
    hasProject: async (repoId) => repoId === 'repo-alpha',
    observeHost: async () => { calls.observe += 1; },
    readEvents: async ({ after }) => {
      calls.read += 1;
      return { schema_version: 1, events: [], next_cursor: after, has_more: false };
    },
  };
  const { service } = await fixture(t, {
    telegram,
    coordinator,
    pollRefreshMs: 10,
    dispatcherIntervalMs: 10,
    observationIntervalMs: 5_000,
  });
  await registerA(service);
  await service.assignProject({ email: OWNER, botId: BOT_A, repoId: 'repo-alpha' });
  await service.processBotUpdates(BOT_A);
  const [request] = await service.listAuthorizationQueue({ email: OWNER });
  await service.decideAuthorization({ email: OWNER, requestId: request.id, decision: 'approve' });
  telegram.updateQueues.set(TOKEN_A, []);
  calls.observe = 0;
  calls.read = 0;

  await service.start();
  await waitUntil(() => calls.read >= 3);
  await service.stop();
  assert.equal(calls.observe, 1);
  assert.ok(calls.read >= 3);
});
