import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';
import { createTelegramService } from '../src/telegram.mjs';

const EMAIL = 'operator@gmail.com';
const BOT_ID = '123456';
const TOKEN = `${BOT_ID}:${'T'.repeat(36)}`;

function telegramResponse(result, status = 200) {
  return new Response(JSON.stringify(status === 200
    ? { ok: true, result }
    : { ok: false, error_code: status, description: String(result) }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('Console registration through /start approval delivers an exact-project crash event', async (t) => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-telegram-console-integration-'));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const clock = { value: Date.parse('2026-07-18T12:00:00.000Z') };
  const calls = [];
  const sends = [];
  const updates = [{
    update_id: 1,
    message: {
      message_id: 1,
      text: '/start',
      from: { id: 7001, is_bot: false, username: 'telegram_user', first_name: 'Telegram' },
      chat: { id: 7001, type: 'private' },
    },
  }];
  const telegramFetch = async (url, options) => {
    const match = String(url).match(/^https:\/\/api\.telegram\.org\/bot([^/]+)\/([^/]+)$/);
    assert.ok(match);
    const [, token, method] = match;
    assert.equal(token, TOKEN);
    const body = JSON.parse(options.body);
    calls.push({ method, body });
    if (method === 'getMe') {
      return telegramResponse({ id: Number(BOT_ID), is_bot: true, username: 'console_alerts_bot', first_name: 'Alerts' });
    }
    if (method === 'getWebhookInfo') return telegramResponse({ url: '' });
    if (method === 'getUpdates') return telegramResponse(updates);
    if (method === 'sendMessage') {
      sends.push(body);
      return telegramResponse({ message_id: sends.length });
    }
    assert.fail(`unexpected Telegram method ${method}`);
  };

  const feed = [];
  let observations = 0;
  const cursorFor = (event) => `cursor:${event.event_id}`;
  const telegram = createTelegramService({
    file: path.join(directory, 'telegram-control.json'),
    fetchImpl: telegramFetch,
    now: () => clock.value,
    isAdmin: () => false,
    coordinator: {
      hasProject: async (repoId) => repoId === 'repo-global-finance',
      observeHost: async () => { observations += 1; },
      readEvents: async ({ after, limit }) => {
        const index = after === null
          ? 0
          : Math.max(0, feed.findIndex((event) => cursorFor(event) === after) + 1);
        const events = feed.slice(index, index + limit);
        return {
          schema_version: 1,
          events,
          next_cursor: events.length ? cursorFor(events.at(-1)) : after,
          has_more: index + events.length < feed.length,
        };
      },
    },
  });
  await telegram.load();

  const api = createConsoleApi({
    config: {
      consoleOrigin: 'https://console.example.test',
      consoleHost: 'console.example.test',
      domain: 'example.test',
    },
    log: null,
    coordinator: {
      inventory: async () => ({
        repositories: [{
          repo_id: 'repo-global-finance',
          display_name: 'GlobalFinance',
          canonical_root: '/srv/global-finance',
        }],
      }),
    },
    routeStore: { list: () => [] },
    upstreamAuthStore: null,
    accessStore: { isAdmin: () => false },
    guard: { checkOrigin: () => true },
    certManager: null,
    metrics: null,
    prefs: null,
    telegram,
  });
  const server = http.createServer((req, res) => api.handle(req, res, { email: EMAIL }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  async function request(pathname, { method = 'GET', body } = {}) {
    const response = await fetch(`${origin}${pathname}`, {
      method,
      headers: body === undefined ? undefined : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, json: await response.json() };
  }

  const registered = await request('/api/telegram/bots', {
    method: 'POST', body: { token: TOKEN, label: 'Operations alerts' },
  });
  assert.equal(registered.status, 201);
  assert.equal(registered.json.registeredBotId, BOT_ID);
  assert.doesNotMatch(JSON.stringify(registered.json), new RegExp(TOKEN));

  const assigned = await request(`/api/telegram/bots/${BOT_ID}/projects`, {
    method: 'PATCH', body: { projectIds: ['repo-global-finance'] },
  });
  assert.equal(assigned.status, 200);
  await telegram.processBotUpdates(BOT_ID);

  const queue = await request('/api/telegram');
  const pending = queue.json.bots[0].authorizations[0];
  assert.equal(pending.status, 'pending');
  assert.equal(pending.telegramUserId, '7001');
  const approved = await request(
    `/api/telegram/bots/${BOT_ID}/authorizations/${pending.id}/decision`,
    { method: 'POST', body: { decision: 'approve' } },
  );
  assert.equal(approved.status, 200);
  assert.equal(approved.json.bots[0].authorizations[0].status, 'approved');
  assert.equal(observations, 1, 'approval must establish the coordinator event high-watermark first');

  feed.push({
    event_id: 'global-finance-crash-1',
    repo_id: 'repo-global-finance',
    event_kind: 'server.stopped',
    code: 'server_crashed',
    message: 'Server payments-api stopped unexpectedly',
    occurred_at: '2026-07-18T12:01:00.000Z',
  });
  assert.equal((await telegram.ingestEvents()).deliveries, 1);
  for (let pass = 0; pass < 5; pass += 1) {
    await telegram.deliverDue({ limit: 10 });
    clock.value += 1_000;
  }
  assert.ok(sends.some((message) => /waiting for a Console administrator/.test(message.text)));
  assert.ok(sends.some((message) => /approved/.test(message.text)));
  assert.ok(sends.some((message) => /global-finance-crash-1/.test(message.text)));
  assert.ok(sends.some((message) => /payments-api stopped unexpectedly/.test(message.text)));
  assert.ok(sends.every((message) => message.chat_id === '7001'));
});
