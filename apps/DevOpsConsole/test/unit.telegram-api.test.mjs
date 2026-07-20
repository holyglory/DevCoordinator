import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';
import { TelegramServiceError } from '../src/telegram.mjs';

async function fixture(t) {
  const calls = [];
  const bots = [{
    id: '12345',
    label: 'Operations',
    ownerEmail: 'operator@gmail.com',
    username: 'operations_bot',
    firstName: 'Operations',
    enabled: true,
    projects: ['repo-global-finance'],
    token: '12345:THIS_MUST_NEVER_REACH_THE_BROWSER_1234567890', // public-artifact-guard: allow text-secret -- synthetic no-leak fixture
    tokenFingerprint: 'private-fingerprint',
    createdAt: '2026-07-18T10:00:00.000Z',
    updatedAt: '2026-07-18T10:00:00.000Z',
    hasToken: true,
  }];
  const authorizations = [{
    id: 'authorization-1',
    botId: '12345',
    telegramUserId: '777',
    chatId: 'private-chat-id',
    username: 'telegram_user',
    firstName: 'Telegram',
    lastName: 'User',
    status: 'pending',
    requestedAt: '2026-07-18T11:00:00.000Z',
    decidedAt: null,
    decidedBy: null,
  }];
  const telegram = {
    async listBots({ email }) {
      calls.push({ method: 'listBots', email });
      if (email === 'intruder@gmail.com') {
        throw new TelegramServiceError(403, 'bot_forbidden', 'Telegram bot belongs to another Console user');
      }
      return bots;
    },
    async listAuthorizationQueue({ email, botId, status }) {
      calls.push({ method: 'listAuthorizationQueue', email, botId, status });
      return authorizations.filter((request) => request.botId === botId);
    },
    async registerBot(body) {
      calls.push({ method: 'registerBot', body });
      return bots[0];
    },
    async setProjects(body) {
      calls.push({ method: 'setProjects', body });
      bots[0].projects = [...body.repoIds];
      return bots[0];
    },
    async decideAuthorization(body) {
      calls.push({ method: 'decideAuthorization', body });
      authorizations[0].status = body.decision === 'approve' ? 'approved' : 'denied';
      return authorizations[0];
    },
    async removeBot(body) {
      calls.push({ method: 'removeBot', body });
      bots.length = 0;
      return true;
    },
  };
  const coordinator = {
    async inventory(options) {
      calls.push({ method: 'inventory', options });
      return {
        repositories: [
          { repo_id: 'repo-other', display_name: 'Other', canonical_root: '/srv/other' },
          {
            repo_id: 'repo-global-finance',
            display_name: 'GlobalFinance',
            canonical_root: '/srv/global-finance',
          },
        ],
      };
    },
  };
  const api = createConsoleApi({
    config: {
      consoleOrigin: 'https://console.example.test',
      consoleHost: 'console.example.test',
      domain: 'example.test',
    },
    log: null,
    coordinator,
    routeStore: { list: () => [] },
    upstreamAuthStore: null,
    accessStore: { isAdmin: (email) => email === 'owner@gmail.com' },
    guard: { checkOrigin: () => true },
    certManager: null,
    metrics: null,
    prefs: null,
    telegram,
  });
  const server = http.createServer((req, res) => api.handle(req, res, {
    email: req.headers['x-fixture-email'] || 'operator@gmail.com',
  }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  async function request(pathname, { method = 'GET', body, email = 'operator@gmail.com' } = {}) {
    const response = await fetch(`${origin}${pathname}`, {
      method,
      headers: {
        'x-fixture-email': email,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, json: await response.json() };
  }
  return { authorizations, bots, calls, request, telegram };
}

test('Telegram view is actor-scoped, uses exact repository IDs, and never returns secrets or chat IDs', async (t) => {
  const { calls, request } = await fixture(t);
  const response = await request('/api/telegram');

  assert.equal(response.status, 200);
  assert.deepEqual(response.json.projects.map((project) => project.id), [
    'repo-global-finance',
    'repo-other',
  ]);
  assert.equal(response.json.bots[0].ownerEmail, 'operator@gmail.com');
  assert.equal(response.json.bots[0].authorizations[0].telegramUserId, '777');
  assert.equal(response.json.bots[0].authorizations[0].chatId, undefined);
  assert.equal(response.json.bots[0].token, undefined);
  assert.equal(response.json.bots[0].tokenFingerprint, undefined);
  assert.doesNotMatch(JSON.stringify(response.json), /THIS_MUST_NEVER|private-fingerprint|private-chat-id/);
  assert.ok(calls.some((call) => call.method === 'listBots' && call.email === 'operator@gmail.com'));
});

test('registration and bot mutations always bind the signed-in Console identity', async (t) => {
  const { calls, request } = await fixture(t);
  const token = '12345:VALID_FIXTURE_TOKEN_12345678901234567890';
  const registered = await request('/api/telegram/bots', {
    method: 'POST',
    body: { token, label: 'Operations', takeOver: true, email: 'attacker@gmail.com' },
  });
  assert.equal(registered.status, 201);
  assert.deepEqual(calls.find((call) => call.method === 'registerBot').body, {
    email: 'operator@gmail.com',
    token,
    label: 'Operations',
    takeoverWebhook: true,
  });
  assert.doesNotMatch(JSON.stringify(registered.json), /VALID_FIXTURE_TOKEN/);

  const assigned = await request('/api/telegram/bots/12345/projects', {
    method: 'PATCH', body: { projectIds: ['repo-other'] },
  });
  assert.equal(assigned.status, 200);
  assert.deepEqual(calls.find((call) => call.method === 'setProjects').body, {
    email: 'operator@gmail.com',
    botId: '12345',
    repoIds: ['repo-other'],
  });

  const decided = await request('/api/telegram/bots/12345/authorizations/authorization-1/decision', {
    method: 'POST', body: { decision: 'approve' },
  });
  assert.equal(decided.status, 200);
  assert.deepEqual(calls.find((call) => call.method === 'decideAuthorization').body, {
    email: 'operator@gmail.com',
    requestId: 'authorization-1',
    decision: 'approve',
  });
});

test('unknown project IDs and mismatched authorization paths fail before mutation', async (t) => {
  const { calls, request } = await fixture(t);
  const unknown = await request('/api/telegram/bots/12345/projects', {
    method: 'PATCH', body: { projectIds: ['display-name-is-not-an-id'] },
  });
  assert.equal(unknown.status, 404);
  assert.equal(calls.some((call) => call.method === 'setProjects'), false);

  const mismatched = await request('/api/telegram/bots/99999/authorizations/authorization-1/decision', {
    method: 'POST', body: { decision: 'approve' },
  });
  assert.equal(mismatched.status, 404);
  assert.equal(calls.some((call) => call.method === 'decideAuthorization'), false);
});

test('Telegram ownership errors retain a stable browser-safe error code', async (t) => {
  const { request } = await fixture(t);
  const response = await request('/api/telegram', { email: 'intruder@gmail.com' });
  assert.equal(response.status, 403);
  assert.equal(response.json.code, 'bot_forbidden');
  assert.match(response.json.error, /another Console user/);
});

test('an invalid Telegram token is a form error, never a false Console-session expiry', async (t) => {
  const { request, telegram } = await fixture(t);
  telegram.registerBot = async () => {
    throw new TelegramServiceError(401, 'telegram_api_error', 'Unauthorized');
  };
  const response = await request('/api/telegram/bots', {
    method: 'POST',
    body: { token: '12345:INVALID_BUT_REDACTED_TOKEN_1234567890' },
  });
  assert.equal(response.status, 400);
  assert.equal(response.json.code, 'telegram_api_error');
  assert.equal(response.json.error, 'Unauthorized');
});
