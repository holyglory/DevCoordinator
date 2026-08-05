import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';
import { CoordError } from '../src/coordinator.mjs';
import { TelegramServiceError } from '../src/telegram.mjs';
import { createTelegramIpcClient } from '../src/telegram-ipc.mjs';

async function fixture(t, { telegramOverride = null, log = null } = {}) {
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
  const localTelegram = {
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
  const telegram = telegramOverride ?? localTelegram;
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
    log,
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
  return { authorizations, bots, calls, coordinator, request, telegram };
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

test('Telegram project catalog serves bounded retained inventory when its background refresh fails', async (t) => {
  const entries = [];
  const log = {
    child: () => log,
    warn: (message, fields) => entries.push({ level: 'warn', message, fields }),
    error: (message, fields) => entries.push({ level: 'error', message, fields }),
  };
  const { calls, coordinator, request } = await fixture(t, { log });
  const transient = new CoordError('loopback inventory connection reset', {
    status: 502,
    body: { code: 'coordinator_unavailable', classification: 'dependency' },
  });
  coordinator.inventoryForOverview = async (options) => {
    calls.push({ method: 'inventoryForOverview', options });
    return {
      inventory: {
        repositories: [{
          repo_id: 'repo-global-finance',
          display_name: 'GlobalFinance',
          canonical_root: '/srv/global-finance',
        }],
      },
      state: 'stale',
      ageMs: 45_000,
      refreshing: false,
      error: transient,
    };
  };
  coordinator.inventory = async () => {
    throw new Error('Telegram must not force a second fresh inventory request');
  };

  const first = await request('/api/telegram');
  const second = await request('/api/telegram');

  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.deepEqual(first.json.projects.map((project) => project.id), ['repo-global-finance']);
  assert.deepEqual(calls.find((call) => call.method === 'inventoryForOverview').options, {
    maxAgeMs: 15_000,
    maxStaleMs: 300_000,
    maxWaitMs: 1_000,
  });
  const warnings = entries.filter((entry) => (
    entry.level === 'warn'
    && entry.message === 'Telegram project catalog is using retained inventory'
  ));
  assert.equal(warnings.length, 1, 'identical refresh failures must be rate-bounded');
  assert.deepEqual(warnings[0].fields, {
    reason: 'background_refresh_failed',
    state: 'stale',
    ageMs: 45_000,
    refreshing: false,
    code: 'coordinator_unavailable',
    classification: 'dependency',
    status: 502,
    error: 'loopback inventory connection reset',
  });
});

test('Telegram project catalog fails closed and logs no malformed repository identity', async (t) => {
  const entries = [];
  const log = {
    child: () => log,
    warn: (message, fields) => entries.push({ level: 'warn', message, fields }),
    error: (message, fields) => entries.push({ level: 'error', message, fields }),
  };
  const { coordinator, request } = await fixture(t, { log });
  coordinator.inventoryForOverview = async () => ({
    inventory: {
      repositories: [{ repo_id: 'invalid\nidentity', display_name: 'Must not leak' }],
    },
    state: 'retained',
    ageMs: 12_000,
    refreshing: true,
    error: null,
  });

  const response = await request('/api/telegram');

  assert.equal(response.status, 502);
  assert.equal(response.json.error, 'coordinator returned an invalid repository identity');
  const malformed = entries.find((entry) => (
    entry.level === 'error'
    && entry.message === 'Telegram project catalog identity is malformed'
  ));
  assert.deepEqual(malformed?.fields, {
    reason: 'repository_identity_invalid',
    state: 'retained',
    ageMs: 12_000,
    repositoryIndex: 0,
  });
  assert.doesNotMatch(JSON.stringify(entries), /invalid\\nidentity|Must not leak/,
    'diagnostics must describe the failure without logging untrusted identity values');
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

test('maintenance is browser-safe and tells clients to wait instead of exposing the operator task', async (t) => {
  const { coordinator, request } = await fixture(t);
  coordinator.inventory = async () => {
    throw new CoordError('Publishing GlobalFinance OKX collector on fresh runtime', {
      status: 500,
      body: {
        code: 'maintenance_in_progress',
        classification: 'maintenance',
        retry_after_seconds: 30,
      },
    });
  };

  const response = await request('/api/telegram');
  assert.equal(response.status, 503);
  assert.equal(response.json.classification, 'maintenance');
  assert.equal(response.json.code, 'maintenance_in_progress');
  assert.equal(response.json.retryAfterSeconds, 30);
  assert.match(response.json.error, /temporarily paused/);
  assert.doesNotMatch(JSON.stringify(response.json), /GlobalFinance|OKX|collector|fresh runtime/);
});

test('notification handoff returns typed local unavailability without taking down Console API', async (t) => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'dc-notification-handoff-'));
  await fsp.chmod(directory, 0o700);
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const telegram = createTelegramIpcClient({
    socketPath: path.join(directory, 'worker-not-started.sock'),
    timeoutMs: 100,
  });
  const { request } = await fixture(t, { telegramOverride: telegram });

  const unavailable = await request('/api/telegram');
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.json.code, 'notification_unavailable');
  assert.match(unavailable.json.error, /Notification worker is unavailable/);
  assert.doesNotMatch(JSON.stringify(unavailable.json), /socket|ECONNREFUSED|api-token/);
});
