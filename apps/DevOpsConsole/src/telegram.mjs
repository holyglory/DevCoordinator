// Telegram bot registration, authorization, and durable event delivery for the
// DevOps Console. This module deliberately has no HTTP/router dependencies: the
// Console composition root supplies authenticated email identities and an
// exact-repository coordinator adapter.

import crypto from 'node:crypto';
import { constants as fsConstants, promises as fsp } from 'node:fs';
import path from 'node:path';

const EMAIL_RE = /^[^\s@<>(),;:\\"\[\]]+@[^\s@<>(),;:\\"\[\]]+\.[^\s@<>(),;:\\"\[\]]+$/;
const TELEGRAM_TOKEN_RE = /^[1-9][0-9]{3,19}:[A-Za-z0-9_-]{20,220}$/;
const TELEGRAM_ID_RE = /^[1-9][0-9]{0,19}$/;
const START_COMMAND_RE = /^\/start(?:@([A-Za-z0-9_]{5,32}))?(?:\s|$)/i;
const MAX_REPO_ID_LENGTH = 512;
const MAX_CURSOR_LENGTH = 1024;
const MAX_LABEL_LENGTH = 80;
const MAX_BOTS = 100;
const MAX_AUTHORIZATIONS = 10_000;
const MAX_OUTBOX = 25_000;
const MAX_PROCESSED_UPDATES = 512;
const MAX_TELEGRAM_MESSAGE = 4096;
const DEFAULT_EVENT_LIMIT = 200;
const DEFAULT_DELIVERY_LIMIT = 25;
const MAX_DELIVERY_ATTEMPTS = 8;
const NO_CHANGE = Symbol('no-change');

export class TelegramServiceError extends Error {
  constructor(status, code, message, { retryAfter = null } = {}) {
    super(message);
    this.name = 'TelegramServiceError';
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

function noChange(value) {
  return { [NO_CHANGE]: true, value };
}

function normalizeEmail(value) {
  if (typeof value !== 'string') {
    throw new TelegramServiceError(400, 'invalid_email', 'email must be a string');
  }
  const email = value.trim().toLowerCase();
  if (!email || email.length > 254 || !EMAIL_RE.test(email)) {
    throw new TelegramServiceError(400, 'invalid_email', 'email must be a valid email address');
  }
  return email;
}

function requireToken(value) {
  if (typeof value !== 'string' || !TELEGRAM_TOKEN_RE.test(value)) {
    throw new TelegramServiceError(400, 'invalid_bot_token', 'Telegram bot token is invalid');
  }
  return value;
}

function requireTelegramId(value, field = 'Telegram ID') {
  const id = typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : String(value ?? '');
  if (!TELEGRAM_ID_RE.test(id)) {
    throw new TelegramServiceError(400, 'invalid_telegram_id', `${field} is invalid`);
  }
  return id;
}

function requireRepoId(value) {
  if (typeof value !== 'string') {
    throw new TelegramServiceError(400, 'invalid_repo_id', 'repo_id must be a string');
  }
  const repoId = value.trim();
  if (
    !repoId
    || repoId.length > MAX_REPO_ID_LENGTH
    || /[\u0000-\u001f\u007f]/.test(repoId)
  ) {
    throw new TelegramServiceError(400, 'invalid_repo_id', 'repo_id is invalid');
  }
  return repoId;
}

function requireCursor(value, { nullable = true } = {}) {
  if (value === null && nullable) return null;
  if (
    typeof value !== 'string'
    || !value
    || value.length > MAX_CURSOR_LENGTH
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TelegramServiceError(502, 'invalid_event_cursor', 'coordinator event cursor is invalid');
  }
  return value;
}

function normalizeLabel(value, fallback = null) {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value !== 'string') {
    throw new TelegramServiceError(400, 'invalid_bot_label', 'bot label must be a string');
  }
  const label = value.trim();
  if (!label || label.length > MAX_LABEL_LENGTH || /[\u0000-\u001f\u007f]/.test(label)) {
    throw new TelegramServiceError(
      400,
      'invalid_bot_label',
      `bot label must be 1-${MAX_LABEL_LENGTH} characters without control characters`,
    );
  }
  return label;
}

function safeText(value, max = 512) {
  if (typeof value !== 'string') return null;
  const text = value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim();
  return text ? text.slice(0, max) : null;
}

function safeUsername(value) {
  const username = safeText(value, 32);
  return username && /^[A-Za-z0-9_]{5,32}$/.test(username) ? username : null;
}

function timestamp(ms) {
  return new Date(ms).toISOString();
}

function makeInitialState() {
  return {
    version: 1,
    revision: 0,
    eventCursor: null,
    bots: {},
    authorizationRequests: {},
    outbox: {},
  };
}

function botView(bot) {
  if (!bot) return null;
  return {
    id: bot.id,
    ownerEmail: bot.ownerEmail,
    label: bot.label,
    username: bot.username,
    firstName: bot.firstName,
    enabled: bot.enabled,
    projects: [...bot.projects].sort(),
    nextUpdateId: bot.nextUpdateId,
    createdAt: bot.createdAt,
    updatedAt: bot.updatedAt,
    lastPollAt: bot.lastPollAt,
    lastUpdateAt: bot.lastUpdateAt,
    lastDeliveryAt: bot.lastDeliveryAt,
    lastError: bot.lastError,
    hasToken: true,
  };
}

function requestView(request, bot) {
  return {
    id: request.id,
    botId: request.botId,
    botUsername: bot?.username ?? null,
    telegramUserId: request.telegramUserId,
    chatId: request.chatId,
    username: request.username,
    firstName: request.firstName,
    lastName: request.lastName,
    languageCode: request.languageCode,
    status: request.status,
    requestedAt: request.requestedAt,
    decidedAt: request.decidedAt,
    decidedBy: request.decidedBy,
  };
}

function tokenFingerprint(token) {
  return crypto.createHash('sha256').update(token).digest('hex').slice(0, 16);
}

function stableId(...parts) {
  return crypto.createHash('sha256').update(parts.join('\u0000')).digest('hex');
}

function redactString(value, tokens = []) {
  let text = String(value ?? '');
  for (const token of tokens) {
    if (token) text = text.split(token).join('[REDACTED]');
  }
  return text
    .replace(/https:\/\/api\.telegram\.org\/bot[^/\s]+/gi, 'https://api.telegram.org/bot[REDACTED]')
    .replace(/\bbot[1-9][0-9]{3,19}:[A-Za-z0-9_-]{20,220}\b/g, 'bot[REDACTED]')
    .replace(/\b[1-9][0-9]{3,19}:[A-Za-z0-9_-]{20,220}\b/g, '[REDACTED]');
}

function telegramError(error, tokens = []) {
  if (error instanceof TelegramServiceError) {
    return new TelegramServiceError(
      error.status,
      error.code,
      redactString(error.message, tokens),
      { retryAfter: error.retryAfter },
    );
  }
  return new TelegramServiceError(
    502,
    'telegram_unavailable',
    `Telegram API unavailable: ${redactString(error?.message ?? error, tokens)}`,
  );
}

function isAbortError(error) {
  return error?.name === 'AbortError' || error?.code === 'ABORT_ERR';
}

function defaultSleep(ms, signal) {
  if (signal?.aborted) return Promise.reject(signal.reason ?? new DOMException('Aborted', 'AbortError'));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(done, Math.max(0, ms));
    timer.unref?.();
    function done() {
      signal?.removeEventListener('abort', aborted);
      resolve();
    }
    function aborted() {
      clearTimeout(timer);
      signal?.removeEventListener('abort', aborted);
      reject(signal.reason ?? new DOMException('Aborted', 'AbortError'));
    }
    signal?.addEventListener('abort', aborted, { once: true });
  });
}

function validateLoadedState(parsed) {
  const validEnvelope = parsed
    && typeof parsed === 'object'
    && !Array.isArray(parsed)
    && parsed.version === 1
    && Number.isSafeInteger(parsed.revision)
    && parsed.revision >= 0
    && (parsed.eventCursor === null || typeof parsed.eventCursor === 'string')
    && parsed.bots && typeof parsed.bots === 'object' && !Array.isArray(parsed.bots)
    && parsed.authorizationRequests && typeof parsed.authorizationRequests === 'object'
    && !Array.isArray(parsed.authorizationRequests)
    && parsed.outbox && typeof parsed.outbox === 'object' && !Array.isArray(parsed.outbox);
  if (!validEnvelope) throw new Error('invalid Telegram state envelope');
  requireCursor(parsed.eventCursor);

  for (const [id, bot] of Object.entries(parsed.bots)) {
    if (
      !bot || typeof bot !== 'object' || Array.isArray(bot)
      || requireTelegramId(id, 'bot ID') !== id
      || requireTelegramId(bot.id, 'bot ID') !== id
      || normalizeEmail(bot.ownerEmail) !== bot.ownerEmail
      || requireToken(bot.token) !== bot.token
      || bot.tokenFingerprint !== tokenFingerprint(bot.token)
      || typeof bot.label !== 'string'
      || normalizeLabel(bot.label) !== bot.label
      || typeof bot.enabled !== 'boolean'
      || !Array.isArray(bot.projects)
      || !Number.isSafeInteger(bot.nextUpdateId) || bot.nextUpdateId < 0
      || !Array.isArray(bot.processedUpdateIds)
    ) throw new Error('invalid Telegram bot record');
    const projectSet = new Set(bot.projects.map(requireRepoId));
    if (projectSet.size !== bot.projects.length) throw new Error('duplicate Telegram bot project');
    for (const updateId of bot.processedUpdateIds) {
      if (!Number.isSafeInteger(updateId) || updateId < 0) throw new Error('invalid processed update ID');
    }
  }

  for (const [id, request] of Object.entries(parsed.authorizationRequests)) {
    if (
      !request || typeof request !== 'object' || Array.isArray(request)
      || request.id !== id
      || !parsed.bots[request.botId]
      || requireTelegramId(request.telegramUserId, 'Telegram user ID') !== request.telegramUserId
      || requireTelegramId(request.chatId, 'Telegram chat ID') !== request.chatId
      || !['pending', 'approved', 'denied', 'revoked'].includes(request.status)
      || (request.approvalCursor !== null && typeof request.approvalCursor !== 'string')
    ) throw new Error('invalid Telegram authorization record');
    requireCursor(request.approvalCursor);
  }

  for (const [id, delivery] of Object.entries(parsed.outbox)) {
    if (
      !delivery || typeof delivery !== 'object' || Array.isArray(delivery)
      || delivery.id !== id
      || !['event', 'system'].includes(delivery.kind)
      || !['pending', 'sending', 'retry', 'delivered', 'dead', 'cancelled'].includes(delivery.status)
      || !Number.isSafeInteger(delivery.attempts) || delivery.attempts < 0
      || !Number.isFinite(delivery.nextAttemptAt)
    ) throw new Error('invalid Telegram outbox record');
  }
  return parsed;
}

function normalizeBotIdentity(result) {
  if (!result || typeof result !== 'object' || result.is_bot !== true) {
    throw new TelegramServiceError(400, 'not_a_bot', 'Telegram token does not identify a bot');
  }
  return {
    id: requireTelegramId(result.id, 'bot ID'),
    username: safeUsername(result.username),
    firstName: safeText(result.first_name, 128),
  };
}

function normalizeEvent(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TelegramServiceError(502, 'invalid_event_feed', 'coordinator returned an invalid event');
  }
  const eventId = safeText(raw.event_id, 512);
  if (!eventId) {
    throw new TelegramServiceError(502, 'invalid_event_feed', 'coordinator event_id is invalid');
  }
  const repoId = raw.repo_id === null ? null : requireRepoId(raw.repo_id);
  return {
    event_id: eventId,
    repo_id: repoId,
    event_kind: safeText(raw.event_kind, 128) ?? 'event',
    source_id: safeText(raw.source_id, 256),
    resource_kind: safeText(raw.resource_kind, 64),
    resource_name: safeText(raw.resource_name, 256),
    code: safeText(raw.code, 128),
    message: safeText(raw.message, 2048),
    occurred_at: safeText(raw.occurred_at, 64),
  };
}

function formatEventMessage(event) {
  const kind = (event.event_kind ?? 'event').replace(/[_-]+/g, ' ').toUpperCase();
  const resource = event.resource_name || event.source_id;
  const lines = [
    `DevOps Console: ${kind}`,
    `Project: ${event.repo_id}`,
  ];
  if (resource) lines.push(`Resource: ${resource}`);
  if (event.message) lines.push('', event.message);
  if (event.code) lines.push(`Code: ${event.code}`);
  if (event.occurred_at) lines.push(`Time: ${event.occurred_at}`);
  lines.push(`Event: ${event.event_id}`);
  const text = lines.join('\n');
  return text.length <= MAX_TELEGRAM_MESSAGE ? text : `${text.slice(0, MAX_TELEGRAM_MESSAGE - 1)}…`;
}

/**
 * Create the Console Telegram subsystem.
 *
 * coordinator is intentionally a small injected boundary:
 *   - hasProject(repoId) -> boolean (exact immutable repo_id comparison)
 *   - observeHost() -> refresh the coordinator's transition journal
 *   - readEvents({ after, limit }) ->
 *       { events: [{ event_id, repo_id, ... }], next_cursor, has_more }
 *
 * after/next_cursor are bounded opaque strings owned by the coordinator. The
 * cursor is persisted only in the same atomic write that enqueues every
 * recipient delivery for the page.
 */
export function createTelegramService({
  file,
  log,
  fetchImpl = globalThis.fetch,
  coordinator,
  isAdmin = () => false,
  now = () => Date.now(),
  randomUUID = () => crypto.randomUUID(),
  sleep = defaultSleep,
  pollTimeoutSeconds = 25,
  pollRefreshMs = 1_000,
  dispatcherIntervalMs = 1_000,
  observationIntervalMs = 5_000,
  requestTimeoutMs = 30_000,
  maxOutbox = MAX_OUTBOX,
} = {}) {
  if (typeof file !== 'string' || !file) {
    throw new TypeError('createTelegramService requires a state file path');
  }
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('createTelegramService requires fetch');
  }
  const clog = typeof log?.child === 'function' ? log.child({ mod: 'telegram' }) : log;
  let state = makeInitialState();
  let loaded = false;
  let loadPromise = null;
  let mutationChain = Promise.resolve();
  let ingestionChain = Promise.resolve();
  let controller = null;
  let supervisorPromise = null;
  let dispatcherPromise = null;
  const pollers = new Map();
  const chatNextSendAt = new Map();
  let nextObservationAt = 0;

  function knownTokens(extra = []) {
    return [...Object.values(state.bots).map((bot) => bot.token), ...extra].filter(Boolean);
  }

  function logFailure(message, error, extra = {}) {
    const tokens = knownTokens();
    clog?.warn?.(message, {
      ...extra,
      error: redactString(error?.message ?? error, tokens),
      code: error?.code ?? null,
    });
  }

  async function openPrivateStateFile() {
    let handle;
    try {
      handle = await fsp.open(file, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    } catch (error) {
      if (error?.code === 'ENOENT') throw error;
      if (error?.code === 'ELOOP') {
        throw new TelegramServiceError(500, 'unsafe_state_file', 'Telegram state symlinks are not allowed');
      }
      throw error;
    }
    try {
      const stat = await handle.stat();
      if (!stat.isFile()) {
        throw new TelegramServiceError(500, 'unsafe_state_file', 'Telegram state must be a regular file');
      }
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
        throw new TelegramServiceError(500, 'unsafe_state_file', 'Telegram state must be owned by the Console account');
      }
      if ((stat.mode & 0o077) !== 0) {
        throw new TelegramServiceError(500, 'unsafe_state_file', 'Telegram state must not be group/world accessible');
      }
      return handle;
    } catch (error) {
      await handle.close().catch(() => {});
      throw error;
    }
  }

  async function load() {
    if (loaded) return;
    if (loadPromise) return loadPromise;
    loadPromise = (async () => {
      let handle;
      try {
        handle = await openPrivateStateFile();
      } catch (error) {
        if (error?.code === 'ENOENT') {
          state = makeInitialState();
          loaded = true;
          return;
        }
        throw error;
      }
      try {
        const parsed = JSON.parse(await handle.readFile('utf8'));
        state = validateLoadedState(parsed);
      } catch (error) {
        if (error instanceof TelegramServiceError && error.code === 'unsafe_state_file') throw error;
        throw new TelegramServiceError(
          500,
          'invalid_state',
          `Telegram state is invalid and was left untouched: ${redactString(error?.message ?? error)}`,
        );
      } finally {
        await handle.close().catch(() => {});
      }
      // A crash after Telegram accepted sendMessage but before the local ack
      // leaves a sending claim. Retrying is the only lossless option and can
      // cause a duplicate; event messages carry a stable event ID for this.
      let recovered = false;
      for (const delivery of Object.values(state.outbox)) {
        if (delivery.status === 'sending') {
          delivery.status = 'retry';
          delivery.claimId = null;
          delivery.claimedAt = null;
          delivery.nextAttemptAt = now();
          recovered = true;
        }
      }
      loaded = true;
      if (recovered) await persist(state);
    })();
    try {
      await loadPromise;
    } finally {
      loadPromise = null;
    }
  }

  async function syncDirectory(directory) {
    let handle;
    try {
      handle = await fsp.open(directory, fsConstants.O_RDONLY);
      await handle.sync();
    } catch (error) {
      if (!['EINVAL', 'ENOTSUP', 'EPERM', 'EISDIR'].includes(error?.code)) throw error;
    } finally {
      await handle?.close().catch(() => {});
    }
  }

  async function persist(nextState) {
    const directory = path.dirname(file);
    await fsp.mkdir(directory, { recursive: true, mode: 0o700 });
    const tmp = `${file}.tmp-${process.pid}-${randomUUID()}`;
    let handle;
    try {
      handle = await fsp.open(tmp, 'wx', 0o600);
      await handle.writeFile(`${JSON.stringify(nextState, null, 2)}\n`, 'utf8');
      await handle.sync();
      await handle.close();
      handle = null;
      await fsp.chmod(tmp, 0o600);
      await fsp.rename(tmp, file);
      await fsp.chmod(file, 0o600);
      await syncDirectory(directory);
    } finally {
      await handle?.close().catch(() => {});
      await fsp.unlink(tmp).catch(() => {});
    }
  }

  async function ensureLoaded() {
    if (!loaded) await load();
  }

  async function mutate(apply) {
    await ensureLoaded();
    const pending = mutationChain.catch(() => {}).then(async () => {
      const draft = structuredClone(state);
      const result = await apply(draft);
      if (result?.[NO_CHANGE]) return result.value;
      draft.revision = state.revision + 1;
      await persist(draft);
      state = draft;
      return result;
    });
    mutationChain = pending.then(() => undefined, () => undefined);
    return pending;
  }

  async function actorIsAdmin(email) {
    try {
      return Boolean(await isAdmin(email));
    } catch {
      return false;
    }
  }

  async function requireManagedBot(emailInput, botIdInput) {
    await ensureLoaded();
    await mutationChain;
    const email = normalizeEmail(emailInput);
    const botId = requireTelegramId(botIdInput, 'bot ID');
    const bot = state.bots[botId];
    if (!bot) throw new TelegramServiceError(404, 'bot_not_found', 'Telegram bot not found');
    const admin = await actorIsAdmin(email);
    if (!admin && bot.ownerEmail !== email) {
      throw new TelegramServiceError(403, 'bot_forbidden', 'Telegram bot belongs to another Console user');
    }
    return { email, botId, bot, admin };
  }

  async function telegramCall(tokenInput, method, params = {}, { signal, timeoutMs } = {}) {
    const token = requireToken(tokenInput);
    const requestController = new AbortController();
    const onAbort = () => requestController.abort(signal.reason);
    if (signal?.aborted) onAbort();
    else signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(
      () => requestController.abort(new DOMException('Telegram request timed out', 'TimeoutError')),
      timeoutMs ?? requestTimeoutMs,
    );
    timer.unref?.();
    try {
      const response = await fetchImpl(`https://api.telegram.org/bot${token}/${method}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(params),
        signal: requestController.signal,
      });
      let payload;
      try {
        payload = await response.json();
      } catch {
        payload = null;
      }
      if (!response.ok || !payload || payload.ok !== true) {
        const status = Number(payload?.error_code) || Number(response.status) || 502;
        const retryAfter = Number.isFinite(Number(payload?.parameters?.retry_after))
          ? Math.max(0, Number(payload.parameters.retry_after))
          : null;
        const description = safeText(payload?.description, 512) ?? `Telegram API ${method} failed`;
        throw new TelegramServiceError(
          status >= 400 && status <= 599 ? status : 502,
          status === 429 ? 'telegram_rate_limited' : 'telegram_api_error',
          redactString(description, [token]),
          { retryAfter },
        );
      }
      return payload.result;
    } catch (error) {
      if (isAbortError(error) && signal?.aborted) throw error;
      throw telegramError(error, [token]);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    }
  }

  async function inspectToken(tokenInput, takeoverWebhook, signal) {
    const token = requireToken(tokenInput);
    const identity = normalizeBotIdentity(await telegramCall(token, 'getMe', {}, { signal }));
    let webhook = await telegramCall(token, 'getWebhookInfo', {}, { signal });
    const webhookUrl = safeText(webhook?.url, 2048) ?? '';
    if (webhookUrl && !takeoverWebhook) {
      throw new TelegramServiceError(
        409,
        'telegram_webhook_active',
        'Telegram bot has a webhook; explicitly approve long-polling takeover',
      );
    }
    if (webhookUrl) {
      await telegramCall(token, 'deleteWebhook', { drop_pending_updates: false }, { signal });
      webhook = await telegramCall(token, 'getWebhookInfo', {}, { signal });
      if (safeText(webhook?.url, 2048)) {
        throw new TelegramServiceError(409, 'telegram_webhook_active', 'Telegram webhook is still active');
      }
    }
    return { token, ...identity };
  }

  async function registerBot({
    email: emailInput,
    token: tokenInput, // public-artifact-guard: allow text-secret -- runtime argument alias, not a literal credential
    label: labelInput,
    takeoverWebhook = false,
    signal,
  } = {}) {
    const email = normalizeEmail(emailInput);
    const inspected = await inspectToken(tokenInput, takeoverWebhook === true, signal);
    const label = normalizeLabel(
      labelInput,
      inspected.username ? `@${inspected.username}` : inspected.firstName ?? `Telegram bot ${inspected.id}`,
    );
    return mutate(async (draft) => {
      if (draft.bots[inspected.id]) {
        throw new TelegramServiceError(409, 'bot_exists', 'Telegram bot is already registered');
      }
      if (Object.keys(draft.bots).length >= MAX_BOTS) {
        throw new TelegramServiceError(409, 'bot_limit', `at most ${MAX_BOTS} Telegram bots may be registered`);
      }
      const at = timestamp(now());
      const bot = {
        id: inspected.id,
        ownerEmail: email,
        label,
        username: inspected.username,
        firstName: inspected.firstName,
        enabled: true,
        token: inspected.token, // public-artifact-guard: allow text-secret -- validated runtime token persistence, not a literal credential
        tokenFingerprint: tokenFingerprint(inspected.token),
        projects: [],
        nextUpdateId: 0,
        processedUpdateIds: [],
        createdAt: at,
        updatedAt: at,
        lastPollAt: null,
        lastUpdateAt: null,
        lastDeliveryAt: null,
        lastError: null,
      };
      draft.bots[bot.id] = bot;
      return botView(bot);
    });
  }

  async function rotateBotToken({ email, botId, token, takeoverWebhook = false, signal } = {}) {
    const managed = await requireManagedBot(email, botId);
    const inspected = await inspectToken(token, takeoverWebhook === true, signal);
    if (inspected.id !== managed.botId) {
      throw new TelegramServiceError(409, 'bot_identity_mismatch', 'new token belongs to a different Telegram bot');
    }
    return mutate((draft) => {
      const bot = draft.bots[managed.botId];
      if (!bot) throw new TelegramServiceError(404, 'bot_not_found', 'Telegram bot not found');
      bot.token = inspected.token;
      bot.tokenFingerprint = tokenFingerprint(inspected.token);
      bot.username = inspected.username;
      bot.firstName = inspected.firstName;
      bot.updatedAt = timestamp(now());
      bot.lastError = null;
      return botView(bot);
    });
  }

  async function removeBot({ email, botId } = {}) {
    const managed = await requireManagedBot(email, botId);
    return mutate((draft) => {
      if (!draft.bots[managed.botId]) return noChange(false);
      delete draft.bots[managed.botId];
      for (const [id, request] of Object.entries(draft.authorizationRequests)) {
        if (request.botId === managed.botId) delete draft.authorizationRequests[id];
      }
      for (const [id, delivery] of Object.entries(draft.outbox)) {
        if (delivery.botId === managed.botId) delete draft.outbox[id];
      }
      return true;
    });
  }

  async function setBotEnabled({ email, botId, enabled } = {}) {
    if (typeof enabled !== 'boolean') {
      throw new TelegramServiceError(400, 'invalid_enabled', 'enabled must be a boolean');
    }
    const managed = await requireManagedBot(email, botId);
    return mutate((draft) => {
      const bot = draft.bots[managed.botId];
      if (bot.enabled === enabled) return noChange(botView(bot));
      bot.enabled = enabled;
      bot.updatedAt = timestamp(now());
      if (enabled) bot.lastError = null;
      return botView(bot);
    });
  }

  async function setBotLabel({ email, botId, label: labelInput } = {}) {
    const label = normalizeLabel(labelInput);
    if (!label) {
      throw new TelegramServiceError(400, 'invalid_bot_label', 'bot label is required');
    }
    const managed = await requireManagedBot(email, botId);
    return mutate((draft) => {
      const bot = draft.bots[managed.botId];
      if (!bot) throw new TelegramServiceError(404, 'bot_not_found', 'Telegram bot not found');
      if (bot.label === label) return noChange(botView(bot));
      bot.label = label;
      bot.updatedAt = timestamp(now());
      return botView(bot);
    });
  }

  async function coordinatorHasProject(repoId) {
    if (typeof coordinator?.hasProject === 'function') {
      return Boolean(await coordinator.hasProject(repoId));
    }
    if (typeof coordinator?.listProjects === 'function') {
      const projects = await coordinator.listProjects();
      return Array.isArray(projects) && projects.some((project) => {
        const candidate = typeof project === 'string' ? project : project?.repo_id ?? project?.id;
        return candidate === repoId;
      });
    }
    throw new TelegramServiceError(503, 'coordinator_unavailable', 'coordinator project lookup is unavailable');
  }

  async function assignProject({ email, botId, repoId: repoIdInput, assigned = true } = {}) {
    if (typeof assigned !== 'boolean') {
      throw new TelegramServiceError(400, 'invalid_assignment', 'assigned must be a boolean');
    }
    const repoId = requireRepoId(repoIdInput);
    const managed = await requireManagedBot(email, botId);
    if (assigned && !(await coordinatorHasProject(repoId))) {
      throw new TelegramServiceError(404, 'project_not_found', 'coordinator repository not found');
    }
    return mutate((draft) => {
      const bot = draft.bots[managed.botId];
      const projects = new Set(bot.projects);
      if (assigned) projects.add(repoId);
      else projects.delete(repoId);
      const next = [...projects].sort();
      if (JSON.stringify(next) === JSON.stringify(bot.projects)) return noChange(botView(bot));
      bot.projects = next;
      bot.updatedAt = timestamp(now());
      if (!assigned) {
        for (const delivery of Object.values(draft.outbox)) {
          if (
            delivery.kind === 'event'
            && delivery.botId === bot.id
            && delivery.repoId === repoId
            && ['pending', 'retry'].includes(delivery.status)
          ) delivery.status = 'cancelled';
        }
      }
      return botView(bot);
    });
  }

  async function setProjects({ email, botId, repoIds } = {}) {
    if (!Array.isArray(repoIds) || repoIds.length > 500) {
      throw new TelegramServiceError(400, 'invalid_projects', 'repoIds must be an array of at most 500 items');
    }
    const normalized = repoIds.map(requireRepoId);
    if (new Set(normalized).size !== normalized.length) {
      throw new TelegramServiceError(400, 'invalid_projects', 'repoIds must not contain duplicates');
    }
    const managed = await requireManagedBot(email, botId);
    const existence = await Promise.all(normalized.map((repoId) => coordinatorHasProject(repoId)));
    if (existence.some((value) => !value)) {
      throw new TelegramServiceError(404, 'project_not_found', 'one or more coordinator repositories were not found');
    }
    const projects = [...normalized].sort();
    return mutate((draft) => {
      const bot = draft.bots[managed.botId];
      if (!bot) throw new TelegramServiceError(404, 'bot_not_found', 'Telegram bot not found');
      if (JSON.stringify(bot.projects) === JSON.stringify(projects)) return noChange(botView(bot));
      const removed = new Set(bot.projects.filter((repoId) => !projects.includes(repoId)));
      bot.projects = projects;
      bot.updatedAt = timestamp(now());
      if (removed.size) {
        for (const delivery of Object.values(draft.outbox)) {
          if (
            delivery.kind === 'event'
            && delivery.botId === bot.id
            && removed.has(delivery.repoId)
            && ['pending', 'retry'].includes(delivery.status)
          ) delivery.status = 'cancelled';
        }
      }
      return botView(bot);
    });
  }

  async function listBots({ email: emailInput } = {}) {
    await ensureLoaded();
    await mutationChain;
    const email = normalizeEmail(emailInput);
    const admin = await actorIsAdmin(email);
    return Object.values(state.bots)
      .filter((bot) => admin || bot.ownerEmail === email)
      .sort((a, b) => a.id.localeCompare(b.id))
      .map(botView);
  }

  function requestForUser(draft, botId, telegramUserId) {
    return Object.values(draft.authorizationRequests)
      .find((request) => request.botId === botId && request.telegramUserId === telegramUserId) ?? null;
  }

  function ensureOutboxCapacity(draft, needed = 1) {
    let count = Object.keys(draft.outbox).length;
    if (count + needed <= maxOutbox) return;
    const terminal = Object.values(draft.outbox)
      .filter((delivery) => ['delivered', 'dead', 'cancelled'].includes(delivery.status))
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
    for (const delivery of terminal) {
      if (count + needed <= maxOutbox) break;
      delete draft.outbox[delivery.id];
      count -= 1;
    }
    if (count + needed > maxOutbox) {
      throw new TelegramServiceError(503, 'outbox_full', 'Telegram delivery outbox is full');
    }
  }

  function createSystemDelivery(draft, request, text, reason) {
    ensureOutboxCapacity(draft);
    const id = `system-${stableId(request.id, reason, randomUUID())}`;
    draft.outbox[id] = {
      id,
      kind: 'system',
      botId: request.botId,
      authorizationRequestId: request.id,
      telegramUserId: request.telegramUserId,
      chatId: request.chatId,
      repoId: null,
      event: null,
      text: text.slice(0, MAX_TELEGRAM_MESSAGE),
      status: 'pending',
      attempts: 0,
      nextAttemptAt: now(),
      claimId: null,
      claimedAt: null,
      createdAt: timestamp(now()),
      deliveredAt: null,
      lastError: null,
    };
  }

  function processStartUpdate(draft, bot, update) {
    const message = update?.message;
    if (!message || message.chat?.type !== 'private' || message.from?.is_bot === true) return false;
    const text = typeof message.text === 'string' ? message.text : '';
    const match = text.match(START_COMMAND_RE);
    if (!match) return false;
    if (match[1] && bot.username && match[1].toLowerCase() !== bot.username.toLowerCase()) return false;
    const telegramUserId = requireTelegramId(message.from?.id, 'Telegram user ID');
    const chatId = requireTelegramId(message.chat?.id, 'Telegram chat ID');
    let request = requestForUser(draft, bot.id, telegramUserId);
    const at = timestamp(now());
    if (!request) {
      if (Object.keys(draft.authorizationRequests).length >= MAX_AUTHORIZATIONS) {
        throw new TelegramServiceError(503, 'authorization_limit', 'Telegram authorization queue is full');
      }
      request = {
        id: randomUUID(),
        botId: bot.id,
        telegramUserId,
        chatId,
        username: safeUsername(message.from?.username),
        firstName: safeText(message.from?.first_name, 128),
        lastName: safeText(message.from?.last_name, 128),
        languageCode: safeText(message.from?.language_code, 32),
        status: 'pending',
        requestedAt: at,
        decidedAt: null,
        decidedBy: null,
        approvalCursor: null,
      };
      draft.authorizationRequests[request.id] = request;
    } else {
      request.chatId = chatId;
      request.username = safeUsername(message.from?.username);
      request.firstName = safeText(message.from?.first_name, 128);
      request.lastName = safeText(message.from?.last_name, 128);
      request.languageCode = safeText(message.from?.language_code, 32);
      request.requestedAt = at;
      if (request.status !== 'approved') {
        request.status = 'pending';
        request.decidedAt = null;
        request.decidedBy = null;
        request.approvalCursor = null;
      }
    }
    createSystemDelivery(
      draft,
      request,
      request.status === 'approved'
        ? 'You are already authorized for this DevOps Console bot.'
        : 'Your authorization request is waiting for a Console administrator.',
      request.status === 'approved' ? 'already-approved' : 'request-received',
    );
    return true;
  }

  async function recordBotError(botId, error, { disable = false } = {}) {
    const sanitized = redactString(error?.message ?? error, knownTokens());
    return mutate((draft) => {
      const bot = draft.bots[botId];
      if (!bot) return noChange(false);
      bot.lastError = sanitized.slice(0, 512);
      bot.updatedAt = timestamp(now());
      if (disable) bot.enabled = false;
      return true;
    });
  }

  async function processBotUpdates(botIdInput, { signal } = {}) {
    await ensureLoaded();
    await mutationChain;
    const botId = requireTelegramId(botIdInput, 'bot ID');
    const snapshot = state.bots[botId];
    if (!snapshot || !snapshot.enabled) return { updates: 0, requests: 0, nextUpdateId: snapshot?.nextUpdateId ?? 0 };
    const token = snapshot.token;
    let updates;
    try {
      updates = await telegramCall(token, 'getUpdates', {
        offset: snapshot.nextUpdateId,
        limit: 100,
        timeout: pollTimeoutSeconds,
        allowed_updates: ['message'],
      }, {
        signal,
        timeoutMs: Math.max(requestTimeoutMs, (pollTimeoutSeconds + 5) * 1_000),
      });
    } catch (error) {
      if (isAbortError(error) && signal?.aborted) throw error;
      const safe = telegramError(error, [token]);
      await recordBotError(botId, safe, { disable: safe.status === 401 });
      throw safe;
    }
    if (!Array.isArray(updates)) {
      const error = new TelegramServiceError(502, 'invalid_telegram_response', 'Telegram getUpdates result is invalid');
      await recordBotError(botId, error);
      throw error;
    }
    const ordered = [...updates].sort((a, b) => Number(a?.update_id) - Number(b?.update_id));
    return mutate((draft) => {
      const bot = draft.bots[botId];
      if (!bot || !bot.enabled || bot.tokenFingerprint !== tokenFingerprint(token)) {
        return noChange({ updates: 0, requests: 0, nextUpdateId: bot?.nextUpdateId ?? 0 });
      }
      const processed = new Set(bot.processedUpdateIds);
      let accepted = 0;
      let requests = 0;
      let nextUpdateId = bot.nextUpdateId;
      for (const update of ordered) {
        const updateId = update?.update_id;
        if (!Number.isSafeInteger(updateId) || updateId < 0) {
          throw new TelegramServiceError(502, 'invalid_telegram_response', 'Telegram update_id is invalid');
        }
        if (updateId < nextUpdateId || processed.has(updateId)) continue;
        if (processStartUpdate(draft, bot, update)) requests += 1;
        processed.add(updateId);
        nextUpdateId = Math.max(nextUpdateId, updateId + 1);
        accepted += 1;
      }
      bot.nextUpdateId = nextUpdateId;
      bot.processedUpdateIds = [...processed].sort((a, b) => a - b).slice(-MAX_PROCESSED_UPDATES);
      bot.lastPollAt = timestamp(now());
      if (accepted) bot.lastUpdateAt = timestamp(now());
      bot.lastError = null;
      bot.updatedAt = timestamp(now());
      return { updates: accepted, requests, nextUpdateId };
    });
  }

  async function listAuthorizationQueue({ email: emailInput, botId: botIdInput = null, status = 'pending' } = {}) {
    await ensureLoaded();
    await mutationChain;
    const email = normalizeEmail(emailInput);
    const admin = await actorIsAdmin(email);
    const botId = botIdInput === null ? null : requireTelegramId(botIdInput, 'bot ID');
    if (botId) {
      const bot = state.bots[botId];
      if (!bot) throw new TelegramServiceError(404, 'bot_not_found', 'Telegram bot not found');
      if (!admin && bot.ownerEmail !== email) {
        throw new TelegramServiceError(403, 'bot_forbidden', 'Telegram bot belongs to another Console user');
      }
    }
    if (status !== null && !['pending', 'approved', 'denied', 'revoked'].includes(status)) {
      throw new TelegramServiceError(400, 'invalid_status', 'authorization status is invalid');
    }
    return Object.values(state.authorizationRequests)
      .filter((request) => {
        const bot = state.bots[request.botId];
        return bot && (admin || bot.ownerEmail === email) && (!botId || request.botId === botId)
          && (status === null || request.status === status);
      })
      .sort((a, b) => b.requestedAt.localeCompare(a.requestedAt) || a.id.localeCompare(b.id))
      .map((request) => requestView(request, state.bots[request.botId]));
  }

  async function observeCoordinator() {
    if (typeof coordinator?.observeHost !== 'function') return null;
    try {
      return await coordinator.observeHost();
    } catch (error) {
      throw new TelegramServiceError(
        502,
        'coordinator_observation_failed',
        `coordinator observation failed: ${redactString(error?.message ?? error, knownTokens())}`,
      );
    }
  }

  async function drainEventBacklog({ maxPages = 10_000 } = {}) {
    for (let pageNumber = 0; pageNumber < maxPages; pageNumber += 1) {
      const result = await ingestEvents();
      if (!result.hasMore) return result;
    }
    throw new TelegramServiceError(
      503,
      'event_backlog_too_large',
      'coordinator event backlog could not be drained before authorization',
    );
  }

  async function decideAuthorization({ email: emailInput, requestId, decision } = {}) {
    await ensureLoaded();
    await mutationChain;
    const email = normalizeEmail(emailInput);
    if (typeof requestId !== 'string' || !requestId) {
      throw new TelegramServiceError(400, 'invalid_request_id', 'authorization request ID is required');
    }
    if (!['approve', 'deny'].includes(decision)) {
      throw new TelegramServiceError(400, 'invalid_decision', "decision must be 'approve' or 'deny'");
    }
    const existing = state.authorizationRequests[requestId];
    if (!existing) throw new TelegramServiceError(404, 'request_not_found', 'authorization request not found');
    const managed = await requireManagedBot(email, existing.botId);
    if (decision === 'approve') {
      // Keep the requester pending while every currently visible event page is
      // durably fanned out. Once approved, reads continue strictly after the
      // persisted opaque cursor, so a newly approved user does not receive the
      // existing backlog.
      await observeCoordinator();
      await drainEventBacklog();
      await mutationChain;
    }
    const approvalCursor = decision === 'approve' ? state.eventCursor : null;
    return mutate((draft) => {
      const request = draft.authorizationRequests[requestId];
      if (!request) throw new TelegramServiceError(404, 'request_not_found', 'authorization request not found');
      const at = timestamp(now());
      request.status = decision === 'approve' ? 'approved' : 'denied';
      request.decidedAt = at;
      request.decidedBy = managed.email;
      request.approvalCursor = approvalCursor;
      for (const delivery of Object.values(draft.outbox)) {
        if (
          delivery.kind === 'event'
          && delivery.authorizationRequestId === request.id
          && ['pending', 'retry'].includes(delivery.status)
        ) delivery.status = 'cancelled';
      }
      createSystemDelivery(
        draft,
        request,
        decision === 'approve'
          ? 'Your Telegram account was approved for this DevOps Console bot.'
          : 'Your Telegram authorization request was denied.',
        decision,
      );
      return requestView(request, draft.bots[request.botId]);
    });
  }

  async function revokeAuthorization({ email: emailInput, requestId } = {}) {
    await ensureLoaded();
    await mutationChain;
    const request = state.authorizationRequests[requestId];
    if (!request) throw new TelegramServiceError(404, 'request_not_found', 'authorization request not found');
    const managed = await requireManagedBot(emailInput, request.botId);
    return mutate((draft) => {
      const next = draft.authorizationRequests[requestId];
      next.status = 'revoked';
      next.decidedAt = timestamp(now());
      next.decidedBy = managed.email;
      next.approvalCursor = null;
      for (const delivery of Object.values(draft.outbox)) {
        if (
          delivery.kind === 'event'
          && delivery.authorizationRequestId === requestId
          && ['pending', 'retry'].includes(delivery.status)
        ) delivery.status = 'cancelled';
      }
      return requestView(next, draft.bots[next.botId]);
    });
  }

  async function ingestEvents({ limit = DEFAULT_EVENT_LIMIT } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
      throw new TelegramServiceError(400, 'invalid_limit', 'event limit must be between 1 and 500');
    }
    await ensureLoaded();
    const operation = ingestionChain.catch(() => {}).then(async () => {
      await mutationChain;
      if (typeof coordinator?.readEvents !== 'function') {
        throw new TelegramServiceError(503, 'coordinator_unavailable', 'coordinator event feed is unavailable');
      }
      const after = state.eventCursor;
      const page = await coordinator.readEvents({ after, limit });
      if (
        !page || typeof page !== 'object' || Array.isArray(page)
        || !Array.isArray(page.events)
        || typeof page.has_more !== 'boolean'
        || !Object.hasOwn(page, 'next_cursor')
      ) {
        throw new TelegramServiceError(502, 'invalid_event_feed', 'coordinator event page is invalid');
      }
      const events = page.events.map(normalizeEvent);
      if (new Set(events.map((event) => event.event_id)).size !== events.length) {
        throw new TelegramServiceError(502, 'invalid_event_feed', 'coordinator event page contains duplicate IDs');
      }
      const nextCursor = requireCursor(page.next_cursor);
      if (
        (events.length && nextCursor === after)
        || (!events.length && nextCursor !== after)
        || (page.has_more && !events.length)
      ) {
        throw new TelegramServiceError(502, 'invalid_event_feed', 'coordinator event cursor did not match its page');
      }
      const eventRepoIds = [...new Set(
        events.map((event) => event.repo_id).filter((repoId) => repoId !== null),
      )];
      const currentProjects = await Promise.all(
        eventRepoIds.map(async (repoId) => [repoId, await coordinatorHasProject(repoId)]),
      );
      const currentRepoIds = new Set(
        currentProjects.filter(([, exists]) => exists).map(([repoId]) => repoId),
      );
      return mutate((draft) => {
        if (draft.eventCursor !== after) {
          return noChange({ events: 0, deliveries: 0, cursor: draft.eventCursor, hasMore: true });
        }
        if (!events.length && nextCursor === after) {
          return noChange({ events: 0, deliveries: 0, cursor: after, hasMore: false });
        }
        let deliveries = 0;
        for (const event of events) {
          if (event.repo_id === null || !currentRepoIds.has(event.repo_id)) continue;
          for (const bot of Object.values(draft.bots)) {
            if (!bot.enabled || !bot.projects.includes(event.repo_id)) continue;
            for (const request of Object.values(draft.authorizationRequests)) {
              if (
                request.botId !== bot.id
                || request.status !== 'approved'
              ) continue;
              const id = `event-${stableId(event.event_id, bot.id, request.telegramUserId)}`;
              if (draft.outbox[id]) continue;
              ensureOutboxCapacity(draft);
              draft.outbox[id] = {
                id,
                kind: 'event',
                botId: bot.id,
                authorizationRequestId: request.id,
                telegramUserId: request.telegramUserId,
                chatId: request.chatId,
                repoId: event.repo_id,
                event,
                text: formatEventMessage(event),
                status: 'pending',
                attempts: 0,
                nextAttemptAt: now(),
                claimId: null,
                claimedAt: null,
                createdAt: timestamp(now()),
                deliveredAt: null,
                lastError: null,
              };
              deliveries += 1;
            }
          }
        }
        draft.eventCursor = nextCursor;
        return { events: events.length, deliveries, cursor: nextCursor, hasMore: page.has_more };
      });
    });
    ingestionChain = operation.then(() => undefined, () => undefined);
    return operation;
  }

  function deliveryAllowed(draft, delivery) {
    const bot = draft.bots[delivery.botId];
    if (!bot?.enabled) return false;
    const request = draft.authorizationRequests[delivery.authorizationRequestId];
    if (!request || request.chatId !== delivery.chatId) return false;
    if (delivery.kind === 'system') return true;
    return request.status === 'approved' && bot.projects.includes(delivery.repoId);
  }

  async function claimDelivery() {
    return mutate((draft) => {
      const at = now();
      const candidates = Object.values(draft.outbox)
        .filter((delivery) => ['pending', 'retry'].includes(delivery.status) && delivery.nextAttemptAt <= at)
        .sort((a, b) => a.nextAttemptAt - b.nextAttemptAt || a.createdAt.localeCompare(b.createdAt));
      for (const delivery of candidates) {
        if (!deliveryAllowed(draft, delivery)) {
          delivery.status = 'cancelled';
          continue;
        }
        if ((chatNextSendAt.get(delivery.chatId) ?? 0) > at) continue;
        const bot = draft.bots[delivery.botId];
        delivery.status = 'sending';
        delivery.attempts += 1;
        delivery.claimId = randomUUID();
        delivery.claimedAt = at;
        return {
          id: delivery.id,
          claimId: delivery.claimId,
          botId: bot.id,
          token: bot.token, // public-artifact-guard: allow text-secret -- private runtime delivery plumbing, not a literal credential
          chatId: delivery.chatId,
          text: delivery.text,
        };
      }
      if (candidates.some((delivery) => delivery.status === 'cancelled')) return null;
      return noChange(null);
    });
  }

  async function finishDelivery(claim, result) {
    return mutate((draft) => {
      const delivery = draft.outbox[claim.id];
      if (!delivery || delivery.status !== 'sending' || delivery.claimId !== claim.claimId) {
        return noChange(false);
      }
      const bot = draft.bots[claim.botId];
      delivery.claimId = null;
      delivery.claimedAt = null;
      if (result.ok) {
        delivery.status = 'delivered';
        delivery.deliveredAt = timestamp(now());
        delivery.lastError = null;
        if (bot) {
          bot.lastDeliveryAt = timestamp(now());
          bot.lastError = null;
          bot.updatedAt = timestamp(now());
        }
        return true;
      }
      const error = telegramError(result.error, bot ? [bot.token] : []);
      const message = redactString(error.message, bot ? [bot.token] : []).slice(0, 512);
      delivery.lastError = message;
      if (bot) {
        bot.lastError = message;
        bot.updatedAt = timestamp(now());
      }
      if (error.status === 401) {
        delivery.status = 'dead';
        if (bot) bot.enabled = false;
      } else if (error.status === 403) {
        delivery.status = 'cancelled';
        const request = draft.authorizationRequests[delivery.authorizationRequestId];
        if (request) {
          request.status = 'revoked';
          request.decidedAt = timestamp(now());
          request.decidedBy = 'telegram:403';
          request.approvalCursor = null;
        }
        for (const other of Object.values(draft.outbox)) {
          if (
            other.kind === 'event'
            && other.authorizationRequestId === delivery.authorizationRequestId
            && ['pending', 'retry'].includes(other.status)
          ) other.status = 'cancelled';
        }
      } else if (
        (error.status >= 400 && error.status < 500 && error.status !== 429)
        || delivery.attempts >= MAX_DELIVERY_ATTEMPTS
      ) {
        delivery.status = 'dead';
      } else {
        const retryMs = error.status === 429 && error.retryAfter !== null
          ? error.retryAfter * 1_000
          : Math.min(5 * 60_000, 1_000 * (2 ** Math.max(0, delivery.attempts - 1)));
        delivery.status = 'retry';
        delivery.nextAttemptAt = now() + retryMs;
      }
      return false;
    });
  }

  async function deliverDue({ limit = DEFAULT_DELIVERY_LIMIT, signal } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new TelegramServiceError(400, 'invalid_limit', 'delivery limit must be between 1 and 1000');
    }
    let attempted = 0;
    let delivered = 0;
    let failed = 0;
    while (attempted < limit && !signal?.aborted) {
      const claim = await claimDelivery();
      if (!claim) break;
      attempted += 1;
      try {
        await telegramCall(claim.token, 'sendMessage', {
          chat_id: claim.chatId,
          text: claim.text,
        }, { signal });
        chatNextSendAt.set(claim.chatId, now() + 1_000);
        await finishDelivery(claim, { ok: true });
        delivered += 1;
      } catch (error) {
        if (isAbortError(error) && signal?.aborted) {
          await finishDelivery(claim, {
            ok: false,
            error: new TelegramServiceError(503, 'delivery_interrupted', 'Telegram delivery interrupted'),
          });
          throw error;
        }
        await finishDelivery(claim, { ok: false, error });
        failed += 1;
      }
    }
    return { attempted, delivered, failed };
  }

  async function status({ email: emailInput } = {}) {
    const bots = await listBots({ email: emailInput });
    await mutationChain;
    const ids = new Set(bots.map((bot) => bot.id));
    const authorizations = Object.values(state.authorizationRequests).filter((request) => ids.has(request.botId));
    const deliveries = Object.values(state.outbox).filter((delivery) => ids.has(delivery.botId));
    return {
      running: Boolean(controller),
      eventCursor: state.eventCursor,
      bots,
      authorizationCounts: Object.fromEntries(
        ['pending', 'approved', 'denied', 'revoked'].map((value) => [
          value,
          authorizations.filter((request) => request.status === value).length,
        ]),
      ),
      deliveryCounts: Object.fromEntries(
        ['pending', 'sending', 'retry', 'delivered', 'dead', 'cancelled'].map((value) => [
          value,
          deliveries.filter((delivery) => delivery.status === value).length,
        ]),
      ),
    };
  }

  async function hasEligibleEventRecipients() {
    await ensureLoaded();
    await mutationChain;
    const approvedBots = new Set(
      Object.values(state.authorizationRequests)
        .filter((request) => request.status === 'approved')
        .map((request) => request.botId),
    );
    return Object.values(state.bots).some(
      (bot) => bot.enabled && bot.projects.length > 0 && approvedBots.has(bot.id),
    );
  }

  async function pollBotLoop(botId, signal) {
    while (!signal.aborted) {
      try {
        const result = await processBotUpdates(botId, { signal });
        if (!state.bots[botId]?.enabled) return;
        if (!result.updates) await sleep(Math.max(50, pollRefreshMs), signal);
      } catch (error) {
        if (isAbortError(error) && signal.aborted) return;
        logFailure('Telegram polling failed', error, { botId });
        await sleep(Math.max(250, pollRefreshMs), signal).catch(() => {});
      }
    }
  }

  async function supervisePollers(signal) {
    while (!signal.aborted) {
      await ensureLoaded();
      await mutationChain;
      for (const bot of Object.values(state.bots)) {
        if (!bot.enabled || pollers.has(bot.id)) continue;
        const task = pollBotLoop(bot.id, signal)
          .catch((error) => {
            if (!isAbortError(error)) logFailure('Telegram poller stopped', error, { botId: bot.id });
          })
          .finally(() => {
            if (pollers.get(bot.id) === task) pollers.delete(bot.id);
          });
        pollers.set(bot.id, task);
      }
      await sleep(Math.max(50, pollRefreshMs), signal);
    }
  }

  async function dispatchLoop(signal) {
    while (!signal.aborted) {
      if (await hasEligibleEventRecipients()) {
        if (now() >= nextObservationAt) {
          try {
            await observeCoordinator();
          } catch (error) {
            if (isAbortError(error) && signal.aborted) return;
            logFailure('Telegram coordinator observation failed', error);
          } finally {
            nextObservationAt = now() + Math.max(250, observationIntervalMs);
          }
        }
        try {
          let page;
          do {
            page = await ingestEvents();
          } while (page.hasMore && !signal.aborted);
        } catch (error) {
          if (isAbortError(error) && signal.aborted) return;
          logFailure('Telegram event ingestion failed', error);
        }
      }
      try {
        await deliverDue({ signal });
      } catch (error) {
        if (isAbortError(error) && signal.aborted) return;
        logFailure('Telegram delivery pass failed', error);
      }
      await sleep(Math.max(50, dispatcherIntervalMs), signal);
    }
  }

  async function start() {
    await ensureLoaded();
    if (controller) return false;
    nextObservationAt = 0;
    controller = new AbortController();
    const signal = controller.signal;
    supervisorPromise = supervisePollers(signal).catch((error) => {
      if (!isAbortError(error)) logFailure('Telegram poll supervisor stopped', error);
    });
    dispatcherPromise = dispatchLoop(signal).catch((error) => {
      if (!isAbortError(error)) logFailure('Telegram dispatcher stopped', error);
    });
    return true;
  }

  async function stop() {
    if (!controller) return false;
    const active = controller;
    controller = null;
    active.abort(new DOMException('Telegram service stopped', 'AbortError'));
    await Promise.allSettled([supervisorPromise, dispatcherPromise, ...pollers.values()]);
    supervisorPromise = null;
    dispatcherPromise = null;
    pollers.clear();
    return true;
  }

  return {
    load,
    start,
    stop,
    status,
    listBots,
    registerBot,
    rotateBotToken,
    removeBot,
    setBotEnabled,
    setBotLabel,
    assignProject,
    setProjects,
    processBotUpdates,
    listAuthorizationQueue,
    decideAuthorization,
    revokeAuthorization,
    ingestEvents,
    deliverDue,
  };
}
