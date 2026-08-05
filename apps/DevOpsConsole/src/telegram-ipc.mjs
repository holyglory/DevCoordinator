// Bounded local Console -> notification-worker IPC. Every local account is the
// same developer, so filesystem metadata is not an authorization boundary.
// Request IDs still bind replies and the protocol remains strictly bounded.

import crypto from 'node:crypto';
import { promises as fsp } from 'node:fs';
import net from 'node:net';
import path from 'node:path';

import { TelegramServiceError } from './telegram.mjs';

const VERSION = 1;
const MAX_FRAME_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 35_000;
const OPERATIONS = new Map([
  ['status', { required: [], optional: [] }],
  ['listBots', { required: ['email'], optional: [] }],
  ['registerBot', { required: ['email', 'token'], optional: ['label', 'takeoverWebhook'] }],
  ['removeBot', { required: ['email', 'botId'], optional: [] }],
  ['setProjects', { required: ['email', 'botId', 'repoIds'], optional: [] }],
  ['listAuthorizationQueue', { required: ['email'], optional: ['botId', 'status'] }],
  ['decideAuthorization', { required: ['email', 'requestId', 'decision'], optional: [] }],
]);

function encodeFrame(value) {
  let payload;
  try {
    payload = Buffer.from(JSON.stringify(value), 'utf8');
  } catch (error) {
    throw new Error('notification IPC value is not JSON', { cause: error });
  }
  if (!payload.length || payload.length > MAX_FRAME_BYTES) {
    throw new Error('notification IPC frame exceeds its bound');
  }
  const frame = Buffer.allocUnsafe(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

function decodePayload(payload) {
  try {
    const value = JSON.parse(payload.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('not an object');
    }
    return value;
  } catch (error) {
    throw new Error('notification IPC frame is invalid JSON', { cause: error });
  }
}

function exactArguments(operation, value) {
  const contract = OPERATIONS.get(operation);
  if (!contract || !value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('notification IPC operation is invalid');
  }
  const keys = Object.keys(value);
  if (
    contract.required.some((key) => !keys.includes(key))
    || keys.some((key) => !contract.required.includes(key) && !contract.optional.includes(key))
  ) throw new Error('notification IPC operation arguments are invalid');
  return value;
}

function publicError(error) {
  if (error instanceof TelegramServiceError) {
    const code = typeof error.code === 'string' && /^[a-z][a-z0-9_]{0,127}$/.test(error.code)
      ? error.code
      : 'notification_error';
    return {
      status: error.status,
      code,
      message: String(error.message || 'Telegram operation failed').slice(0, 512),
      retryAfter: error.retryAfter ?? null,
    };
  }
  return {
    status: 500,
    code: 'notification_ipc_error',
    message: 'Notification worker rejected the request',
    retryAfter: null,
  };
}

async function receiveFrame(socket, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let expected = null;
    let timer = null;
    const fail = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', fail);
      socket.off('end', onEnd);
    };
    const onEnd = () => fail(new Error('notification IPC connection closed mid-frame'));
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > MAX_FRAME_BYTES + 4) return fail(new Error('notification IPC frame exceeds its bound'));
      if (expected === null && buffer.length >= 4) {
        expected = buffer.readUInt32BE(0);
        if (expected < 1 || expected > MAX_FRAME_BYTES) return fail(new Error('notification IPC frame size is invalid'));
      }
      if (expected !== null && buffer.length === expected + 4) {
        const payload = buffer.subarray(4);
        cleanup();
        resolve(decodePayload(payload));
      } else if (expected !== null && buffer.length > expected + 4) {
        fail(new Error('notification IPC sent trailing data'));
      }
    };
    timer = setTimeout(
      () => fail(new Error('notification IPC request timed out')),
      timeoutMs,
    );
    timer.unref?.();
    socket.on('data', onData);
    socket.once('error', fail);
    socket.once('end', onEnd);
  });
}

async function validateSocketPath(socketPath) {
  if (typeof socketPath !== 'string' || !path.isAbsolute(socketPath) || socketPath.length > 100) {
    throw new Error('notification IPC socket path is invalid');
  }
  const parent = path.dirname(socketPath);
  const parentInfo = await fsp.lstat(parent);
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) {
    throw new Error('notification IPC socket parent is unsafe');
  }
}

async function prepareSocket(socketPath) {
  await validateSocketPath(socketPath);
  try {
    const existing = await fsp.lstat(socketPath);
    if (
      !existing.isSocket()
      || existing.isSymbolicLink()
    ) throw new Error('notification IPC socket path is unsafe');
    await fsp.unlink(socketPath);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

export async function validateTelegramIpcConfig({ socketPath } = {}) {
  await validateSocketPath(socketPath);
  return true;
}

export function createTelegramIpcServer({
  socketPath,
  service,
  log = null,
  onFatal = null,
} = {}) {
  if (!service || typeof service !== 'object') throw new TypeError('notification IPC service is required');
  let server = null;
  let socketIdentity = null;

  async function handle(socket) {
    let requestId = null;
    try {
      const request = await receiveFrame(socket);
      if (
        request.version !== VERSION
        || typeof request.requestId !== 'string'
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(request.requestId)
        || typeof request.operation !== 'string'
      ) throw new Error('notification IPC request identity is invalid');
      requestId = request.requestId;
      const args = exactArguments(request.operation, request.arguments);
      const method = service[request.operation];
      if (typeof method !== 'function') throw new Error('notification IPC operation is unavailable');
      const result = await method.call(service, args);
      socket.end(encodeFrame({ version: VERSION, requestId: request.requestId, ok: true, result }));
    } catch (error) {
      const response = {
        version: VERSION,
        requestId,
        ok: false,
        error: publicError(error),
      };
      try { socket.end(encodeFrame(response)); } catch { socket.destroy(); }
    }
  }

  async function start() {
    if (server) return false;
    await prepareSocket(socketPath);
    server = net.createServer((socket) => { void handle(socket); });
    server.on('error', (error) => {
      log?.error?.('notification IPC listener failed', { error: error.message });
      if (server?.listening) onFatal?.(error);
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, () => {
        server.off('error', reject);
        resolve();
      });
    });
    await fsp.chmod(socketPath, 0o666);
    const metadata = await fsp.lstat(socketPath);
    socketIdentity = { dev: metadata.dev, ino: metadata.ino };
    return true;
  }

  async function close() {
    if (!server) return false;
    const active = server;
    server = null;
    await new Promise((resolve) => active.close(resolve));
    try {
      const metadata = await fsp.lstat(socketPath);
      if (metadata.dev === socketIdentity?.dev && metadata.ino === socketIdentity?.ino) {
        await fsp.unlink(socketPath);
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    socketIdentity = null;
    return true;
  }

  return { start, close };
}

export function createTelegramIpcClient({ socketPath, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const call = async (operation, operationArguments = {}) => {
    if (!OPERATIONS.has(operation)) throw new Error('notification IPC operation is invalid');
    const requestId = crypto.randomUUID();
    const socket = net.createConnection(socketPath);
    const connected = new Promise((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    });
    try {
      await connected;
      socket.write(encodeFrame({
        version: VERSION,
        requestId,
        operation,
        arguments: operationArguments,
      }));
      const response = await receiveFrame(socket, { timeoutMs });
      if (
        response.version !== VERSION
        || response.requestId !== requestId
        || typeof response.ok !== 'boolean'
      ) {
        throw new Error('notification IPC response identity is invalid');
      }
      if (!response.ok) {
        const error = response.error ?? {};
        throw new TelegramServiceError(
          Number.isInteger(error.status) ? error.status : 503,
          typeof error.code === 'string' ? error.code : 'notification_unavailable',
          typeof error.message === 'string' ? error.message : 'Notification worker is unavailable',
          { retryAfter: error.retryAfter ?? null },
        );
      }
      return response.result;
    } catch (error) {
      if (error instanceof TelegramServiceError) throw error;
      throw new TelegramServiceError(503, 'notification_unavailable', 'Notification worker is unavailable');
    } finally {
      socket.destroy();
    }
  };

  return {
    ownsBackgroundLoops: false,
    load: async () => true,
    start: async () => false,
    stop: async () => false,
    status: () => call('status'),
    listBots: (operationArguments) => call('listBots', operationArguments),
    registerBot: (operationArguments) => call('registerBot', operationArguments),
    removeBot: (operationArguments) => call('removeBot', operationArguments),
    setProjects: (operationArguments) => call('setProjects', operationArguments),
    listAuthorizationQueue: (operationArguments) => call('listAuthorizationQueue', operationArguments),
    decideAuthorization: (operationArguments) => call('decideAuthorization', operationArguments),
  };
}

export const TELEGRAM_IPC_MAX_FRAME_BYTES = MAX_FRAME_BYTES;
