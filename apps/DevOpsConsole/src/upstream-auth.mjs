// Private, route-scoped credentials used only between the Console proxy and a
// loopback upstream. Browser/API route views expose metadata, never secrets.

import { promises as fsp } from 'node:fs';
import { randomUUID } from 'node:crypto';
import path from 'node:path';

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const TOKEN68_RE = /^[A-Za-z0-9._~+/-]+=*$/;
const MAX_SECRET_LENGTH = 8 * 1024;
const MAX_USERNAME_LENGTH = 256;

export class UpstreamAuthError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'UpstreamAuthError';
    this.status = status;
  }
}

function validateSlug(value) {
  const slug = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!SLUG_RE.test(slug)) {
    throw new UpstreamAuthError(400, 'route slug must be a valid lowercase DNS label');
  }
  return slug;
}

function requireSecret(value, { bearer = false } = {}) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new UpstreamAuthError(400, 'upstream credential secret is required');
  }
  if (value.length > MAX_SECRET_LENGTH) {
    throw new UpstreamAuthError(400, `upstream credential secret must be at most ${MAX_SECRET_LENGTH} characters`);
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    throw new UpstreamAuthError(400, 'upstream credential secret must not contain control characters');
  }
  if (bearer && !TOKEN68_RE.test(value)) {
    throw new UpstreamAuthError(400, 'bearer credential must use token68 characters only');
  }
  return value;
}

function normalizeDefinition(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new UpstreamAuthError(400, 'upstream credential must be an object');
  }
  if (value.scheme === 'bearer') {
    return { scheme: 'bearer', secret: requireSecret(value.secret, { bearer: true }) };
  }
  if (value.scheme === 'basic') {
    const username = typeof value.username === 'string' ? value.username : '';
    if (
      username.length === 0
      || username.length > MAX_USERNAME_LENGTH
      || username.includes(':')
      || /[\u0000-\u001f\u007f]/.test(username)
    ) {
      throw new UpstreamAuthError(
        400,
        `basic-auth username must be 1-${MAX_USERNAME_LENGTH} characters without colon or control characters`,
      );
    }
    return { scheme: 'basic', username, secret: requireSecret(value.secret) };
  }
  throw new UpstreamAuthError(400, "upstream credential scheme must be 'bearer' or 'basic'");
}

function descriptor(record) {
  return record ? { configured: true, scheme: record.scheme } : { configured: false };
}

export function createUpstreamAuthStore({ file, log } = {}) {
  if (typeof file !== 'string' || file === '') {
    throw new TypeError('createUpstreamAuthStore requires a state file path');
  }
  const clog = typeof log?.child === 'function' ? log.child({ mod: 'upstream-auth' }) : log;
  let records = new Map();
  let mutationChain = Promise.resolve();

  async function assertPrivateRegularFile() {
    const stat = await fsp.lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`upstream credential state must be a regular file: ${file}`);
    }
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
      throw new Error(`upstream credential state must be owned by the Console account: ${file}`);
    }
    if ((stat.mode & 0o077) !== 0) {
      throw new Error(`upstream credential state must not be group/world accessible: ${file}`);
    }
  }

  async function load() {
    try {
      await assertPrivateRegularFile();
    } catch (err) {
      if (err?.code === 'ENOENT') {
        records = new Map();
        return;
      }
      throw err;
    }

    let parsed;
    try {
      parsed = JSON.parse(await fsp.readFile(file, 'utf8'));
    } catch (err) {
      const backup = `${file}.corrupt-${Date.now()}`;
      await fsp.rename(file, backup).catch(() => {});
      records = new Map();
      clog?.error?.('upstream credential state invalid; preserved and disabled', { file, backup });
      return;
    }

    const validEnvelope = parsed
      && typeof parsed === 'object'
      && !Array.isArray(parsed)
      && parsed.version === 1
      && parsed.routes
      && typeof parsed.routes === 'object'
      && !Array.isArray(parsed.routes);
    if (!validEnvelope) {
      const backup = `${file}.corrupt-${Date.now()}`;
      await fsp.rename(file, backup).catch(() => {});
      records = new Map();
      clog?.error?.('upstream credential state invalid; preserved and disabled', { file, backup });
      return;
    }

    const next = new Map();
    try {
      for (const [slugInput, value] of Object.entries(parsed.routes)) {
        const slug = validateSlug(slugInput);
        if (slug !== slugInput) throw new UpstreamAuthError(400, 'credential route keys must be canonical');
        next.set(slug, normalizeDefinition(value));
      }
    } catch {
      const backup = `${file}.corrupt-${Date.now()}`;
      await fsp.rename(file, backup).catch(() => {});
      records = new Map();
      clog?.error?.('upstream credential state invalid; preserved and disabled', { file, backup });
      return;
    }
    records = next;
  }

  async function persist(nextRecords) {
    const snapshot = { version: 1, routes: {} };
    for (const slug of [...nextRecords.keys()].sort()) {
      snapshot.routes[slug] = nextRecords.get(slug);
    }
    const payload = `${JSON.stringify(snapshot, null, 2)}\n`;
    await fsp.mkdir(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp-${process.pid}-${randomUUID()}`;
    try {
      await fsp.writeFile(tmp, payload, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      await fsp.chmod(tmp, 0o600);
      await fsp.rename(tmp, file);
    } finally {
      await fsp.unlink(tmp).catch(() => {});
    }
  }

  function mutate(operation) {
    const pending = mutationChain.catch(() => {}).then(operation);
    mutationChain = pending;
    return pending;
  }

  function describe(slugInput) {
    const slug = validateSlug(slugInput);
    return descriptor(records.get(slug));
  }

  function authorizationFor(slugInput) {
    const slug = validateSlug(slugInput);
    const record = records.get(slug);
    if (!record) return null;
    if (record.scheme === 'bearer') return `Bearer ${record.secret}`;
    return `Basic ${Buffer.from(`${record.username}:${record.secret}`, 'utf8').toString('base64')}`;
  }

  function listDescriptions() {
    return [...records.keys()].sort().map((slug) => ({ slug, ...descriptor(records.get(slug)) }));
  }

  async function set(slugInput, definition) {
    const slug = validateSlug(slugInput);
    const record = normalizeDefinition(definition);
    return mutate(async () => {
      const next = new Map(records);
      next.set(slug, record);
      await persist(next);
      records = next;
      return descriptor(record);
    });
  }

  async function remove(slugInput) {
    const slug = validateSlug(slugInput);
    return mutate(async () => {
      if (!records.has(slug)) return false;
      const next = new Map(records);
      next.delete(slug);
      await persist(next);
      records = next;
      return true;
    });
  }

  async function move(fromInput, toInput) {
    const from = validateSlug(fromInput);
    const to = validateSlug(toInput);
    return mutate(async () => {
      if (from === to) return descriptor(records.get(from));
      const source = records.get(from);
      const next = new Map(records);
      next.delete(to);
      next.delete(from);
      if (source) next.set(to, source);
      await persist(next);
      records = next;
      return descriptor(source);
    });
  }

  return { load, describe, listDescriptions, authorizationFor, set, remove, move };
}
