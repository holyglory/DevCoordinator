// Persistent per-Google-account authorization for the Console and protected
// route hosts. Configured ALLOWED_EMAILS remain immutable owners; invited
// users and their exact grants live in <stateDir>/access-control.json.

import { promises as fsp } from 'node:fs';
import path from 'node:path';

const EMAIL_RE = /^[^\s@<>(),;:\\"\[\]]+@[^\s@<>(),;:\\"\[\]]+\.[^\s@<>(),;:\\"\[\]]+$/;
const ROUTE_GRANT_RE = /^route:([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$/;
const MAX_USERS = 1000;
const MAX_GRANTS = 1000;

export const CONSOLE_GRANT = 'console';
export const routeGrant = (slug) => `route:${String(slug ?? '').trim().toLowerCase()}`;

export class AccessError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'AccessError';
    this.status = status;
  }
}

function normalizeEmail(value) {
  if (typeof value !== 'string') throw new AccessError(400, 'email must be a string');
  const email = value.trim().toLowerCase();
  if (!email || email.length > 254 || !EMAIL_RE.test(email)) {
    throw new AccessError(400, 'email must be a valid email address');
  }
  return email;
}

function cloneUsers(users) {
  return new Map([...users].map(([email, grants]) => [email, new Set(grants)]));
}

export function createAccessStore({ file, adminEmails, routeStore, log }) {
  const clog = typeof log?.child === 'function' ? log.child({ mod: 'access' }) : log;
  const admins = new Set();
  for (const value of adminEmails ?? []) admins.add(normalizeEmail(value));

  let users = new Map();
  let mutationChain = Promise.resolve();

  function grantExists(grant) {
    if (grant === CONSOLE_GRANT) return true;
    const match = typeof grant === 'string' ? grant.match(ROUTE_GRANT_RE) : null;
    return Boolean(match && routeStore?.get(match[1]));
  }

  function normalizeGrants(values, { requireCurrent = true } = {}) {
    if (!Array.isArray(values)) throw new AccessError(400, 'grants must be an array');
    if (values.length > MAX_GRANTS) throw new AccessError(400, `grants may contain at most ${MAX_GRANTS} entries`);
    const out = new Set();
    for (const value of values) {
      if (typeof value !== 'string') throw new AccessError(400, 'each grant must be a string');
      const grant = value.trim().toLowerCase();
      if (grant !== CONSOLE_GRANT && !ROUTE_GRANT_RE.test(grant)) {
        throw new AccessError(400, `unknown access resource '${grant.slice(0, 100)}'`);
      }
      if (requireCurrent && !grantExists(grant)) {
        throw new AccessError(400, `access resource '${grant}' does not exist`);
      }
      out.add(grant);
    }
    return out;
  }

  function payloadFor(nextUsers) {
    const serialized = {};
    for (const email of [...nextUsers.keys()].sort()) {
      serialized[email] = { grants: [...nextUsers.get(email)].sort() };
    }
    return `${JSON.stringify({ version: 1, users: serialized }, null, 2)}\n`;
  }

  async function persist(nextUsers) {
    try {
      await fsp.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
      const tmp = `${file}.tmp`;
      await fsp.writeFile(tmp, payloadFor(nextUsers), { encoding: 'utf8', mode: 0o600 });
      await fsp.chmod(tmp, 0o600);
      await fsp.rename(tmp, file);
    } catch (error) {
      throw new AccessError(500, `could not save access policy: ${error?.message ?? error}`);
    }
  }

  function mutate(apply) {
    const operation = mutationChain.then(async () => {
      const next = cloneUsers(users);
      const result = apply(next);
      await persist(next);
      users = next;
      return result;
    });
    // A failed write must not poison later mutations. The caller still sees
    // the original rejection, while the queue resumes from the unchanged map.
    mutationChain = operation.then(() => undefined, () => undefined);
    return operation;
  }

  async function load() {
    let text;
    try {
      text = await fsp.readFile(file, 'utf8');
    } catch (error) {
      if (error?.code === 'ENOENT') {
        users = new Map();
        return;
      }
      throw new AccessError(500, `could not read access policy: ${error?.message ?? error}`);
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
    const valid = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      && parsed.version === 1 && parsed.users && typeof parsed.users === 'object'
      && !Array.isArray(parsed.users);
    if (!valid) {
      const backup = `${file}.corrupt-${Date.now()}`;
      await fsp.rename(file, backup).catch(() => {});
      clog?.error?.('access policy invalid; invited access disabled', { file, backup });
      users = new Map();
      return;
    }

    const next = new Map();
    let pruned = false;
    for (const [rawEmail, value] of Object.entries(parsed.users)) {
      let email;
      try {
        email = normalizeEmail(rawEmail);
      } catch {
        pruned = true;
        continue;
      }
      if (admins.has(email) || !value || typeof value !== 'object' || Array.isArray(value)) {
        pruned = true;
        continue;
      }
      let grants;
      try {
        grants = normalizeGrants(value.grants, { requireCurrent: false });
      } catch {
        pruned = true;
        continue;
      }
      const current = new Set([...grants].filter(grantExists));
      if (current.size !== grants.size) pruned = true;
      next.set(email, current);
      if (next.size > MAX_USERS) {
        pruned = true;
        next.delete(email);
      }
    }
    users = next;
    if (pruned) await persist(users);
  }

  const isAdmin = (email) => {
    try {
      return admins.has(normalizeEmail(email));
    } catch {
      return false;
    }
  };

  const isKnown = (email) => {
    try {
      const normalized = normalizeEmail(email);
      return admins.has(normalized) || users.has(normalized);
    } catch {
      return false;
    }
  };

  const canAccess = (email, grant) => {
    let normalized;
    try {
      normalized = normalizeEmail(email);
    } catch {
      return false;
    }
    if (admins.has(normalized)) return true;
    return grantExists(grant) && Boolean(users.get(normalized)?.has(grant));
  };

  function list() {
    const out = [...admins].sort().map((email) => ({ email, owner: true, grants: [] }));
    for (const email of [...users.keys()].sort()) {
      out.push({ email, owner: false, grants: [...users.get(email)].filter(grantExists).sort() });
    }
    return out;
  }

  async function addUser({ email: input, grants: rawGrants = [] } = {}) {
    const email = normalizeEmail(input);
    if (admins.has(email)) throw new AccessError(409, 'that account is already a configured owner');
    const grants = normalizeGrants(rawGrants);
    return mutate((next) => {
      if (next.has(email)) throw new AccessError(409, 'that Google account is already invited');
      if (next.size >= MAX_USERS) throw new AccessError(400, `access policy may contain at most ${MAX_USERS} invited users`);
      next.set(email, grants);
      return { email, owner: false, grants: [...grants].sort() };
    });
  }

  async function setGrant(input, rawGrant, allowed) {
    const email = normalizeEmail(input);
    if (admins.has(email)) throw new AccessError(400, 'configured owner access cannot be changed in the Console');
    if (typeof allowed !== 'boolean') throw new AccessError(400, 'allowed must be true or false');
    const grants = normalizeGrants([rawGrant]);
    const grant = grants.values().next().value;
    return mutate((next) => {
      const current = next.get(email);
      if (!current) throw new AccessError(404, 'invited user not found');
      if (allowed) current.add(grant);
      else current.delete(grant);
      return { email, owner: false, grants: [...current].sort() };
    });
  }

  async function removeUser(input) {
    const email = normalizeEmail(input);
    if (admins.has(email)) throw new AccessError(400, 'configured owners can only be changed in ALLOWED_EMAILS');
    return mutate((next) => {
      if (!next.delete(email)) throw new AccessError(404, 'invited user not found');
      return { email };
    });
  }

  async function clearResource(grant) {
    return mutate((next) => {
      for (const grants of next.values()) grants.delete(grant);
      return undefined;
    });
  }

  async function moveResource(fromGrant, toGrant) {
    if (!grantExists(toGrant)) throw new AccessError(400, `access resource '${toGrant}' does not exist`);
    return mutate((next) => {
      for (const grants of next.values()) {
        if (!grants.delete(fromGrant)) continue;
        grants.add(toGrant);
      }
      return undefined;
    });
  }

  return {
    load,
    isAdmin,
    isKnown,
    canAccess,
    list,
    addUser,
    setGrant,
    removeUser,
    clearResource,
    moveResource,
  };
}
