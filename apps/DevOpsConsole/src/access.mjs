// Persistent per-Google-account authorization for the Console and protected
// route hosts. Configured ALLOWED_EMAILS remain immutable owners; invited
// users and their exact grants live in <stateDir>/access-control.json.

import crypto from 'node:crypto';
import { constants as fsConstants, promises as fsp } from 'node:fs';
import path from 'node:path';

const EMAIL_RE = /^[^\s@<>(),;:\\"\[\]]+@[^\s@<>(),;:\\"\[\]]+\.[^\s@<>(),;:\\"\[\]]+$/;
const ROUTE_GRANT_RE = /^route:([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$/;
const MAX_USERS = 1000;
const MAX_GRANTS = 1000;
const MAX_PENDING_REQUESTS = 1000;
const MAX_REQUESTS = 5000;
const REQUESTS_PER_HOUR = 5;
const REQUESTS_PER_DAY = 20;
const DENIED_RETRY_MS = 24 * 60 * 60 * 1000;
const REQUEST_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
const CONSOLE_INSTANCE = 'console:v1';
const REQUEST_STATUSES = new Set(['pending', 'approved', 'denied', 'stale']);
const NO_CHANGE = Symbol('no-change');

export const CONSOLE_GRANT = 'console';
export const routeGrant = (slug) => `route:${String(slug ?? '').trim().toLowerCase()}`;

export class AccessError extends Error {
  constructor(status, message, { retryAfter = null } = {}) {
    super(message);
    this.name = 'AccessError';
    this.status = status;
    this.retryAfter = retryAfter;
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

function cloneRequests(requests) {
  return new Map([...requests].map(([id, request]) => [id, { ...request }]));
}

function requestView(request) {
  if (!request) return null;
  const {
    subjectHash: _privateSubject,
    resourceInstance: _privateResourceInstance,
    ...view
  } = request;
  return { ...view };
}

function requireRequestText(value, field, max = 512) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new AccessError(400, `${field} must be a non-empty string`);
  }
  const text = value.trim();
  if (text.length > max || /[\u0000-\u001f\u007f]/.test(text)) {
    throw new AccessError(400, `${field} is invalid`);
  }
  return text;
}

export function createAccessStore({
  file,
  adminEmails,
  routeStore,
  log,
  now = () => Date.now(),
  randomUUID = () => crypto.randomUUID(),
}) {
  const clog = typeof log?.child === 'function' ? log.child({ mod: 'access' }) : log;
  const admins = new Set();
  for (const value of adminEmails ?? []) admins.add(normalizeEmail(value));

  let users = new Map();
  let requests = new Map();
  let mutationChain = Promise.resolve();

  function grantExists(grant) {
    if (grant === CONSOLE_GRANT) return true;
    const match = typeof grant === 'string' ? grant.match(ROUTE_GRANT_RE) : null;
    return Boolean(match && routeStore?.get(match[1]));
  }

  function resourceInstance(grant) {
    if (grant === CONSOLE_GRANT) return CONSOLE_INSTANCE;
    const match = typeof grant === 'string' ? grant.match(ROUTE_GRANT_RE) : null;
    if (!match) return null;
    const route = routeStore?.get(match[1]);
    if (!route) return null;
    if (typeof route.instanceId === 'string' && route.instanceId) return route.instanceId;
    // Compatibility for a caller that has not yet loaded the route-instance
    // migration. New and migrated routes always carry instanceId.
    return typeof route.createdAt === 'string' && route.createdAt ? `legacy:${route.createdAt}` : null;
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

  function payloadFor(nextUsers, nextRequests) {
    const serialized = {};
    for (const email of [...nextUsers.keys()].sort()) {
      serialized[email] = { grants: [...nextUsers.get(email)].sort() };
    }
    const serializedRequests = {};
    for (const id of [...nextRequests.keys()].sort()) {
      serializedRequests[id] = nextRequests.get(id);
    }
    return `${JSON.stringify({ version: 2, users: serialized, requests: serializedRequests }, null, 2)}\n`;
  }

  async function persist(nextUsers, nextRequests) {
    try {
      await fsp.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
      const tmp = `${file}.tmp`;
      await fsp.writeFile(tmp, payloadFor(nextUsers, nextRequests), { encoding: 'utf8', mode: 0o600 });
      await fsp.chmod(tmp, 0o600);
      await fsp.rename(tmp, file);
    } catch (error) {
      throw new AccessError(500, `could not save access policy: ${error?.message ?? error}`);
    }
  }

  function mutate(apply) {
    const operation = mutationChain.then(async () => {
      const next = cloneUsers(users);
      const nextRequests = cloneRequests(requests);
      const result = apply(next, nextRequests);
      if (result?.[NO_CHANGE]) return result.value;
      await persist(next, nextRequests);
      users = next;
      requests = nextRequests;
      return result;
    });
    // A failed write must not poison later mutations. The caller still sees
    // the original rejection, while the queue resumes from the unchanged map.
    mutationChain = operation.then(() => undefined, () => undefined);
    return operation;
  }

  async function openPrivatePolicyFile() {
    let handle;
    try {
      handle = await fsp.open(file, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    } catch (error) {
      if (error?.code === 'ENOENT') throw error;
      if (error?.code === 'ELOOP') {
        throw new AccessError(500, 'access policy symlinks are not allowed');
      }
      throw error;
    }
    try {
      const stat = await handle.stat();
      if (!stat.isFile()) {
        throw new AccessError(500, 'access policy must be a regular file');
      }
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
        throw new AccessError(500, 'access policy must be owned by the Console account');
      }
      if ((stat.mode & 0o077) !== 0) {
        throw new AccessError(500, 'access policy must not be group/world accessible');
      }
      return handle;
    } catch (error) {
      await handle.close().catch(() => {});
      throw error;
    }
  }

  async function load() {
    let handle;
    try {
      handle = await openPrivatePolicyFile();
    } catch (error) {
      if (error?.code === 'ENOENT') {
        users = new Map();
        requests = new Map();
        return;
      }
      if (error instanceof AccessError) throw error;
      throw new AccessError(500, `could not read access policy: ${error?.message ?? error}`);
    }

    let text;
    try {
      text = await handle.readFile('utf8');
    } catch (error) {
      throw new AccessError(500, `could not read access policy: ${error?.message ?? error}`);
    } finally {
      await handle.close().catch(() => {});
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
    const valid = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      && (parsed.version === 1 || parsed.version === 2) && parsed.users && typeof parsed.users === 'object'
      && !Array.isArray(parsed.users);
    if (!valid) {
      const backup = `${file}.corrupt-${Date.now()}`;
      await fsp.rename(file, backup).catch(() => {});
      clog?.error?.('access policy invalid; invited access disabled', { file, backup });
      users = new Map();
      requests = new Map();
      return;
    }

    const next = new Map();
    let pruned = parsed.version === 1;
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

    const nextRequests = new Map();
    if (parsed.version === 2) {
      if (!parsed.requests || typeof parsed.requests !== 'object' || Array.isArray(parsed.requests)) {
        pruned = true;
      } else {
        for (const [id, raw] of Object.entries(parsed.requests)) {
          if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
            pruned = true;
            continue;
          }
          let email;
          try {
            email = normalizeEmail(raw.email);
          } catch {
            pruned = true;
            continue;
          }
          const valid =
            typeof id === 'string' && /^[0-9a-f-]{16,64}$/i.test(id)
            && typeof raw.subjectHash === 'string' && /^[0-9a-f]{64}$/.test(raw.subjectHash)
            && typeof raw.resource === 'string'
            && (raw.resource === CONSOLE_GRANT || ROUTE_GRANT_RE.test(raw.resource))
            && typeof raw.resourceInstance === 'string' && raw.resourceInstance.length > 0
            && raw.resourceInstance.length <= 200 && !/[\u0000-\u001f\u007f]/.test(raw.resourceInstance)
            && typeof raw.host === 'string' && raw.host.length > 0 && raw.host.length <= 300
            && !/[\u0000-\u001f\u007f]/.test(raw.host)
            && typeof raw.title === 'string' && raw.title.length > 0 && raw.title.length <= 300
            && !/[\u0000-\u001f\u007f]/.test(raw.title)
            && typeof raw.target === 'string' && raw.target.length > 0 && raw.target.length <= 600
            && !/[\u0000-\u001f\u007f]/.test(raw.target)
            && REQUEST_STATUSES.has(raw.status)
            && typeof raw.requestedAt === 'string' && Number.isFinite(Date.parse(raw.requestedAt))
            && (raw.resolvedAt === null || (typeof raw.resolvedAt === 'string' && Number.isFinite(Date.parse(raw.resolvedAt))))
            && (raw.resolvedBy === null || (typeof raw.resolvedBy === 'string' && raw.resolvedBy.length <= 254));
          if (!valid) {
            pruned = true;
            continue;
          }
          const request = { ...raw, id, email };
          if (
            request.status === 'pending'
            && (resourceInstance(request.resource) !== request.resourceInstance)
          ) {
            request.status = 'stale';
            request.resolvedAt = new Date(now()).toISOString();
            request.resolvedBy = 'system:resource-changed';
            pruned = true;
          }
          nextRequests.set(id, request);
        }
      }
    }
    requests = nextRequests;
    if (pruned) await persist(users, requests);
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

  function listRequests({ status = 'pending' } = {}) {
    if (status !== 'all' && !REQUEST_STATUSES.has(status)) {
      throw new AccessError(400, 'request status is invalid');
    }
    return [...requests.values()]
      .filter((request) => status === 'all' || request.status === status)
      .sort((a, b) => {
        const direction = status === 'pending' ? 1 : -1;
        return direction * String(a.requestedAt).localeCompare(String(b.requestedAt))
          || a.id.localeCompare(b.id);
      })
      .map(requestView);
  }

  const pendingRequestCount = () => [...requests.values()].filter((request) => request.status === 'pending').length;

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

  async function requestAccess({ email: input, subject, resource: rawResource, resourceInstance: requestedInstance,
    host, title, target } = {}) {
    const email = normalizeEmail(input);
    if (typeof subject !== 'string' || !subject || subject.length > 512) {
      throw new AccessError(400, 'subject is invalid');
    }
    const subjectText = subject;
    const subjectHash = crypto.createHash('sha256').update(subjectText, 'utf8').digest('hex');
    const resource = normalizeGrants([rawResource]).values().next().value;
    const instance = requireRequestText(requestedInstance, 'resource instance', 200);
    if (resourceInstance(resource) !== instance) {
      throw new AccessError(409, 'the requested resource changed; reload and try again');
    }
    if (canAccess(email, resource)) throw new AccessError(409, 'this account already has access');
    const safeHost = requireRequestText(host, 'host', 300);
    const safeTitle = requireRequestText(title, 'title', 300);
    const safeTarget = requireRequestText(target, 'target', 600);

    return mutate((nextUsers, nextRequests) => {
      const currentMs = now();
      const existingPending = [...nextRequests.values()].find((request) =>
        request.status === 'pending'
        && request.subjectHash === subjectHash
        && request.email === email
        && request.resource === resource
        && request.resourceInstance === instance);
      if (existingPending) return { [NO_CHANGE]: true, value: { ...requestView(existingPending), duplicate: true } };

      const latestDenied = [...nextRequests.values()]
        .filter((request) => request.status === 'denied'
          && request.subjectHash === subjectHash
          && request.email === email
          && request.resource === resource
          && request.resourceInstance === instance)
        .sort((a, b) => String(b.resolvedAt).localeCompare(String(a.resolvedAt)))[0];
      if (latestDenied) {
        const retryAt = Date.parse(latestDenied.resolvedAt) + DENIED_RETRY_MS;
        if (retryAt > currentMs) {
          throw new AccessError(429, 'this request was denied recently; try again later', {
            retryAfter: Math.max(1, Math.ceil((retryAt - currentMs) / 1000)),
          });
        }
      }

      const recent = [...nextRequests.values()].filter((request) =>
        request.subjectHash === subjectHash && currentMs - Date.parse(request.requestedAt) < DENIED_RETRY_MS);
      const lastHour = recent.filter((request) => currentMs - Date.parse(request.requestedAt) < 60 * 60 * 1000);
      if (lastHour.length >= REQUESTS_PER_HOUR || recent.length >= REQUESTS_PER_DAY) {
        const oldest = (lastHour.length >= REQUESTS_PER_HOUR ? lastHour : recent)
          .map((request) => Date.parse(request.requestedAt)).sort((a, b) => a - b)[0];
        const windowMs = lastHour.length >= REQUESTS_PER_HOUR ? 60 * 60 * 1000 : DENIED_RETRY_MS;
        throw new AccessError(429, 'too many access requests; try again later', {
          retryAfter: Math.max(1, Math.ceil((oldest + windowMs - currentMs) / 1000)),
        });
      }

      const pending = [...nextRequests.values()].filter((request) => request.status === 'pending').length;
      if (pending >= MAX_PENDING_REQUESTS) throw new AccessError(503, 'the access request queue is full');

      const retentionCutoff = currentMs - REQUEST_RETENTION_MS;
      for (const [id, request] of nextRequests) {
        if (request.status !== 'pending' && Date.parse(request.resolvedAt || request.requestedAt) < retentionCutoff) {
          nextRequests.delete(id);
        }
      }
      if (nextRequests.size >= MAX_REQUESTS) throw new AccessError(503, 'the access request history is full');

      if (admins.has(email) || nextUsers.get(email)?.has(resource)) {
        throw new AccessError(409, 'this account already has access');
      }

      const id = randomUUID();
      const request = {
        id,
        email,
        subjectHash,
        resource,
        resourceInstance: instance,
        host: safeHost,
        title: safeTitle,
        target: safeTarget,
        status: 'pending',
        requestedAt: new Date(currentMs).toISOString(),
        resolvedAt: null,
        resolvedBy: null,
      };
      nextRequests.set(id, request);
      return requestView(request);
    });
  }

  async function decideRequest(idInput, decision, actorInput) {
    const id = requireRequestText(idInput, 'request id', 64);
    if (decision !== 'approve' && decision !== 'deny') {
      throw new AccessError(400, "decision must be 'approve' or 'deny'");
    }
    const actor = normalizeEmail(actorInput);
    if (!admins.has(actor)) throw new AccessError(403, 'only configured Console owners can decide access requests');

    return mutate((nextUsers, nextRequests) => {
      const request = nextRequests.get(id);
      if (!request) throw new AccessError(404, 'access request not found');
      const wantedStatus = decision === 'approve' ? 'approved' : 'denied';
      if (request.status === wantedStatus) {
        return { [NO_CHANGE]: true, value: requestView(request) };
      }
      if (request.status !== 'pending') throw new AccessError(409, `access request is already ${request.status}`);

      if (decision === 'approve') {
        if (resourceInstance(request.resource) !== request.resourceInstance) {
          throw new AccessError(409, 'the requested resource no longer exists or has changed');
        }
        if (!admins.has(request.email)) {
          let grants = nextUsers.get(request.email);
          if (!grants) {
            if (nextUsers.size >= MAX_USERS) {
              throw new AccessError(409, `access policy may contain at most ${MAX_USERS} invited users`);
            }
            grants = new Set();
            nextUsers.set(request.email, grants);
          }
          grants.add(request.resource);
        }
      }
      request.status = wantedStatus;
      request.resolvedAt = new Date(now()).toISOString();
      request.resolvedBy = actor;
      return requestView(request);
    });
  }

  async function clearResource(grant) {
    return mutate((next, nextRequests) => {
      for (const grants of next.values()) grants.delete(grant);
      const resolvedAt = new Date(now()).toISOString();
      for (const request of nextRequests.values()) {
        if (request.resource !== grant || request.status !== 'pending') continue;
        request.status = 'stale';
        request.resolvedAt = resolvedAt;
        request.resolvedBy = 'system:resource-removed';
      }
      return undefined;
    });
  }

  async function moveResource(fromGrant, toGrant) {
    if (!grantExists(toGrant)) throw new AccessError(400, `access resource '${toGrant}' does not exist`);
    return mutate((next, nextRequests) => {
      for (const grants of next.values()) {
        if (!grants.delete(fromGrant)) continue;
        grants.add(toGrant);
      }
      const resolvedAt = new Date(now()).toISOString();
      for (const request of nextRequests.values()) {
        if (request.resource !== fromGrant || request.status !== 'pending') continue;
        request.status = 'stale';
        request.resolvedAt = resolvedAt;
        request.resolvedBy = 'system:resource-renamed';
      }
      return undefined;
    });
  }

  return {
    load,
    isAdmin,
    isKnown,
    canAccess,
    resourceInstance,
    list,
    listRequests,
    pendingRequestCount,
    addUser,
    setGrant,
    removeUser,
    requestAccess,
    decideRequest,
    clearResource,
    moveResource,
  };
}
