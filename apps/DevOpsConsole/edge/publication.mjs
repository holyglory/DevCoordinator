// Immutable, checksummed route/access publication consumed by the stable edge.
//
// The producer writes one complete snapshot with atomic rename.  The edge
// validates every field before swapping its in-memory pointer and keeps a
// retained last-known-good copy for process restarts. A malformed, stale, or
// partially written producer file never clears the currently served routes.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { promises as fsp } from 'node:fs';
import path from 'node:path';

export const PUBLICATION_SCHEMA = 1;
export const MAX_PUBLICATION_BYTES = 2 * 1024 * 1024;
export const MAX_ROUTES = 4096;
export const MAX_IDENTITIES = 2000;
export const MAX_GRANTS_PER_IDENTITY = 4096;

const DNS_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DNS_NAME_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const EMAIL_RE = /^[^\s@<>(),;:\\"\[\]]+@[^\s@<>(),;:\\"\[\]]+\.[^\s@<>(),;:\\"\[\]]+$/;
const COOKIE_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const RELEASE_RE = /^[a-f0-9]{64}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const AUTH_VALUES = new Set(['google', 'public']);
const SCHEMES = new Set(['http', 'https']);
const RESERVED_SLUGS = new Set(['api', 'auth', 'console', 'healthz', 'static', 'www']);
const UNAVAILABLE_UPSTREAM_STATUS = 'unavailable';

export class PublicationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PublicationError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new PublicationError(code, message);
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('publication_shape_invalid', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail('publication_shape_invalid', `${label} fields are invalid`);
  }
}

function normalizedEmail(value, label) {
  if (typeof value !== 'string' || value !== value.trim().toLowerCase() || value.length > 254 || !EMAIL_RE.test(value)) {
    fail('publication_identity_invalid', `${label} must be one normalized email address`);
  }
  return value;
}

function normalizedPort(value, label) {
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    fail('publication_target_invalid', `${label} must be an integer TCP port`);
  }
  return value;
}

function normalizedProtocol(value, label) {
  if (!SCHEMES.has(value.scheme)) {
    fail('publication_target_invalid', `${label}.scheme must be http or https`);
  }
  if (typeof value.tls_verify !== 'boolean') {
    fail('publication_target_invalid', `${label}.tls_verify must be boolean`);
  }
  if (value.scheme === 'http') {
    if (value.tls_server_name !== null || value.tls_verify !== true) {
      fail('publication_target_invalid', `${label} HTTP targets cannot declare TLS overrides`);
    }
  } else if (
    typeof value.tls_server_name !== 'string'
    || value.tls_server_name !== value.tls_server_name.toLowerCase()
    || !DNS_NAME_RE.test(value.tls_server_name)
  ) {
    fail('publication_target_invalid', `${label}.tls_server_name must be one canonical DNS name`);
  }
  return {
    scheme: value.scheme,
    tls_server_name: value.tls_server_name,
    tls_verify: value.tls_verify,
  };
}

function normalizedUpstream(value, label, { reservedPorts }) {
  exactKeys(
    value,
    ['host', 'port', 'scheme', 'tls_server_name', 'tls_verify'],
    label,
  );
  if (value.host !== '127.0.0.1') {
    fail('publication_target_invalid', `${label}.host must be exactly 127.0.0.1`);
  }
  const port = normalizedPort(value.port, `${label}.port`);
  if (reservedPorts.has(port)) {
    fail('publication_target_invalid', `${label}.port targets a reserved control-plane listener`);
  }
  const protocol = normalizedProtocol(value, label);
  return {
    host: '127.0.0.1',
    port,
    ...protocol,
  };
}

function normalizedUnavailableUpstream(value, label) {
  exactKeys(
    value,
    ['scheme', 'status', 'tls_server_name', 'tls_verify'],
    label,
  );
  if (value.status !== UNAVAILABLE_UPSTREAM_STATUS) {
    fail('publication_target_invalid', `${label}.status must be unavailable`);
  }
  return {
    status: UNAVAILABLE_UPSTREAM_STATUS,
    ...normalizedProtocol(value, label),
  };
}

export function isUnavailableRouteUpstream(value) {
  return value?.status === UNAVAILABLE_UPSTREAM_STATUS;
}

export function unavailableRouteUpstream(protocol, label = 'route.upstream') {
  return normalizedUnavailableUpstream(
    { status: UNAVAILABLE_UPSTREAM_STATUS, ...protocol },
    label,
  );
}

function normalizedRouteUpstream(value, label, options) {
  return isUnavailableRouteUpstream(value)
    ? normalizedUnavailableUpstream(value, label)
    : normalizedUpstream(value, label, options);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    const result = {};
    for (const key of Object.keys(value).sort()) result[key] = canonicalize(value[key]);
    return result;
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function publicationDigest(publication) {
  return crypto.createHash('sha256').update(canonicalJson(publication), 'utf8').digest('hex');
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

/** Validate and return a normalized publication detached from caller data. */
export function validatePublication(
  input,
  {
    releaseRoot = '/opt/devcoordinator/releases',
    reservedPorts = new Set([29876]),
  } = {},
) {
  exactKeys(
    input,
    [
      'access',
      'console',
      'console_host',
      'domain',
      'generation',
      'maintenance',
      'published_at',
      'release_digest',
      'routes',
      'schema_version',
      'session',
    ],
    'publication',
  );
  if (input.schema_version !== PUBLICATION_SCHEMA) {
    fail('publication_schema_unsupported', `publication schema must be ${PUBLICATION_SCHEMA}`);
  }
  if (!Number.isSafeInteger(input.generation) || input.generation < 1) {
    fail('publication_generation_invalid', 'publication generation must be a positive safe integer');
  }
  if (
    typeof input.published_at !== 'string'
    || !Number.isFinite(Date.parse(input.published_at))
    || new Date(input.published_at).toISOString() !== input.published_at
  ) {
    fail('publication_timestamp_invalid', 'published_at must be a canonical UTC timestamp');
  }
  if (typeof input.domain !== 'string' || input.domain !== input.domain.toLowerCase() || !DNS_NAME_RE.test(input.domain)) {
    fail('publication_domain_invalid', 'domain must be one canonical DNS name');
  }
  if (input.console_host !== `console.${input.domain}`) {
    fail('publication_domain_invalid', 'console_host must be exactly console.<domain>');
  }
  if (typeof input.release_digest !== 'string' || !RELEASE_RE.test(input.release_digest)) {
    fail('publication_release_invalid', 'release_digest must be one lowercase SHA-256 digest');
  }

  exactKeys(input.maintenance, ['active', 'deployment_id', 'retry_after_seconds', 'started_at'], 'maintenance');
  if (typeof input.maintenance.active !== 'boolean') {
    fail('publication_maintenance_invalid', 'maintenance.active must be boolean');
  }
  if (input.maintenance.active) {
    if (
      typeof input.maintenance.deployment_id !== 'string'
      || !/^[0-9a-f-]{16,64}$/i.test(input.maintenance.deployment_id)
      || !Number.isInteger(input.maintenance.retry_after_seconds)
      || input.maintenance.retry_after_seconds < 1
      || input.maintenance.retry_after_seconds > 300
      || typeof input.maintenance.started_at !== 'string'
      || !Number.isFinite(Date.parse(input.maintenance.started_at))
      || new Date(input.maintenance.started_at).toISOString() !== input.maintenance.started_at
    ) fail('publication_maintenance_invalid', 'active maintenance fields are invalid');
  } else if (
    input.maintenance.deployment_id !== null
    || input.maintenance.retry_after_seconds !== 0
    || input.maintenance.started_at !== null
  ) {
    fail('publication_maintenance_invalid', 'inactive maintenance fields must be cleared');
  }

  exactKeys(input.session, ['cookie_name'], 'session');
  if (typeof input.session.cookie_name !== 'string' || !COOKIE_RE.test(input.session.cookie_name)) {
    fail('publication_session_invalid', 'session.cookie_name is invalid');
  }

  exactKeys(input.console, ['asset_root', 'upstream'], 'console');
  const wantedAssetRoot = path.join(
    path.resolve(releaseRoot),
    input.release_digest,
    'apps/DevOpsConsole/src/ui',
  );
  if (input.console.asset_root !== wantedAssetRoot || !path.isAbsolute(input.console.asset_root)) {
    fail('publication_release_invalid', 'console.asset_root must belong to the exact immutable release');
  }
  const consoleUpstream = normalizedUpstream(input.console.upstream, 'console.upstream', {
    reservedPorts: new Set(),
  });
  if (consoleUpstream.scheme !== 'https' || consoleUpstream.tls_verify !== true) {
    fail('publication_target_invalid', 'the Console backend must use verified HTTPS');
  }

  if (!input.routes || typeof input.routes !== 'object' || Array.isArray(input.routes)) {
    fail('publication_shape_invalid', 'routes must be an object');
  }
  const routeEntries = Object.entries(input.routes);
  if (routeEntries.length > MAX_ROUTES) fail('publication_limit_exceeded', 'too many routes');
  const routes = {};
  for (const [slug, route] of routeEntries.sort(([left], [right]) => left.localeCompare(right))) {
    if (!DNS_LABEL_RE.test(slug) || RESERVED_SLUGS.has(slug)) {
      fail('publication_route_invalid', `invalid or reserved route slug: ${slug}`);
    }
    exactKeys(
      route,
      ['auth', 'instance_id', 'title', 'upstream', 'upstream_authorization'],
      `routes.${slug}`,
    );
    if (!AUTH_VALUES.has(route.auth)) {
      fail('publication_route_invalid', `routes.${slug}.auth must be google or public`);
    }
    if (
      typeof route.instance_id !== 'string'
      || route.instance_id.length < 8
      || route.instance_id.length > 256
      || /[\u0000-\u001f\u007f]/.test(route.instance_id)
    ) {
      fail('publication_route_invalid', `routes.${slug}.instance_id is invalid`);
    }
    if (
      route.title !== null
      && (typeof route.title !== 'string' || route.title.length < 1 || route.title.length > 120 || /[\u0000-\u001f\u007f]/.test(route.title))
    ) {
      fail('publication_route_invalid', `routes.${slug}.title is invalid`);
    }
    if (
      route.upstream_authorization !== null
      && (
        typeof route.upstream_authorization !== 'string'
        || route.upstream_authorization.length < 1
        || route.upstream_authorization.length > 8192
        || /[\r\n]/.test(route.upstream_authorization)
      )
    ) {
      fail('publication_route_invalid', `routes.${slug}.upstream_authorization is invalid`);
    }
    if (route.auth === 'public' && route.upstream_authorization !== null) {
      fail('publication_route_invalid', `routes.${slug} public routes cannot carry private credentials`);
    }
    routes[slug] = {
      auth: route.auth,
      instance_id: route.instance_id,
      title: route.title,
      upstream: normalizedRouteUpstream(
        route.upstream,
        `routes.${slug}.upstream`,
        { reservedPorts },
      ),
      upstream_authorization: route.upstream_authorization,
    };
  }

  exactKeys(input.access, ['grants', 'owners'], 'access');
  if (!Array.isArray(input.access.owners) || input.access.owners.length > MAX_IDENTITIES) {
    fail('publication_identity_invalid', 'access.owners must be a bounded array');
  }
  const owners = [...new Set(input.access.owners.map((email, index) => normalizedEmail(email, `access.owners[${index}]`)))].sort();
  if (owners.length !== input.access.owners.length) {
    fail('publication_identity_invalid', 'access.owners contains duplicate identities');
  }
  if (!input.access.grants || typeof input.access.grants !== 'object' || Array.isArray(input.access.grants)) {
    fail('publication_identity_invalid', 'access.grants must be an object');
  }
  const grantEntries = Object.entries(input.access.grants);
  if (grantEntries.length > MAX_IDENTITIES) fail('publication_limit_exceeded', 'too many grant identities');
  const grants = {};
  for (const [email, values] of grantEntries.sort(([left], [right]) => left.localeCompare(right))) {
    normalizedEmail(email, `access.grants.${email}`);
    if (!Array.isArray(values) || values.length > MAX_GRANTS_PER_IDENTITY) {
      fail('publication_identity_invalid', `access.grants.${email} must be a bounded array`);
    }
    const normalized = [];
    for (const resource of values) {
      if (resource === 'console') {
        normalized.push(resource);
        continue;
      }
      const match = typeof resource === 'string' ? resource.match(/^route:([a-z0-9-]+)$/) : null;
      if (!match || !Object.hasOwn(routes, match[1])) {
        fail('publication_identity_invalid', `access.grants.${email} references an unknown resource`);
      }
      normalized.push(resource);
    }
    const unique = [...new Set(normalized)].sort();
    if (unique.length !== values.length) {
      fail('publication_identity_invalid', `access.grants.${email} contains duplicate resources`);
    }
    grants[email] = unique;
  }

  const normalized = {
    schema_version: PUBLICATION_SCHEMA,
    generation: input.generation,
    published_at: input.published_at,
    domain: input.domain,
    console_host: input.console_host,
    release_digest: input.release_digest,
    maintenance: {
      active: input.maintenance.active,
      deployment_id: input.maintenance.deployment_id,
      retry_after_seconds: input.maintenance.retry_after_seconds,
      started_at: input.maintenance.started_at,
    },
    session: { cookie_name: input.session.cookie_name },
    console: {
      asset_root: wantedAssetRoot,
      upstream: consoleUpstream,
    },
    routes,
    access: { owners, grants },
  };
  return deepFreeze(normalized);
}

export function sealPublication(publication, options) {
  const normalized = validatePublication(publication, options);
  return deepFreeze({
    schema_version: PUBLICATION_SCHEMA,
    payload_sha256: publicationDigest(normalized),
    publication: normalized,
  });
}

export function validateEnvelope(value, options) {
  exactKeys(value, ['payload_sha256', 'publication', 'schema_version'], 'publication envelope');
  if (value.schema_version !== PUBLICATION_SCHEMA || typeof value.payload_sha256 !== 'string' || !SHA256_RE.test(value.payload_sha256)) {
    fail('publication_envelope_invalid', 'publication envelope metadata is invalid');
  }
  const publication = validatePublication(value.publication, options);
  const actual = publicationDigest(publication);
  const expectedBytes = Buffer.from(value.payload_sha256, 'hex');
  const actualBytes = Buffer.from(actual, 'hex');
  if (!crypto.timingSafeEqual(expectedBytes, actualBytes)) {
    fail('publication_digest_mismatch', 'publication payload checksum does not match');
  }
  return deepFreeze({ schema_version: PUBLICATION_SCHEMA, payload_sha256: actual, publication });
}

async function readBoundedRegular(file) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_CLOEXEC ?? 0);
  let handle;
  try {
    handle = await fsp.open(file, flags);
  } catch (error) {
    if (error?.code === 'ELOOP') fail('publication_file_unsafe', `publication is a symlink: ${file}`);
    throw error;
  }
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size < 2 || before.size > MAX_PUBLICATION_BYTES) {
      fail('publication_file_unsafe', `publication is not one bounded regular file: ${file}`);
    }
    const text = await handle.readFile('utf8');
    const after = await handle.stat();
    if (before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
      fail('publication_file_changed', `publication changed while it was read: ${file}`);
    }
    return text;
  } finally {
    await handle.close().catch(() => {});
  }
}

export async function loadPublicationFile(file, options = {}) {
  const text = await readBoundedRegular(file, options);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail('publication_json_invalid', `publication is not valid JSON: ${file}`);
  }
  return validateEnvelope(value, options);
}

async function fsyncDirectory(directory) {
  const handle = await fsp.open(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0));
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function atomicWriteEnvelope(
  file,
  envelope,
  {
    mode = 0o600,
    validation = {},
  } = {},
) {
  const validated = validateEnvelope(envelope, validation);
  const directory = path.dirname(file);
  const parent = await fsp.lstat(directory);
  if (!parent.isDirectory() || parent.isSymbolicLink()) {
    fail('publication_file_unsafe', `publication directory is unsafe: ${directory}`);
  }
  const temporary = path.join(directory, `.${path.basename(file)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  const body = `${JSON.stringify(validated, null, 2)}\n`;
  // A root-owned release switch must not replace an edge-readable 0600
  // snapshot with a root-only inode.  Root materializes the file for the
  // identity that owns its private state directory.  This is only a write
  // detail; ownership never accepts or rejects contents or callers.
  const retainedIdentity = process.geteuid?.() === 0
    ? { uid: parent.uid, gid: parent.gid }
    : null;
  let handle;
  try {
    handle = await fsp.open(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0),
      mode,
    );
    await handle.writeFile(body, 'utf8');
    if (retainedIdentity) {
      await handle.chown(retainedIdentity.uid, retainedIdentity.gid);
    }
    await handle.chmod(mode);
    await handle.sync();
    await handle.close();
    handle = null;
    await fsp.rename(temporary, file);
    await fsyncDirectory(directory);
  } finally {
    await handle?.close().catch(() => {});
    await fsp.unlink(temporary).catch(() => {});
  }
}

export class PublicationStore {
  constructor({ file, lastKnownGoodFile = `${file}.last-known-good`, log, validation = {} } = {}) {
    if (typeof file !== 'string' || !path.isAbsolute(file)) {
      throw new TypeError('PublicationStore requires an absolute publication file');
    }
    this.file = file;
    this.lastKnownGoodFile = lastKnownGoodFile;
    this.log = log;
    this.validation = validation;
    this.snapshot = null;
    this.envelope = null;
    this.timer = null;
    this.adoptionChain = Promise.resolve();
  }

  current() {
    if (!this.snapshot) fail('publication_unavailable', 'no valid route publication is loaded');
    return this.snapshot;
  }

  description() {
    if (!this.envelope) fail('publication_unavailable', 'no valid route publication is loaded');
    // Callers receive a detached document so authenticated producer code can
    // use the exact active generation/CAS token without obtaining a mutable
    // reference to the edge's serving snapshot.
    return structuredClone(this.envelope);
  }

  async _load(file) {
    return loadPublicationFile(file, this.validation);
  }

  _accept(envelope, source) {
    if (this.envelope) {
      const currentGeneration = this.envelope.publication.generation;
      const nextGeneration = envelope.publication.generation;
      for (const [label, currentValue, nextValue] of [
        ['domain', this.envelope.publication.domain, envelope.publication.domain],
        ['console host', this.envelope.publication.console_host, envelope.publication.console_host],
        ['session cookie', this.envelope.publication.session.cookie_name, envelope.publication.session.cookie_name],
      ]) {
        if (currentValue !== nextValue) {
          fail('publication_identity_boundary_changed', `${label} cannot change during an edge process lifetime`);
        }
      }
      if (nextGeneration < currentGeneration) {
        fail('publication_generation_stale', `refusing publication generation rollback from ${currentGeneration} to ${nextGeneration}`);
      }
      if (nextGeneration === currentGeneration && envelope.payload_sha256 !== this.envelope.payload_sha256) {
        fail('publication_generation_conflict', 'same publication generation has different content');
      }
      if (envelope.payload_sha256 === this.envelope.payload_sha256) return false;
    }
    this.envelope = envelope;
    this.snapshot = envelope.publication;
    this.log?.info?.('edge publication activated', {
      source,
      generation: this.snapshot.generation,
      release: this.snapshot.release_digest,
      routes: Object.keys(this.snapshot.routes).length,
    });
    return true;
  }

  async loadInitial() {
    let primaryError;
    try {
      const primary = await this._load(this.file);
      this._accept(primary, 'primary');
      await this.persistLastKnownGood();
      return this.snapshot;
    } catch (error) {
      primaryError = error;
      this.log?.error?.('primary edge publication invalid', { error: error?.message || String(error) });
    }
    try {
      const retained = await this._load(this.lastKnownGoodFile);
      this._accept(retained, 'last-known-good');
      return this.snapshot;
    } catch (retainedError) {
      throw new AggregateError(
        [primaryError, retainedError],
        'primary and last-known-good edge publications are unavailable',
      );
    }
  }

  async persistLastKnownGood() {
    if (!this.envelope) return;
    // Validation already proved the release root used by this store.  Write
    // the exact accepted envelope; never regenerate it from mutable inputs.
    const directory = path.dirname(this.lastKnownGoodFile);
    const temporary = path.join(directory, `.${path.basename(this.lastKnownGoodFile)}.${process.pid}.${crypto.randomUUID()}.tmp`);
    let handle;
    try {
      handle = await fsp.open(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
      await handle.writeFile(`${JSON.stringify(this.envelope, null, 2)}\n`, 'utf8');
      await handle.chmod(0o600);
      await handle.sync();
      await handle.close();
      handle = null;
      await fsp.rename(temporary, this.lastKnownGoodFile);
      await fsyncDirectory(directory);
    } finally {
      await handle?.close().catch(() => {});
      await fsp.unlink(temporary).catch(() => {});
    }
  }

  async refresh() {
    try {
      const envelope = await this._load(this.file);
      const changed = this._accept(envelope, 'primary-refresh');
      if (changed) await this.persistLastKnownGood();
      return { ok: true, changed };
    } catch (error) {
      this.log?.error?.('edge publication refresh rejected; retaining active snapshot', {
        error: error?.message || String(error),
        generation: this.snapshot?.generation ?? null,
      });
      return { ok: false, changed: false, error };
    }
  }

  adopt(envelopeInput, { expectedPayloadSha256 } = {}) {
    const operation = this.adoptionChain.then(async () => {
      const envelope = validateEnvelope(envelopeInput, this.validation);
      if (!this.envelope || expectedPayloadSha256 !== this.envelope.payload_sha256) {
        fail('publication_cas_conflict', 'active publication changed before proposal adoption');
      }
      if (envelope.publication.generation !== this.envelope.publication.generation + 1) {
        fail('publication_generation_invalid', 'proposal generation must advance by exactly one');
      }
      const currentFile = await fsp.lstat(this.file);
      if (!currentFile.isFile() || currentFile.isSymbolicLink()) {
        fail('publication_file_unsafe', 'active publication identity is unsafe');
      }
      await atomicWriteEnvelope(this.file, envelope, {
        validation: this.validation,
      });
      this._accept(envelope, 'authenticated-proposal');
      await this.persistLastKnownGood();
      return {
        ok: true,
        generation: envelope.publication.generation,
        payload_sha256: envelope.payload_sha256,
      };
    });
    this.adoptionChain = operation.catch(() => {});
    return operation;
  }

  start({ intervalMs = 1000 } = {}) {
    if (!Number.isInteger(intervalMs) || intervalMs < 100 || intervalMs > 60_000) {
      throw new TypeError('publication refresh interval must be 100-60000ms');
    }
    if (this.timer) return;
    this.timer = setInterval(() => void this.refresh(), intervalMs);
    this.timer.unref?.();
  }

  close() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}
