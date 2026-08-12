// Trusted loopback client for the codex-dev-coordinator HTTP API (see
// docs/coordinator-http-api.json). The listener and Host/Origin checks form the
// local boundary; public browser authentication remains in the Console edge.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const DOCKER_ACTIONS = new Set(['start', 'stop', 'restart']);
const PROJECT_ACTIONS = new Set(['start', 'stop', 'restart']);
const RUNTIME_ARTIFACT_KINDS = new Set([
  'service', 'run', 'diagnostic', 'docker', 'database_stack', 'worker_attempt',
]);
const RUNTIME_ARTIFACT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RUNTIME_ARTIFACT_MAX_BYTES = 1024 * 1024;
const TEST_STATS_CACHE_MAX_BYTES = 8 * 1024 * 1024;
const TEST_STATS_CACHE_MAX_ENTRIES = 32;
const TEST_STATS_MAX_STALE_MS = 24 * 60 * 60 * 1000;
// The envelope remains version 1 so the state-copy validator can safely carry
// it across Console slots.  This separate revision is intentionally bumped
// whenever the meaning of a cached test projection changes; entries written by
// an older renderer are ignored instead of surviving a deploy with stale UI
// semantics.
const TEST_STATS_CACHE_SEMANTICS_REVISION = 2;
const FULL_DOCKER_OBSERVER_DOMAIN = 'host-runtime-v2:full-docker';
const OPERATIONAL_SERVER_STATES = new Set([
  'running', 'starting', 'unhealthy', 'stopping', 'stopped',
]);
const CONSOLE_INVENTORY_KEYS = Object.freeze([
  'coordinator_home',
  'state_path',
  'project',
  'urls',
  'servers',
  'leases',
  'port_assignments',
  'recent_events',
  'docker',
  'postgres',
  'backups',
  'project_usage',
]);

// Connection-level failure codes where the request never reached the
// coordinator, making a single retry after autostart safe even for mutations.
const RETRYABLE_CODES = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
  'UND_ERR_CONNECT_TIMEOUT',
]);
const TRANSIENT_TEST_SETUP_CODES = new Set([
  'test_scheduler_unavailable',
  'test_repository_setup_unavailable',
]);
const TEST_SETUP_RETRY_MIN_DELAY_MS = 250;
const TEST_SETUP_RETRY_MAX_DELAY_MS = 2_000;

export class CoordError extends Error {
  constructor(message, { status = 0, body = null } = {}) {
    super(message);
    this.name = 'CoordError';
    this.status = status; // 0 = transport-level failure (unreachable/timeout)
    this.body = body;
    const evidence = body?.evidence && typeof body.evidence === 'object'
      ? body.evidence
      : null;
    this.code = typeof body?.code === 'string'
      ? body.code
      : typeof evidence?.code === 'string' ? evidence.code : null;
    this.classification = typeof body?.classification === 'string'
      ? body.classification
      : typeof evidence?.classification === 'string' ? evidence.classification
      : null;
    const retryAfter = Number(
      body?.retry_after_seconds
      ?? body?.retryAfterSeconds
      ?? evidence?.retry_after_seconds
      ?? evidence?.retryAfterSeconds,
    );
    this.retryAfterSeconds = Number.isFinite(retryAfter) && retryAfter > 0
      ? Math.ceil(retryAfter)
      : null;
  }
}

// Coordinator KeyError messages arrive with their Python quotes intact,
// e.g. {"error":"'agent'"} — strip matched surrounding quote pairs.
function cleanMessage(raw) {
  let msg = String(raw ?? '').trim();
  while (
    msg.length >= 2 &&
    ((msg.startsWith("'") && msg.endsWith("'")) ||
      (msg.startsWith('"') && msg.endsWith('"')))
  ) {
    msg = msg.slice(1, -1).trim();
  }
  return msg || 'coordinator error';
}

function timestampMillis(value) {
  if (typeof value !== 'string' || !value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

// During a rolling server-wide upgrade, the HTTP API can already expose a
// newer normalized graph while the independently supervised broker still
// emits an older v1 compatibility projection. Derive only facts that the
// normalized graph proves: present container identities and telemetry from
// the latest completed Docker observation window. The canonical broker stats
// remain authoritative and win as soon as they are available.
function consoleDockerProjection(value, docker, trustedObservations) {
  if (!docker || typeof docker !== 'object' || Array.isArray(docker)) return docker;
  if (!Array.isArray(docker.containers)) return docker;

  const resources = value?.resources?.docker;
  if (!Array.isArray(resources)) return docker;

  const resourceById = new Map();
  const resourceByContainerId = new Map();
  for (const resource of resources) {
    if (!resource || typeof resource !== 'object' || Array.isArray(resource)) continue;
    const resourceId = String(resource.docker_resource_id ?? '');
    if (!resourceId) continue;
    resourceById.set(resourceId, resource);
    const containerId = String(resource.full_container_id ?? '');
    if (containerId) resourceByContainerId.set(containerId, resource);
  }

  const rows = [];
  for (const original of docker.containers) {
    if (!original || typeof original !== 'object' || Array.isArray(original)) continue;
    const resource = resourceById.get(String(original.host_resource_id ?? ''))
      ?? resourceByContainerId.get(String(original.id ?? ''));
    if (!resource) continue;
    rows.push({ item: { ...original }, resource });
  }

  const engines = value?.docker_engines;
  const snapshots = value?.observations?.snapshots;
  const dockerObservations = value?.observations?.docker;
  const telemetry = value?.observations?.telemetry;
  if (
    !Array.isArray(engines)
    || !Array.isArray(snapshots)
    || !Array.isArray(dockerObservations)
    || !Array.isArray(telemetry)
  ) {
    return { ...docker, containers: rows.map(({ item }) => item) };
  }

  const engineById = new Map(
    engines
      .filter((engine) => engine && typeof engine === 'object' && !Array.isArray(engine))
      .map((engine) => [String(engine.engine_id ?? ''), engine]),
  );
  const snapshotByHost = new Map();
  for (const [hostId, proof] of trustedObservations ?? []) {
    if (
      proof?.schema_version !== 2
      || !['completed', 'fresh'].includes(proof.status)
      || proof.observer_domain !== FULL_DOCKER_OBSERVER_DOMAIN
      || proof.docker_available !== true
      || typeof proof.capability_fingerprint !== 'string'
      || typeof proof.material_fingerprint !== 'string'
      || String(proof.host_id ?? '') !== hostId
    ) continue;
    const snapshot = snapshots.find((candidate) => (
      candidate?.snapshot_id === proof.snapshot_id
      && String(candidate.host_id ?? '') === hostId
      && candidate.observer_domain === FULL_DOCKER_OBSERVER_DOMAIN
      && candidate.status === 'completed'
      && candidate.completed_at === proof.completed_at
    ));
    if (!snapshot) continue;
    const startedAt = timestampMillis(snapshot.started_at);
    const completedAt = timestampMillis(snapshot.completed_at);
    if (startedAt === null || completedAt === null || startedAt > completedAt) continue;
    snapshotByHost.set(hostId, {
      startedAt,
      completedAt,
      snapshotId: String(snapshot.snapshot_id),
    });
  }

  const dockerObservationByResource = new Map();
  for (const observation of dockerObservations) {
    const resourceId = String(observation?.docker_resource_id ?? '');
    const sampledAt = timestampMillis(observation?.sampled_at);
    if (!resourceById.has(resourceId) || sampledAt === null) continue;
    const previous = dockerObservationByResource.get(resourceId);
    if (!previous || sampledAt > previous.sampledAt) {
      dockerObservationByResource.set(resourceId, { observation, sampledAt });
    }
  }

  const sampleByResource = new Map();
  for (const sample of telemetry) {
    if (sample?.host_resource_kind !== 'docker') continue;
    const resourceId = String(sample.host_resource_id ?? '');
    const resource = resourceById.get(resourceId);
    const engine = resource ? engineById.get(String(resource.engine_id ?? '')) : null;
    const hostId = engine ? String(engine.host_id ?? '') : null;
    const snapshot = hostId ? snapshotByHost.get(hostId) : null;
    const sampledAt = timestampMillis(sample.sampled_at);
    if (
      !snapshot
      || sampledAt === null
      || sampledAt < snapshot.startedAt
      || sampledAt > snapshot.completedAt
    ) continue;
    const previous = sampleByResource.get(resourceId);
    const sampleId = String(sample.sample_id ?? '');
    if (
      !previous
      || sampledAt > previous.sampledAt
      || (sampledAt === previous.sampledAt && sampleId > previous.sampleId)
    ) {
      sampleByResource.set(resourceId, { sample, sampledAt, sampleId });
    }
  }

  const containers = rows.map(({ item, resource }) => {
    if (item.status !== 'running' || Object.hasOwn(item, 'stats')) return item;
    const resourceId = String(resource.docker_resource_id ?? '');
    const engine = engineById.get(String(resource.engine_id ?? ''));
    if (engine?.capability_state !== 'available') return item;
    const hostId = String(engine.host_id ?? '');
    const snapshot = snapshotByHost.get(hostId);
    const currentObservation = dockerObservationByResource.get(resourceId);
    if (
      !snapshot
      || currentObservation?.observation?.lifecycle !== 'running'
      || currentObservation.sampledAt < snapshot.startedAt
      || currentObservation.sampledAt > snapshot.completedAt
    ) return item;
    const usage = sampleByResource.get(resourceId)?.sample;
    if (!usage) return item;
    return {
      ...item,
      stats: {
        source: 'normalized_observation',
        id: item.id,
        container_id: item.id,
        name: item.name,
        timestamp: usage.sampled_at,
        live: true,
        cpu_percent: usage.cpu_percent,
        memory_usage_bytes: usage.memory_bytes,
        network_rx_bytes: usage.network_rx_bytes,
        network_tx_bytes: usage.network_tx_bytes,
        block_read_bytes: usage.block_read_bytes,
        block_write_bytes: usage.block_write_bytes,
      },
    };
  });
  return { ...docker, containers };
}

export function coordinatorTimeoutFor(apiPath) {
  if (apiPath === '/v1/runtime') return 300_000;
  if (apiPath === '/v1/lifecycle/apply') return 600_000;
  if (apiPath.startsWith('/v1/lifecycle/')) return 300_000;
  if (apiPath.startsWith('/v1/projects/')) return 300_000; // compose up can run minutes
  if (apiPath === '/v1/inventory') return 60_000; // may read a large host snapshot
  if (apiPath === '/v1/observe') return 720_000; // broker serializes host-wide Docker stats
  if (apiPath.startsWith('/v1/docker/')) return 60_000;
  return 15_000;
}

function failureCode(err) {
  const seen = new Set();
  const stack = [err];
  while (stack.length > 0) {
    const e = stack.pop();
    if (!e || typeof e !== 'object' || seen.has(e)) continue;
    seen.add(e);
    if (typeof e.code === 'string' && e.code) return e.code;
    if (e.cause) stack.push(e.cause);
    if (Array.isArray(e.errors)) stack.push(...e.errors);
  }
  return null;
}

// Normalized schemas keep identities at the top level and isolate the
// legacy Console read model under v1_compatibility. Existing Console journeys
// deliberately consume that declared projection: overlay only its known keys
// into a new view, retaining the normalized graph as non-conflicting evidence
// and never mutating the cached wire response.
function consoleInventoryView(value, trustedObservations = new Map()) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![2, 3].includes(value.schema_version)) {
    return value;
  }
  const compatibility = value.v1_compatibility;
  if (!compatibility || typeof compatibility !== 'object' || Array.isArray(compatibility)) {
    throw new CoordError('coordinator inventory compatibility projection is incomplete', {
      status: 502,
    });
  }
  const missing = CONSOLE_INVENTORY_KEYS.filter(
    (key) => !Object.prototype.hasOwnProperty.call(compatibility, key),
  );
  if (missing.length > 0) {
    throw new CoordError('coordinator inventory compatibility projection is incomplete', {
      status: 502,
    });
  }
  const projected = { ...value };
  for (const key of CONSOLE_INVENTORY_KEYS) {
    projected[key] = key === 'docker'
      ? consoleDockerProjection(value, compatibility.docker, trustedObservations)
      : compatibility[key];
  }
  // A rolling older broker may still project configuration-only definitions as
  // `unobserved` servers merely because they have a port policy. Keep the
  // untouched normalized graph and compatibility payload for exact lease
  // consumers, but the Console read model must require lifecycle evidence.
  const servers = Array.isArray(projected.servers)
    ? projected.servers.filter((server) => OPERATIONAL_SERVER_STATES.has(server?.status))
    : [];
  const serverIds = new Set(servers.map((server) => String(server.id ?? '')));
  projected.servers = servers;
  projected.project_usage = Array.isArray(projected.project_usage)
    ? projected.project_usage.map((row) => ({
      ...row,
      server_ids: Array.isArray(row?.server_ids)
        ? row.server_ids.filter((id) => serverIds.has(String(id)))
        : row?.server_ids,
    }))
    : projected.project_usage;
  return projected;
}

// The Coordinator's normalized inventory also contains durable audit and
// historical observation evidence.  The browser needs the authoritative
// repository/resource graph and the compatibility read model, but it must not
// receive the entire audit graph on every six-second overview poll.  Docker
// telemetry is projected above before the historical-only fields are removed.
function consoleOverviewInventoryView(value, trustedObservations = new Map()) {
  const projected = consoleInventoryView(value, trustedObservations);
  if (!projected || ![2, 3].includes(projected.schema_version)) return projected;
  const observations = projected.observations;
  return {
    schema_version: projected.schema_version,
    store: projected.store,
    repositories: projected.repositories,
    repository_trees: projected.repository_trees,
    resources: projected.resources,
    unassigned_resources: projected.unassigned_resources,
    lifecycle_violations: projected.lifecycle_violations,
    observations: observations && typeof observations === 'object'
      ? {
          servers: observations.servers,
          docker: observations.docker,
          databases: observations.databases,
        }
      : observations,
    ...Object.fromEntries(CONSOLE_INVENTORY_KEYS.map((key) => [key, projected[key]])),
  };
}

export function createCoordinator({ config, log }) {
  const clog = typeof log?.child === 'function' ? log.child({ mod: 'coordinator' }) : log;
  const baseUrl = String(config.coordinatorUrl).replace(/\/+$/, '');

  const pendingAborts = new Set();
  let closed = false;

  let ok = false;
  let autostarted = false;
  let lastError = null;
  let lastOkAt = null;
  let lastSpawnAt = 0; // autostart rate limit: max one spawn attempt per 30s
  let ensureInflight = null;

  const invCache = { value: undefined, at: 0, inflight: null, generation: 0, dirty: false };
  const srvCache = { value: undefined, at: 0, inflight: null, generation: 0, dirty: false };
  const testRepositoryCache = { value: undefined, at: 0, inflight: null, generation: 0 };
  const testStatsCaches = new Map();
  const trustedDockerObservations = new Map();
  const observationFlights = new Map();
  let inventoryOverviewFailure = null;

  const testStatsSnapshotPath = path.join(config.stateDir, 'test-stats-cache-v1.json');

  function loadTestStatsSnapshots() {
    try {
      const info = fs.lstatSync(testStatsSnapshotPath);
      if (!info.isFile() || info.isSymbolicLink() || info.size > TEST_STATS_CACHE_MAX_BYTES) return;
      const document = JSON.parse(fs.readFileSync(testStatsSnapshotPath, 'utf8'));
      if (
        document?.version !== 1
        || document.semantics_revision !== TEST_STATS_CACHE_SEMANTICS_REVISION
        || !Array.isArray(document.entries)
      ) return;
      const now = Date.now();
      for (const entry of document.entries.slice(0, TEST_STATS_CACHE_MAX_ENTRIES)) {
        if (
          typeof entry?.key !== 'string'
          || entry.key.length < 1
          || entry.key.length > 8192
          || !Number.isFinite(entry.at)
          || entry.at > now
          || now - entry.at > TEST_STATS_MAX_STALE_MS
          || ![1, 2].includes(entry.value?.schema_version)
        ) continue;
        testStatsCaches.set(entry.key, {
          value: entry.value,
          at: entry.at,
          inflight: null,
          generation: 0,
          retained: true,
        });
      }
    } catch (err) {
      if (err?.code !== 'ENOENT') {
        clog?.warn?.('ignored invalid persisted test statistics cache', {
          error: String(err?.message ?? err),
        });
      }
    }
  }

  function persistTestStatsSnapshots() {
    const now = Date.now();
    const entries = [...testStatsCaches.entries()]
      .filter(([, cache]) => (
        [1, 2].includes(cache.value?.schema_version)
        && Number.isFinite(cache.at)
        && now - cache.at <= TEST_STATS_MAX_STALE_MS
      ))
      .sort((a, b) => b[1].at - a[1].at)
      .slice(0, TEST_STATS_CACHE_MAX_ENTRIES)
      .map(([key, cache]) => ({ key, at: cache.at, value: cache.value }));
    const encoded = `${JSON.stringify({
      version: 1,
      semantics_revision: TEST_STATS_CACHE_SEMANTICS_REVISION,
      entries,
    })}\n`;
    if (Buffer.byteLength(encoded) > TEST_STATS_CACHE_MAX_BYTES) return;
    const temporary = `${testStatsSnapshotPath}.${process.pid}.${Date.now()}.tmp`;
    try {
      fs.mkdirSync(path.dirname(testStatsSnapshotPath), { recursive: true, mode: 0o700 });
      fs.writeFileSync(temporary, encoded, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      fs.renameSync(temporary, testStatsSnapshotPath);
    } catch (err) {
      try { fs.unlinkSync(temporary); } catch { /* best-effort temporary cleanup */ }
      clog?.warn?.('could not persist test statistics cache', {
        error: String(err?.message ?? err),
      });
    }
  }

  loadTestStatsSnapshots();

  function noteAlive() {
    ok = true;
    lastOkAt = new Date().toISOString();
    lastError = null;
  }

  function noteDown(err) {
    ok = false;
    lastError = err?.message ? String(err.message) : String(err);
  }

  function autostartLogPath() {
    return path.join(config.stateDir, 'logs', 'coordinator-api.log');
  }

  async function readBoundedRuntimeArtifact(res) {
    const rawLength = res.headers.get('content-length');
    if (rawLength && /^\d+$/.test(rawLength) && Number(rawLength) > RUNTIME_ARTIFACT_MAX_BYTES) {
      await res.body?.cancel().catch(() => {});
      throw new CoordError('coordinator returned an oversized runtime log artifact', { status: 502 });
    }
    if (!String(res.headers.get('content-type') ?? '').toLowerCase().startsWith('text/plain')) {
      await res.body?.cancel().catch(() => {});
      throw new CoordError('coordinator returned an invalid runtime log artifact', { status: 502 });
    }
    if (!res.body) return { text: '' };

    const reader = res.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = Buffer.from(value);
        size += chunk.length;
        if (size > RUNTIME_ARTIFACT_MAX_BYTES) {
          await reader.cancel().catch(() => {});
          throw new CoordError('coordinator returned an oversized runtime log artifact', { status: 502 });
        }
        chunks.push(chunk);
      }
    } finally {
      reader.releaseLock();
    }
    return { text: Buffer.concat(chunks, size).toString('utf8') };
  }

  async function fetchJson(method, apiPath, body, timeoutMs, responseMode = 'json') {
    const ac = new AbortController();
    pendingAborts.add(ac);
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      let res;
      try {
        const headers = {};
        if (body != null) headers['content-type'] = 'application/json';
        res = await fetch(baseUrl + apiPath, {
          method,
          headers: Object.keys(headers).length ? headers : undefined,
          body: body == null ? undefined : JSON.stringify(body),
          signal: ac.signal,
        });
      } catch (err) {
        if (err instanceof CoordError) {
          noteDown(err);
          throw err;
        }
        let coordErr;
        if (ac.signal.aborted) {
          coordErr = new CoordError(
            `coordinator request timed out after ${timeoutMs}ms (${method} ${apiPath})`,
          );
        } else {
          const code = failureCode(err);
          coordErr = new CoordError(
            `coordinator unreachable at ${baseUrl}: ${code ?? err?.message ?? err}`,
          );
          coordErr.retryable = code !== null && RETRYABLE_CODES.has(code);
        }
        coordErr.cause = err;
        noteDown(coordErr);
        throw coordErr;
      }
      let data = null;
      if (responseMode === 'runtime-artifact' && res.status === 200) {
        try {
          data = await readBoundedRuntimeArtifact(res);
        } catch (err) {
          if (err instanceof CoordError) {
            noteAlive();
            throw err;
          }
          const coordErr = new CoordError(
            `coordinator response read failed (${method} ${apiPath}): ${err?.message ?? err}`,
          );
          coordErr.cause = err;
          noteDown(coordErr);
          throw coordErr;
        }
      } else {
        let text = '';
        try {
          text = await res.text();
        } catch (err) {
          const coordErr = new CoordError(
            `coordinator response read failed (${method} ${apiPath}): ${err?.message ?? err}`,
          );
          coordErr.cause = err;
          noteDown(coordErr);
          throw coordErr;
        }
        if (text) {
          try {
            data = JSON.parse(text);
          } catch {
            data = text;
          }
        }
      }
      if (res.status !== 200) {
        const raw =
          data && typeof data === 'object' && typeof data.error === 'string'
            ? data.error
            : `coordinator returned HTTP ${res.status}`;
        const message = cleanMessage(raw);
        const coordErr = new CoordError(message, { status: res.status, body: data });
        noteAlive();
        throw coordErr;
      }
      noteAlive();
      return data;
    } finally {
      clearTimeout(timer);
      pendingAborts.delete(ac);
    }
  }

  async function attempt(method, apiPath, body, timeoutMs, responseMode = 'json') {
    try {
      return await fetchJson(method, apiPath, body, timeoutMs, responseMode);
    } catch (err) {
      const canRetry =
        err instanceof CoordError && err.status === 0 && err.retryable === true && !closed;
      if (!canRetry) throw err;
      // Lazy autostart on connection failure (rate-limited inside).
      const revived = await ensureRunning();
      if (!revived.ok) throw err;
      return fetchJson(method, apiPath, body, timeoutMs, responseMode);
    }
  }

  function invalidateCaches({ preserveInventory = false } = {}) {
    for (const cache of [invCache, srvCache]) {
      cache.generation += 1;
      if (preserveInventory && cache === invCache && cache.value !== undefined) {
        cache.dirty = true;
      } else {
        cache.value = undefined;
        cache.at = 0;
        cache.dirty = false;
      }
      // Detach an older GET instead of returning it to a caller that asked
      // after the mutation committed. The request may finish normally, but
      // its captured generation prevents it from repopulating this cache.
      cache.inflight = null;
    }
  }

  // Every POST except log reads mutates coordinator state (leases, servers,
  // docker). Cached inventory/servers snapshots must not outlive a mutation,
  // or the UI shows pre-mutation state until the cache window expires.
  function isMutation(method, apiPath) {
    return method !== 'GET' && !apiPath.endsWith('/logs');
  }

  async function request(method, apiPath, body, { timeoutMs, responseMode = 'json' } = {}) {
    if (closed) throw new CoordError('coordinator client is closed');
    const ms = timeoutMs ?? coordinatorTimeoutFor(apiPath);
    const result = await attempt(method, apiPath, body ?? null, ms, responseMode);
    if (isMutation(method, apiPath)) {
      // The periodic host observation changes telemetry, but blanking the
      // only usable inventory snapshot makes the Console flash a cold-loading
      // screen every sampling interval. Keep that snapshot as stale while the
      // next read refreshes it. User-triggered mutations still invalidate
      // strictly so their completion cannot reveal pre-mutation state.
      invalidateCaches({ preserveInventory: apiPath === '/v1/observe' });
    }
    return result;
  }

  // Liveness uses the same trusted loopback transport as the API namespace.
  async function probe() {
    try {
      const res = await fetch(`${baseUrl}/healthz`, {
        method: 'GET',
        signal: AbortSignal.timeout(2000),
      });
      await res.arrayBuffer().catch(() => {});
      if (res.status === 200) {
        noteAlive();
        return true;
      }
      return false;
    } catch (err) {
      noteDown(new CoordError(`coordinator probe failed: ${failureCode(err) ?? err?.message ?? err}`));
      return false;
    }
  }

  function spawnCoordinator() {
    const url = new URL(config.coordinatorUrl);
    const port = url.port || (url.protocol === 'https:' ? '443' : '80');
    const logFile = autostartLogPath();
    fs.mkdirSync(path.dirname(logFile), { recursive: true });
    const outFd = fs.openSync(logFile, 'a');
    const env = { ...process.env };
    if (config.coordinatorHome) env.CODEX_AGENT_COORDINATOR_HOME = config.coordinatorHome;
    let child;
    try {
      const args = [
        config.coordinatorScript,
        'api',
        'serve',
        '--host',
        '127.0.0.1',
        '--port',
        String(port),
      ];
      child = spawn(
        'python3',
        args,
        { detached: true, stdio: ['ignore', outFd, outFd], env },
      );
    } finally {
      // spawn dups the fd; our copy is no longer needed.
      fs.closeSync(outFd);
    }
    child.on('error', (err) => {
      ok = false;
      lastError = `coordinator autostart process error: ${err?.message ?? err}`;
      clog?.warn?.('coordinator autostart process error', { error: String(err?.message ?? err) });
    });
    child.unref();
    return child;
  }

  async function ensureRunningInner() {
    if (closed) return { ok: false, autostarted: false, error: 'coordinator client is closed' };
    if (await probe()) return { ok: true, autostarted: false };
    if (!config.coordinatorAutostart) {
      return {
        ok: false,
        autostarted: false,
        error: lastError ?? 'coordinator is not running and autostart is disabled',
      };
    }
    const now = Date.now();
    if (now - lastSpawnAt < 30_000) {
      return {
        ok: false,
        autostarted: false,
        error: 'coordinator is not running; autostart was already attempted in the last 30s',
      };
    }
    lastSpawnAt = now;
    let child;
    try {
      child = spawnCoordinator();
    } catch (err) {
      const msg = `coordinator autostart failed: ${err?.message ?? err}`;
      ok = false;
      lastError = msg;
      clog?.error?.('coordinator autostart spawn failed', { error: String(err?.message ?? err) });
      return { ok: false, autostarted: false, error: msg };
    }
    autostarted = true;
    clog?.info?.('coordinator autostarted', {
      pid: child.pid ?? null,
      port: new URL(config.coordinatorUrl).port || null,
      log: autostartLogPath(),
    });
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      await delay(500);
      if (closed) return { ok: false, autostarted: true, error: 'coordinator client is closed' };
      if (await probe()) return { ok: true, autostarted: true };
    }
    const msg = `coordinator did not become ready within 15s after autostart (log: ${autostartLogPath()})`;
    ok = false;
    lastError = msg;
    return { ok: false, autostarted: true, error: msg };
  }

  function ensureRunning() {
    if (!ensureInflight) {
      ensureInflight = ensureRunningInner().finally(() => {
        ensureInflight = null;
      });
    }
    return ensureInflight;
  }

  function startCachedGet(cache, apiPath, onValue = null) {
    if (cache.inflight) return cache.inflight;
    const generation = cache.generation;
    const inflight = request('GET', apiPath)
      .then((value) => {
        if (cache.generation === generation) {
          cache.value = value;
          cache.at = Date.now();
          cache.dirty = false;
          cache.retained = false;
          onValue?.(value);
        }
        return value;
      })
      .finally(() => {
        if (cache.inflight === inflight) cache.inflight = null;
      });
    cache.inflight = inflight;
    return inflight;
  }

  function cachedGet(cache, apiPath, maxAgeMs, onValue = null) {
    if (!cache.dirty && cache.value !== undefined && Date.now() - cache.at <= maxAgeMs) {
      return Promise.resolve(cache.value);
    }
    return startCachedGet(cache, apiPath, onValue);
  }

  function inventory({ maxAgeMs = 5000 } = {}) {
    return cachedGet(invCache, '/v1/inventory', maxAgeMs)
      .then((value) => consoleInventoryView(value, trustedDockerObservations));
  }

  /**
   * Read inventory for the latency-sensitive Console overview.
   *
   * A current or bounded-stale snapshot returns immediately while one
   * coalesced refresh runs in the background. A cold cache waits only for the
   * supplied first-byte budget; the same in-flight request continues warming
   * the cache after this method returns `loading`.
   */
  async function inventoryForOverview({
    maxAgeMs = 5000,
    maxStaleMs = 300_000,
    maxWaitMs = 40,
  } = {}) {
    const now = Date.now();
    const ageMs = invCache.value === undefined ? null : Math.max(0, now - invCache.at);
    const project = (value) => consoleOverviewInventoryView(value, trustedDockerObservations);
    const failureCooldownMs = (failure) => failure?.error?.classification === 'maintenance'
      ? Math.max(1000, Math.min(60_000, (failure.error.retryAfterSeconds ?? 30) * 1000))
      : 1000;
    if (
      inventoryOverviewFailure
      && now - inventoryOverviewFailure.at >= failureCooldownMs(inventoryOverviewFailure)
    ) {
      inventoryOverviewFailure = null;
    }
    if (inventoryOverviewFailure && (
      invCache.value === undefined
      || inventoryOverviewFailure.error?.classification === 'maintenance'
    )) {
      if (invCache.value === undefined) {
        return {
          inventory: null,
          state: 'error',
          ageMs: null,
          refreshing: false,
          error: inventoryOverviewFailure.error,
        };
      }
      try {
        return {
          inventory: project(invCache.value),
          state: 'stale',
          ageMs,
          refreshing: false,
          error: inventoryOverviewFailure.error,
        };
      } catch (error) {
        return { inventory: null, state: 'error', ageMs, refreshing: false, error };
      }
    }
    if (!invCache.dirty && invCache.value !== undefined && ageMs <= maxAgeMs) {
      try {
        return {
          inventory: project(invCache.value), state: 'fresh', ageMs, refreshing: false, error: null,
        };
      } catch (error) {
        return {
          inventory: null, state: 'error', ageMs, refreshing: false, error,
        };
      }
    }

    const refresh = cachedGet(invCache, '/v1/inventory', maxAgeMs)
      .then((value) => {
        inventoryOverviewFailure = null;
        return { inventory: project(value), error: null };
      })
      .catch((error) => {
        inventoryOverviewFailure = { error, at: Date.now() };
        return { inventory: null, error };
      });
    if (invCache.value !== undefined && ageMs <= maxStaleMs) {
      // Observe rejection inside `refresh` even though the caller gets the
      // retained snapshot immediately.
      void refresh;
      try {
        return {
          inventory: project(invCache.value), state: 'stale', ageMs, refreshing: true, error: null,
        };
      } catch (error) {
        return {
          inventory: null, state: 'error', ageMs, refreshing: true, error,
        };
      }
    }

    const pending = Symbol('inventory-overview-pending');
    const outcome = await Promise.race([
      refresh,
      delay(maxWaitMs, pending, { ref: false }),
    ]);
    if (outcome === pending) {
      return {
        inventory: null, state: 'loading', ageMs: null, refreshing: true, error: null,
      };
    }
    if (outcome.error) {
      return {
        inventory: null, state: 'error', ageMs: null, refreshing: false, error: outcome.error,
      };
    }
    return {
      inventory: outcome.inventory, state: 'fresh', ageMs: 0, refreshing: false, error: null,
    };
  }

  function observeHost(body = {}) {
    const project = typeof body?.project === 'string' ? body.project : '';
    const existing = observationFlights.get(project);
    if (existing) return existing;

    const flight = request('POST', '/v1/observe', body)
      .then((result) => {
        if (
          result?.schema_version === 2
          && ['completed', 'fresh'].includes(result.status)
          && result.observer_domain === FULL_DOCKER_OBSERVER_DOMAIN
          && result.docker_available === true
          && typeof result.host_id === 'string'
          && result.host_id
        ) {
          trustedDockerObservations.set(result.host_id, { ...result });
        }
        return result;
      })
      .finally(() => {
        if (observationFlights.get(project) === flight) observationFlights.delete(project);
      });
    observationFlights.set(project, flight);
    return flight;
  }

  function serversRaw({ maxAgeMs = 3000 } = {}) {
    return cachedGet(srvCache, '/v1/servers', maxAgeMs);
  }

  function events({ after = null, limit = 100 } = {}) {
    if (after !== null && (typeof after !== 'string' || !after || after.length > 1024)) {
      throw new CoordError('event cursor must be a bounded non-empty string', { status: 400 });
    }
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
      throw new CoordError('event limit must be an integer from 1 through 500', { status: 400 });
    }
    const query = new URLSearchParams({ limit: String(limit) });
    if (after !== null) query.set('after', after);
    return request('GET', `/v1/events?${query.toString()}`);
  }

  function testRepositories({ maxAgeMs = 30_000 } = {}) {
    return cachedGet(
      testRepositoryCache,
      '/v1/test-repositories',
      maxAgeMs,
    );
  }

  function testPlan({ repoId, intent, requestedTargets = [], operationId, source } = {}) {
    if (typeof repoId !== 'string' || !repoId || repoId.length > 256) {
      throw new CoordError('test planning requires one immutable repository id', { status: 400 });
    }
    if (!['change', 'checkpoint', 'handoff', 'release', 'manual'].includes(intent)) {
      throw new CoordError('test planning intent is invalid', { status: 400 });
    }
    if (!Array.isArray(requestedTargets) || requestedTargets.length > 256) {
      throw new CoordError('test planning targets must be a bounded array', { status: 400 });
    }
    const targets = requestedTargets.map((target) => {
      if (
        typeof target !== 'string'
        || !target.trim()
        || Buffer.byteLength(target.trim(), 'utf8') > 128
        || /[\u0000-\u001f\u007f]/.test(target)
      ) {
        throw new CoordError('test planning target names are invalid', { status: 400 });
      }
      return target.trim();
    });
    if (new Set(targets).size !== targets.length) {
      throw new CoordError('test planning targets must be unique', { status: 400 });
    }
    if (targets.length && intent !== 'manual') {
      throw new CoordError('explicit test targets are supported only for manual intent', { status: 400 });
    }
    if (
      typeof operationId !== 'string'
      || !RUNTIME_ARTIFACT_ID_RE.test(operationId)
      || operationId.toLowerCase() !== operationId
    ) {
      throw new CoordError('test planning requires one canonical operation UUID', { status: 400 });
    }
    if (!source || typeof source !== 'object' || Array.isArray(source)
      || source.schemaVersion !== 1
      || !['original', 'temporary'].includes(source.kind)
      || typeof source.repositoryId !== 'string'
      || !source.repositoryId
      || source.repositoryId.length > 256
      || !Number.isInteger(source.repositoryGeneration)
      || source.repositoryGeneration < 0
      || (source.kind === 'original' && source.repositoryId !== repoId)) {
      throw new CoordError('test planning requires one typed repository source', { status: 400 });
    }
    const sourceKeys = Object.keys(source).sort();
    if (sourceKeys.join(',') !== [
      'kind', 'repositoryGeneration', 'repositoryId', 'schemaVersion', 'temporaryRoot',
    ].sort().join(',')
      || (source.temporaryRoot !== null && source.temporaryRoot !== undefined
        && (typeof source.temporaryRoot !== 'string' || !source.temporaryRoot.startsWith('/')))
      || (source.kind === 'original' && source.temporaryRoot != null)
      || (source.kind === 'temporary' && typeof source.temporaryRoot !== 'string')) {
      throw new CoordError('test planning repository source fields are invalid', { status: 400 });
    }
    return request('POST', '/v1/test-plan', {
      repo_id: repoId,
      intent,
      operation_id: operationId,
      source: {
        schema_version: 1,
        kind: source.kind,
        repository_id: source.repositoryId,
        repository_generation: source.repositoryGeneration,
      },
      ...(targets.length ? { requested_targets: targets } : {}),
    });
  }

  function submitTestRun({ repoId, planId, operationId, actor } = {}) {
    if (typeof repoId !== 'string' || !repoId || repoId.length > 256) {
      throw new CoordError('test submission requires one immutable repository id', { status: 400 });
    }
    if (typeof planId !== 'string' || !planId || planId.length > 255) {
      throw new CoordError('test submission requires one bounded plan id', { status: 400 });
    }
    if (typeof operationId !== 'string' || !operationId || operationId.length > 64) {
      throw new CoordError('test submission requires one operation id', { status: 400 });
    }
    if (typeof actor !== 'string' || !actor || actor.length > 256 || /[\u0000-\u001f\u007f]/.test(actor)) {
      throw new CoordError('test submission requires one bounded actor', { status: 400 });
    }
    return request('POST', '/v1/test-runs', {
      repo_id: repoId, plan_id: planId, operation_id: operationId, actor,
    });
  }

  function testRuns({ repoId, after = null, limit = 50, state = null } = {}) {
    if (typeof repoId !== 'string' || !repoId || repoId.length > 256) {
      throw new CoordError('test run history requires one immutable repository id', { status: 400 });
    }
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
      throw new CoordError('test run history limit must be 1 through 200', { status: 400 });
    }
    if (after !== null && (typeof after !== 'string' || !after || after.length > 256)) {
      throw new CoordError('test run history cursor is invalid', { status: 400 });
    }
    if (state !== null && ![
      'queued', 'running', 'cancelling', 'superseding', 'succeeded', 'failed',
      'timed_out', 'cancelled', 'incomplete', 'abandoned', 'superseded',
    ].includes(state)) {
      throw new CoordError('test run history state is invalid', { status: 400 });
    }
    const query = new URLSearchParams({ repo_id: repoId, limit: String(limit) });
    if (after !== null) query.set('after', String(after));
    if (state !== null) query.set('state', String(state));
    return request('GET', `/v1/test-runs?${query.toString()}`);
  }

  function validateTestRunIdentity(repoId, runId) {
    if (typeof repoId !== 'string' || !repoId || repoId.length > 256) {
      throw new CoordError('test run read requires one immutable repository id', { status: 400 });
    }
    if (typeof runId !== 'string' || !runId || runId.length > 256) {
      throw new CoordError('test run read requires one bounded run id', { status: 400 });
    }
  }

  function testRunReadPath(repoId, runId, suffix = '', query = null) {
    validateTestRunIdentity(repoId, runId);
    const parameters = new URLSearchParams({ repo_id: repoId });
    for (const [name, value] of query || []) parameters.append(name, value);
    return `/v1/test-runs/${encodeURIComponent(runId)}${suffix}?${parameters.toString()}`;
  }

  function testRunStatus({ repoId, runId } = {}) {
    return request('GET', testRunReadPath(repoId, runId));
  }

  function testRunSummary({ repoId, runId } = {}) {
    return request('GET', testRunReadPath(repoId, runId, '/summary'));
  }

  function testRunEvidence(kind, { repoId, runId, after = null, limit = 50 } = {}) {
    if (!['failures', 'artifacts', 'cases'].includes(kind)) {
      throw new CoordError('test evidence kind is invalid', { status: 400 });
    }
    if (!Number.isInteger(limit) || limit < 1 || limit > 50) {
      throw new CoordError('test evidence limit must be 1 through 50', { status: 400 });
    }
    if (kind === 'cases') {
      if (after !== null && (!Number.isInteger(after) || after < 0)) {
        throw new CoordError('test case cursor is invalid', { status: 400 });
      }
    } else if (after !== null && (typeof after !== 'string' || !after || after.length > 256)) {
      throw new CoordError('test evidence cursor is invalid', { status: 400 });
    }
    const query = new URLSearchParams({ limit: String(limit) });
    if (after !== null) query.set('after', String(after));
    return request('GET', testRunReadPath(repoId, runId, `/${kind}`, query));
  }

  function cancelTestRun({ repoId, runId, reason, operationId, actor } = {}) {
    validateTestRunIdentity(repoId, runId);
    if (typeof reason !== 'string' || !reason || reason.length > 512 || /[\u0000-\u001f\u007f]/.test(reason)) {
      throw new CoordError('test cancellation requires one bounded reason', { status: 400 });
    }
    validateTestMutation(operationId, actor);
    return request('POST', `/v1/test-runs/${encodeURIComponent(runId)}/cancel`, {
      repo_id: repoId, reason, operation_id: operationId, actor,
    });
  }

  function retryTestRun({ repoId, runId, failedOnly = true, operationId, actor } = {}) {
    validateTestRunIdentity(repoId, runId);
    if (typeof failedOnly !== 'boolean') {
      throw new CoordError('test retry failed-only flag is invalid', { status: 400 });
    }
    validateTestMutation(operationId, actor);
    return request('POST', `/v1/test-runs/${encodeURIComponent(runId)}/retry`, {
      repo_id: repoId, failed_only: failedOnly, operation_id: operationId, actor,
    });
  }

  function validateTestMutation(operationId, actor) {
    if (typeof operationId !== 'string' || !operationId || operationId.length > 64) {
      throw new CoordError('test mutation requires one operation id', { status: 400 });
    }
    if (typeof actor !== 'string' || !actor || actor.length > 256 || /[\u0000-\u001f\u007f]/.test(actor)) {
      throw new CoordError('test mutation requires one bounded actor', { status: 400 });
    }
  }

  async function testRepositorySetup({ repoId } = {}) {
    if (typeof repoId !== 'string' || !repoId || repoId.length > 256) {
      throw new CoordError('test setup requires one immutable repository id', { status: 400 });
    }
    const apiPath = `/v1/test-repositories/${encodeURIComponent(repoId)}/setup`;
    try {
      return await request('GET', apiPath);
    } catch (error) {
      if (
        !(error instanceof CoordError)
        || !TRANSIENT_TEST_SETUP_CODES.has(error.code)
        || ![502, 503].includes(error.status)
      ) throw error;
      // The first request after a cutover may activate testd and snapshotd at
      // the same time. This read is idempotent, so hide that one bounded cold
      // activation race instead of surfacing a global Console error.
      const hintedDelayMs = Number.isFinite(error.retryAfterSeconds)
        ? error.retryAfterSeconds * 1_000
        : TEST_SETUP_RETRY_MIN_DELAY_MS;
      const delayMs = Math.min(
        TEST_SETUP_RETRY_MAX_DELAY_MS,
        Math.max(TEST_SETUP_RETRY_MIN_DELAY_MS, hintedDelayMs),
      );
      clog?.warn?.('test setup cold activation retry', {
        repoId,
        code: error.code,
        status: error.status,
        delayMs,
        attempts: 1,
      });
      await delay(delayMs);
      try {
        const value = await request('GET', apiPath);
        clog?.info?.('test setup cold activation recovered', {
          repoId,
          initialCode: error.code,
          initialStatus: error.status,
          delayMs,
          attempts: 2,
        });
        return value;
      } catch (retryError) {
        clog?.error?.('test setup cold activation retry failed', {
          repoId,
          initialCode: error.code,
          initialStatus: error.status,
          finalCode: retryError instanceof CoordError ? retryError.code : null,
          finalStatus: retryError instanceof CoordError ? retryError.status : null,
          delayMs,
          attempts: 2,
          error: String(retryError?.message ?? retryError),
        });
        throw retryError;
      }
    }
  }

  function testEvents({ repoId, after = 0, limit = 200 } = {}) {
    if (typeof repoId !== 'string' || !repoId || repoId.length > 256) {
      throw new CoordError('test events require one immutable repository id', { status: 400 });
    }
    if (!Number.isInteger(after) || after < 0 || !Number.isInteger(limit) || limit < 1 || limit > 500) {
      throw new CoordError('test event cursor or limit is invalid', { status: 400 });
    }
    const query = new URLSearchParams({ repo_id: repoId, after: String(after), limit: String(limit) });
    return request('GET', `/v1/test-events?${query.toString()}`);
  }

  function withTestSnapshotDelivery(value, cache, state, refreshing) {
    if (!value?.snapshot || typeof value.snapshot !== 'object') return value;
    return {
      ...value,
      snapshot: {
        ...value.snapshot,
        delivery: {
          state,
          age_seconds: Math.max(0, Math.round((Date.now() - cache.at) / 1000)),
          refreshing,
        },
      },
    };
  }

  function cachedTestSnapshot({
    cache,
    apiPath,
    maxAgeMs,
    maxStaleMs,
    onRefreshError,
  }) {
    const ageMs = cache.value === undefined ? Number.POSITIVE_INFINITY : Date.now() - cache.at;
    if (cache.value !== undefined && ageMs <= maxStaleMs) {
      if (cache.retained === true || ageMs >= maxAgeMs) {
        // A usable completed projection must stay on the response path while
        // its replacement is fetched. startCachedGet coalesces concurrent
        // refreshes; the live promise is the exact refreshing signal.
        startCachedGet(cache, apiPath, persistTestStatsSnapshots).catch(onRefreshError);
      }
      return Promise.resolve(withTestSnapshotDelivery(
        cache.value,
        cache,
        'retained',
        cache.inflight !== null,
      ));
    }

    // Only callers that had no usable completed projection and therefore
    // awaited the Coordinator read receive a fresh delivery.
    return startCachedGet(cache, apiPath, persistTestStatsSnapshots)
      .then((value) => withTestSnapshotDelivery(value, cache, 'fresh', false));
  }

  function testStats({
    project,
    days = 30,
    limit = 25,
    maxAgeMs = 30_000,
    maxStaleMs = TEST_STATS_MAX_STALE_MS,
  } = {}) {
    if (typeof project !== 'string' || !project || project.length > 4096) {
      throw new CoordError('test statistics require one bounded project identity', { status: 400 });
    }
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
      throw new CoordError('test statistics days must be an integer from 1 through 3650', { status: 400 });
    }
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
      throw new CoordError('test statistics limit must be an integer from 1 through 500', { status: 400 });
    }
    const query = new URLSearchParams({ project, days: String(days), limit: String(limit) });
    const key = query.toString();
    let cache = testStatsCaches.get(key);
    if (!cache) {
      cache = { value: undefined, at: 0, inflight: null, generation: 0, retained: false };
      testStatsCaches.set(key, cache);
      if (testStatsCaches.size > 128) testStatsCaches.delete(testStatsCaches.keys().next().value);
    }
    const apiPath = `/v1/tests?${key}`;
    return cachedTestSnapshot({
      cache,
      apiPath,
      maxAgeMs,
      maxStaleMs,
      onRefreshError: (err) => {
        clog?.warn?.('test statistics refresh failed; serving retained data', {
          project,
          error: String(err?.message ?? err),
        });
      },
    });
  }

  function testFleet({
    hours = 24,
    maxAgeMs = 15_000,
    maxStaleMs = TEST_STATS_MAX_STALE_MS,
  } = {}) {
    if (!Number.isInteger(hours) || hours < 1 || hours > 168) {
      throw new CoordError('fleet test statistics hours must be an integer from 1 through 168', {
        status: 400,
      });
    }
    const query = new URLSearchParams({ hours: String(hours) });
    const key = `fleet:${query.toString()}`;
    let cache = testStatsCaches.get(key);
    if (!cache) {
      cache = { value: undefined, at: 0, inflight: null, generation: 0, retained: false };
      testStatsCaches.set(key, cache);
      if (testStatsCaches.size > 128) testStatsCaches.delete(testStatsCaches.keys().next().value);
    }
    const apiPath = `/v1/test-fleet?${query.toString()}`;
    return cachedTestSnapshot({
      cache,
      apiPath,
      maxAgeMs,
      maxStaleMs,
      onRefreshError: (err) => {
        clog?.warn?.('fleet test statistics refresh failed; serving retained data', {
          error: String(err?.message ?? err),
        });
      },
    });
  }

  async function dockerAction(name, action, body = {}) {
    // Defense in depth for the "fixed endpoint set" invariant: only these
    // three container actions may form a coordinator path.
    if (!DOCKER_ACTIONS.has(action)) {
      throw new CoordError(`unsupported docker action '${action}'`, { status: 400 });
    }
    return request('POST', `/v1/docker/${action}`, { container: name, ...body });
  }

  async function projectAction(action, body = {}) {
    // Same invariant: only the three whole-project runtime verbs form a path.
    if (!PROJECT_ACTIONS.has(action)) {
      throw new CoordError(`unsupported project action '${action}'`, { status: 400 });
    }
    const result = await request('POST', `/v1/projects/${action}`, body);
    if (result?.ok === false) {
      const details = Array.isArray(result.action_errors)
        ? result.action_errors
          .map((item) => item?.error || item?.classification || item?.name)
          .filter(Boolean)
          .join('; ')
        : '';
      const state = result.partial ? 'partially completed' : result.preflight_failed ? 'failed preflight' : 'failed';
      throw new CoordError(
        `project ${action} ${state}: ${details || result.classification || 'coordinator reported failure'}`,
        { status: 409, body: result },
      );
    }
    return result;
  }

  function runtimeArtifact(kind, id) {
    if (!RUNTIME_ARTIFACT_KINDS.has(kind)) {
      throw new CoordError('unsupported runtime artifact kind', { status: 400 });
    }
    if (typeof id !== 'string' || !RUNTIME_ARTIFACT_ID_RE.test(id)) {
      throw new CoordError('runtime artifact id must be a UUID', { status: 400 });
    }
    return request(
      'GET',
      `/v1/runtime/artifacts/${kind}/${encodeURIComponent(id.toLowerCase())}`,
      null,
      { responseMode: 'runtime-artifact' },
    );
  }

  function runtimeAction(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      throw new CoordError('runtime request must be an object', { status: 400 });
    }
    return request('POST', '/v1/runtime', body);
  }

  function lifecycleResult(action, result) {
    const status = String(result?.status ?? '').toLowerCase();
    const failedStatus = new Set(['blocked', 'failed', 'needs_attention', 'partial']);
    if (
      result?.ok === false
      || result?.partial === true
      || result?.needs_attention === true
      || failedStatus.has(status)
    ) {
      const errors = Array.isArray(result?.action_errors)
        ? result.action_errors
          .map((item) => item?.error || item?.message || item?.classification || item?.name)
          .filter(Boolean)
        : [];
      if (Array.isArray(result?.errors)) {
        errors.push(...result.errors
          .map((item) => typeof item === 'string' ? item : item?.error || item?.message || item?.code)
          .filter(Boolean));
      }
      const blockers = Array.isArray(result?.blockers)
        ? result.blockers
          .map((item) => typeof item === 'string' ? item : item?.message || item?.error || item?.code)
          .filter(Boolean)
        : [];
      throw new CoordError(
        `lifecycle ${action} ${status || 'failed'}: ${[...errors, ...blockers].join('; ') || 'coordinator reported incomplete work'}`,
        { status: 409, body: result },
      );
    }
    return result;
  }

  function status() {
    return { ok, url: baseUrl, autostarted, lastError, lastOkAt };
  }

  function close() {
    closed = true;
    for (const ac of pendingAborts) ac.abort();
    pendingAborts.clear();
    observationFlights.clear();
    trustedDockerObservations.clear();
  }

  return {
    ensureRunning,
    probe,
    inventory,
    inventoryForOverview,
    serversRaw,
    events,
    testRepositories,
    testPlan,
    submitTestRun,
    testRuns,
    testRunStatus,
    testRunSummary,
    testRunFailures: (options = {}) => testRunEvidence('failures', options),
    testRunArtifacts: (options = {}) => testRunEvidence('artifacts', options),
    testRunCases: (options = {}) => testRunEvidence('cases', options),
    cancelTestRun,
    retryTestRun,
    testRepositorySetup,
    testEvents,
    testStats,
    testFleet,
    observeHost,
    request,
    leasePort: (b = {}) => request('POST', '/v1/ports/lease', b),
    releasePort: (b = {}) => request('POST', '/v1/ports/release', b),
    unassignPort: (b = {}) => request('POST', '/v1/ports/unassign', b),
    serverStart: (b = {}) => request('POST', '/v1/servers/start', b),
    serverStop: (b = {}) => request('POST', '/v1/servers/stop', b),
    serverRestart: (b = {}) => request('POST', '/v1/servers/restart', b),
    serverLogs: (b = {}) => request('POST', '/v1/servers/logs', b),
    serverRegister: (b = {}) => request('POST', '/v1/servers/register', b),
    dockerAction,
    projectAction,
    projectStatus: (b = {}) => request('POST', '/v1/projects/status', b),
    dockerLogs: (b = {}) => request('POST', '/v1/docker/logs', b),
    runtimeAction,
    runtimeArtifact,
    lifecycleArchives: () => request('GET', '/v1/archives'),
    lifecyclePlan: (b = {}) => request('POST', '/v1/lifecycle/plan', b),
    lifecycleApply: async (b = {}) => lifecycleResult(
      'apply', await request('POST', '/v1/lifecycle/apply', b),
    ),
    lifecycleRestore: async (b = {}) => lifecycleResult(
      'restore', await request('POST', '/v1/lifecycle/restore', b),
    ),
    status,
    close,
  };
}
