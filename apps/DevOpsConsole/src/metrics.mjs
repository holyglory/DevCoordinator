// In-memory CPU/memory history for coordinator-managed servers, Docker
// containers and per-project usage. A background sampler first commits one
// explicit host observation, then pulls the coordinator's pure inventory on a
// fixed interval; every successful /api/overview inventory fetch is also
// ingested so charts stay fresh while someone is watching. History lives only
// in this process: it resets on console restart and an entity's points age out
// after the retention window.

import { createHostProbe } from './host.mjs';
import { isDockerContainerRunningStatus } from './docker-status.mjs';

export const METRICS_MAX_POINTS = 720; // ring capacity per entity

const MIN_INTERVAL_MS = 2000;

function num(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function isContainerRunning(container) {
  return isDockerContainerRunningStatus(container?.status);
}

export function createMetricsStore({ config, log, coordinator, host, maxPoints = METRICS_MAX_POINTS } = {}) {
  const mlog = typeof log?.child === 'function' ? log.child({ mod: 'metrics' }) : log;
  const intervalMs = Math.max(MIN_INTERVAL_MS, Number(config?.metricsIntervalMs) || 10_000);
  const retentionMs = maxPoints * intervalMs;
  const hostProbe = host ?? createHostProbe();

  // key -> { key, kind, id, name, project, points: [{t, cpu, mem}], lastSeen }
  const entities = new Map();

  // Latest full machine reading (cpu/mem/load/disks/uptime); the cpu/mem
  // pair also lands in the 'host' history ring above.
  let hostNow = null;

  let timer = null;
  let sampling = false;
  let lastSampleAt = null;
  let lastError = null;

  function record(key, meta, t, cpu, mem, dedupe) {
    let entity = entities.get(key);
    if (!entity) {
      entity = { key, points: [], ...meta };
      entities.set(key, entity);
    }
    Object.assign(entity, meta);
    entity.lastSeen = t;
    const points = entity.points;
    const last = points[points.length - 1];
    if (dedupe && last && t - last.t < intervalMs * 0.6) {
      // A fresher reading inside the sampling window replaces the last point
      // instead of piling up sub-interval points (overview polls piggyback).
      last.t = t;
      last.cpu = cpu;
      last.mem = mem;
      return;
    }
    points.push({ t, cpu, mem });
    if (points.length > maxPoints) points.splice(0, points.length - maxPoints);
  }

  function prune(now) {
    for (const [key, entity] of entities) {
      if (now - (entity.lastSeen ?? 0) > retentionMs) entities.delete(key);
    }
  }

  /** Feed one coordinator inventory payload into the history buffers. */
  function ingest(inventoryData, { at = Date.now(), dedupe = true } = {}) {
    if (!inventoryData || typeof inventoryData !== 'object') return;
    const t = at;

    for (const server of Array.isArray(inventoryData.servers) ? inventoryData.servers : []) {
      const usage = server?.process_usage;
      if (!server?.id || !usage) continue; // no live pids -> no reading, chart shows a gap
      const cpu = num(usage.cpu_percent);
      const mem = num(usage.memory_bytes ?? usage.rss_bytes);
      if (cpu === null && mem === null) continue;
      record(
        `srv:${server.id}`,
        { kind: 'server', id: server.id, name: server.name ?? null, project: server.project ?? null },
        t,
        cpu ?? 0,
        mem ?? 0,
        dedupe,
      );
    }

    const containers = inventoryData.docker?.available
      ? inventoryData.docker.containers
      : null;
    for (const container of Array.isArray(containers) ? containers : []) {
      const stats = container?.stats;
      if (!container?.name || !stats || !isContainerRunning(container)) continue;
      const cpu = num(stats.cpu_percent);
      const mem = num(stats.memory_usage_bytes);
      if (cpu === null && mem === null) continue;
      record(
        `dock:${container.name}`,
        {
          kind: 'docker',
          id: container.id ?? null,
          name: container.name,
          project: container.project ?? container.compose_project ?? null,
        },
        t,
        cpu ?? 0,
        mem ?? 0,
        dedupe,
      );
    }

    for (const row of Array.isArray(inventoryData.project_usage) ? inventoryData.project_usage : []) {
      // usage_key is the unique identity; project_key is a display name that
      // can collide (two repos named "app") and would merge their histories.
      const key = row?.usage_key ?? row?.project_key ?? row?.project ?? row?.name;
      if (!key) continue;
      const cpu = num(row.cpu_percent);
      const mem = num(row.memory_bytes);
      if (cpu === null && mem === null) continue;
      record(
        `proj:${key}`,
        { kind: 'project', id: null, name: row.name ?? null, project: row.project ?? null },
        t,
        cpu ?? 0,
        mem ?? 0,
        dedupe,
      );
    }

    prune(t);
  }

  /** Record one whole-machine reading (never throws, never blocks charts). */
  async function sampleHost() {
    try {
      const reading = await hostProbe.sample();
      hostNow = reading;
      // First tick has no CPU delta yet — start the ring on the second.
      if (reading.cpuPercent !== null) {
        record(
          'host',
          { kind: 'host', id: null, name: 'this machine', project: null },
          reading.at,
          reading.cpuPercent,
          reading.mem?.usedBytes ?? 0,
          true,
        );
      }
    } catch (err) {
      mlog?.warn?.('host sample failed', { error: err?.message ?? String(err) });
    }
  }

  /** One sampler tick: machine health, explicit host observation, then inventory. */
  async function sampleOnce() {
    if (sampling) return;
    sampling = true;
    let observationError = null;
    try {
      // The machine reading must never depend on coordinator health.
      await sampleHost();
      try {
        await coordinator.observeHost({
          agent: 'devops-console:metrics',
          project: config.projectRoot,
        });
      } catch (err) {
        // A failed observation is unknown host state, not proof that retained
        // containers disappeared. Still read and ingest the last atomically
        // committed inventory, but keep the failure visible to the operator.
        observationError = err;
      }
      const inventoryData = await coordinator.inventory({
        maxAgeMs: Math.max(1000, Math.floor(intervalMs / 2)),
      });
      ingest(inventoryData);
      lastSampleAt = Date.now();
      lastError = observationError
        ? `host observation failed; using last committed inventory: ${observationError?.message ?? String(observationError)}`
        : null;
    } catch (err) {
      // Coordinator down: keep the buffers, note the failure, retry next tick.
      const inventoryError = err?.message ?? String(err);
      lastError = observationError
        ? `host observation failed: ${observationError?.message ?? String(observationError)}; inventory read failed: ${inventoryError}`
        : inventoryError;
    } finally {
      sampling = false;
    }
  }

  function start() {
    if (timer || !coordinator) return;
    timer = setInterval(() => {
      sampleOnce().catch((err) => {
        mlog?.warn?.('metrics sample failed', { error: err?.message ?? String(err) });
      });
    }, intervalMs);
    timer.unref?.();
    sampleOnce().catch(() => {});
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  /**
   * JSON view for GET /api/metrics/history. Points are compact
   * [epochMs, cpuPercent, memoryBytes] triples, oldest first, capped at
   * `limit` per entity.
   */
  function history({ limit = maxPoints } = {}) {
    const capped = Math.max(1, Math.min(maxPoints, Math.floor(limit) || maxPoints));
    const out = [];
    for (const entity of entities.values()) {
      const points = entity.points.slice(-capped).map((p) => [p.t, p.cpu, p.mem]);
      out.push({
        key: entity.key,
        kind: entity.kind,
        id: entity.id ?? null,
        name: entity.name ?? null,
        project: entity.project ?? null,
        points,
      });
    }
    out.sort((a, b) => String(a.key).localeCompare(String(b.key)));
    return {
      now: Date.now(),
      intervalMs,
      maxPoints,
      sampler: {
        running: timer !== null,
        lastSampleAt,
        lastError,
      },
      // Latest whole-machine snapshot (cpu %, mem, load, disks, uptime);
      // its cpu/mem history rides in entities as kind:'host', key 'host'.
      host: hostNow,
      entities: out,
    };
  }

  return { ingest, sampleOnce, start, stop, history, intervalMs };
}
