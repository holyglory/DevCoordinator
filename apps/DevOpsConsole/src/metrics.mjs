// In-memory CPU/memory history for coordinator-managed servers, Docker
// containers and per-project usage. A background sampler pulls the (cached)
// coordinator inventory on a fixed interval; every successful /api/overview
// inventory fetch is also ingested so charts stay fresh while someone is
// watching. History lives only in this process: it resets on console restart
// and an entity's points age out after the retention window.

export const METRICS_MAX_POINTS = 720; // ring capacity per entity

const MIN_INTERVAL_MS = 2000;

function num(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function isContainerRunning(container) {
  return /^\s*up\b/i.test(String(container?.status ?? ''));
}

export function createMetricsStore({ config, log, coordinator, maxPoints = METRICS_MAX_POINTS } = {}) {
  const mlog = typeof log?.child === 'function' ? log.child({ mod: 'metrics' }) : log;
  const intervalMs = Math.max(MIN_INTERVAL_MS, Number(config?.metricsIntervalMs) || 10_000);
  const retentionMs = maxPoints * intervalMs;

  // key -> { key, kind, id, name, project, points: [{t, cpu, mem}], lastSeen }
  const entities = new Map();

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
      record(
        `proj:${key}`,
        { kind: 'project', id: null, name: row.name ?? null, project: row.project ?? null },
        t,
        num(row.cpu_percent) ?? 0,
        num(row.memory_bytes) ?? 0,
        dedupe,
      );
    }

    prune(t);
  }

  /** One sampler tick: fetch (possibly cached) inventory and ingest it. */
  async function sampleOnce() {
    if (sampling) return;
    sampling = true;
    try {
      const inventoryData = await coordinator.inventory({
        maxAgeMs: Math.max(1000, Math.floor(intervalMs / 2)),
      });
      ingest(inventoryData);
      lastSampleAt = Date.now();
      lastError = null;
    } catch (err) {
      // Coordinator down: keep the buffers, note the failure, retry next tick.
      lastError = err?.message ?? String(err);
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
      entities: out,
    };
  }

  return { ingest, sampleOnce, start, stop, history, intervalMs };
}
