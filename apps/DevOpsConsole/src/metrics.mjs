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
export const PERFORMANCE_SCHEMA_VERSION = 2;

const MIN_INTERVAL_MS = 2000;
const MIN_PERFORMANCE_STALE_MS = 10_000;
const LIVE_SERVER_STATES = new Set(['running', 'starting', 'unhealthy']);

function num(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function nonnegative(value) {
  const parsed = num(value);
  return parsed !== null && parsed >= 0 ? parsed : null;
}

function timestampMs(...values) {
  for (const value of values) {
    if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
    if (typeof value !== 'string' || !value) continue;
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed) && parsed >= 0) return parsed;
  }
  return null;
}

function resourceFreshness(sampledAt, at, staleAfterMs, intervalMs) {
  if (sampledAt === null) return null;
  return sampledAt >= at - staleAfterMs && sampledAt <= at + intervalMs;
}

function wholeHostCpu(rawPercent, cores) {
  const value = nonnegative(rawPercent);
  return value === null || !(cores > 0) ? null : value / cores;
}

function expectedProcesses(usage) {
  if (!usage || typeof usage !== 'object') return null;
  const parts = [usage.server?.process_count, usage.docker?.process_count]
    .map(nonnegative);
  if (parts.some((value) => value !== null)) {
    return parts.reduce((sum, value) => sum + (value ?? 0), 0);
  }
  return nonnegative(usage.process_count);
}

function usageValues(usage, cores) {
  const memoryBytes = nonnegative(usage?.memory_bytes);
  const cpuRawPercent = nonnegative(usage?.cpu_percent);
  return {
    memoryBytes,
    cpuRawPercent,
    cpuPercent: wholeHostCpu(cpuRawPercent, cores),
  };
}

function contributorFromServer(server, cores, at, staleAfterMs, intervalMs) {
  const usage = server?.process_usage || {};
  const id = server?.id == null ? null : String(server.id);
  const sampledAt = timestampMs(usage.sampled_at);
  const memoryBytes = nonnegative(usage.memory_bytes ?? usage.rss_bytes);
  const cpuRawPercent = nonnegative(usage.cpu_percent);
  const fresh = resourceFreshness(sampledAt, at, staleAfterMs, intervalMs);
  return {
    key: id ? `srv:${id}` : null,
    kind: 'server',
    id,
    name: server?.name ?? id,
    memoryBytes,
    cpuRawPercent,
    cpuPercent: wholeHostCpu(cpuRawPercent, cores),
    sampledAt,
    fresh,
    exact: memoryBytes !== null && cpuRawPercent !== null && fresh === true,
  };
}

function contributorFromContainer(container, cores, at, staleAfterMs, intervalMs) {
  const stats = container?.stats || {};
  const id = container?.host_resource_id == null ? null : String(container.host_resource_id);
  const sampledAt = timestampMs(stats.timestamp);
  const memoryBytes = nonnegative(stats.memory_usage_bytes);
  const cpuRawPercent = nonnegative(stats.cpu_percent);
  return {
    key: id ? `dock:${id}` : null,
    kind: 'docker',
    id,
    name: container?.name ?? id,
    memoryBytes,
    cpuRawPercent,
    cpuPercent: wholeHostCpu(cpuRawPercent, cores),
    sampledAt,
    fresh: resourceFreshness(sampledAt, at, staleAfterMs, intervalMs),
    exact: false,
  };
}

function finalizeContributor(contributor) {
  contributor.exact = contributor.memoryBytes !== null
    && contributor.cpuRawPercent !== null
    && contributor.fresh === true;
  return contributor;
}

function segmentCoverage(contributors, expected, values, aggregateSampleAt, at, staleAfterMs, intervalMs) {
  const measured = contributors.filter((item) => item.memoryBytes !== null || item.cpuRawPercent !== null);
  const complete = contributors.filter((item) => item.exact);
  const staleResources = contributors.filter((item) => item.fresh === false).length;
  const missingTimestampResources = measured.filter((item) => item.sampledAt === null).length;
  const missingResources = expected === null ? null : Math.max(0, expected - measured.length);
  const aggregateFresh = aggregateSampleAt === null
    ? null
    : resourceFreshness(aggregateSampleAt, at, staleAfterMs, intervalMs);
  const explicitIdle = expected === 0
    && values.memoryBytes === 0
    && values.cpuRawPercent === 0;
  const fresh = explicitIdle
    ? true
    : aggregateFresh ?? (measured.length ? measured.every((item) => item.fresh === true) : null);
  return {
    measuredResources: measured.length,
    completeResources: complete.length,
    expectedResources: expected,
    missingResources,
    staleResources,
    missingTimestampResources,
    fresh,
    exact: values.memoryBytes !== null
      && values.cpuRawPercent !== null
      && expected !== null
      && missingResources === 0
      && complete.length >= expected
      && staleResources === 0
      && missingTimestampResources === 0
      && fresh === true,
  };
}

function makeUsageSegment({
  key, kind, familyId = null, repoId = null, name = null, project = null,
  usage, contributors, aggregateSampleAt, expected, duplicateMembership = false,
  at, cores, staleAfterMs, intervalMs, additive = true,
}) {
  const values = usageValues(usage, cores);
  const coverage = segmentCoverage(
    contributors,
    expected,
    values,
    aggregateSampleAt,
    at,
    staleAfterMs,
    intervalMs,
  );
  return {
    key,
    kind,
    familyId,
    repoId,
    name,
    project,
    active: true,
    additive,
    exact: coverage.exact && !duplicateMembership,
    fresh: coverage.fresh,
    sampledAt: aggregateSampleAt
      ?? (contributors.reduce((latest, item) => Math.max(latest, item.sampledAt ?? 0), 0) || null),
    coverage,
    current: {
      memoryBytes: values.memoryBytes,
      stackMemoryBytes: additive ? null : 0,
      cpuPercent: values.cpuPercent,
      stackCpuPercent: additive ? null : 0,
      cpuRawPercent: values.cpuRawPercent,
    },
    contributors,
  };
}

function proportionalStack(segments, observedField, stackField, capacity, { integer = false } = {}) {
  const measured = segments
    .map((segment) => ({ segment, value: nonnegative(segment.current[observedField]) }))
    .filter((item) => item.value !== null);
  const observed = measured.reduce((sum, item) => sum + item.value, 0);
  if (capacity === null) {
    for (const { segment } of measured) segment.current[stackField] = null;
    return { observed, stacked: null, scale: null, overage: null };
  }
  const boundedCapacity = Math.max(0, capacity);
  const scale = observed > boundedCapacity && observed > 0 ? boundedCapacity / observed : 1;
  if (!integer || scale === 1) {
    for (const { segment, value } of measured) segment.current[stackField] = value * scale;
  } else {
    const allocations = measured.map(({ segment, value }) => {
      const scaled = value * scale;
      return { segment, floor: Math.floor(scaled), fraction: scaled - Math.floor(scaled) };
    });
    let remainder = Math.max(0, Math.round(boundedCapacity) - allocations.reduce((sum, item) => sum + item.floor, 0));
    allocations.sort((a, b) => b.fraction - a.fraction
      || String(a.segment.key).localeCompare(String(b.segment.key)));
    for (const allocation of allocations) {
      allocation.segment.current[stackField] = allocation.floor + (remainder > 0 ? 1 : 0);
      if (remainder > 0) remainder -= 1;
    }
  }
  const stacked = measured.reduce(
    (sum, item) => sum + (nonnegative(item.segment.current[stackField]) ?? 0),
    0,
  );
  return {
    observed,
    stacked,
    scale,
    overage: Math.max(0, observed - boundedCapacity),
  };
}

function problemResourceKeys(inventory) {
  const keys = new Set();
  for (const item of [
    ...(Array.isArray(inventory?.unassigned_resources) ? inventory.unassigned_resources : []),
    ...(Array.isArray(inventory?.lifecycle_violations) ? inventory.lifecycle_violations : []),
  ]) {
    const id = item?.resource_id;
    if (id == null) continue;
    if (item.resource_kind === 'server') keys.add(`server:${id}`);
    if (item.resource_kind === 'container') keys.add(`container:${id}`);
  }
  return keys;
}

function performanceMemoryDiagnostics(value) {
  const source = value && typeof value === 'object' ? value : {};
  const meminfoSource = source.meminfo && typeof source.meminfo === 'object'
    ? source.meminfo : {};
  const meminfo = { available: meminfoSource.available === true };
  for (const field of [
    'shmemBytes', 'anonPagesBytes', 'sUnreclaimBytes', 'slabBytes',
    'pageTablesBytes', 'kernelStackBytes',
  ]) {
    meminfo[field] = nonnegative(meminfoSource[field]);
  }
  const schemaVersion = Number(source.schemaVersion ?? source.schema_version) === 2 ? 2 : 1;
  const additiveRoles = new Set([
    'project-runtimes',
    'coordinator-control',
    'coordinator-background',
    'active-test-attempts',
    'developer-sessions',
  ]);
  const normalizeCgroup = (row, depth = 0) => {
    const role = typeof row?.role === 'string' ? row.role
      : (typeof row?.key === 'string' ? row.key : 'unknown');
    const view = {
      key: typeof row?.key === 'string' ? row.key : 'unknown',
      role,
      label: typeof row?.label === 'string' ? row.label : (row?.key ?? 'Unknown'),
      available: row?.available === true,
      additive: schemaVersion >= 2 && row?.additive === true && additiveRoles.has(role),
      overlap: typeof row?.overlap === 'string' ? row.overlap : null,
      sampledAt: timestampMs(row?.sampledAt, row?.sampled_at),
      populated: typeof row?.populated === 'boolean' ? row.populated : null,
      frozen: typeof row?.frozen === 'boolean' ? row.frozen : null,
      childrenAvailable: row?.childrenAvailable !== false && row?.children_available !== false,
      childrenTruncated: row?.childrenTruncated === true || row?.children_truncated === true,
      accountUid: nonnegative(row?.accountUid ?? row?.account_uid),
      accountName: typeof (row?.accountName ?? row?.account_name) === 'string'
        ? (row?.accountName ?? row?.account_name) : null,
    };
    for (const field of [
      'currentBytes', 'inactiveFileBytes', 'workingBytes', 'anonBytes', 'shmemBytes',
      'fileBytes', 'kernelBytes', 'slabBytes', 'pageTablesBytes',
      'kernelStackBytes', 'socketBytes', 'cpuUsageUsec', 'cpuRawPercent',
      'processCount', 'activeChildCount',
    ]) {
      view[field] = nonnegative(row?.[field]);
    }
    view.children = depth >= 2 ? []
      : (Array.isArray(row?.children) ? row.children : [])
        .slice(0, 96)
        .map((child) => normalizeCgroup(child, depth + 1));
    return view;
  };
  const cgroups = (Array.isArray(source.cgroups) ? source.cgroups : [])
    .slice(0, 16)
    .map((row) => normalizeCgroup(row));
  return {
    schemaVersion,
    additive: false,
    overlapping: true,
    stackContributionBytes: 0,
    meminfo,
    cgroups,
  };
}

function cgroupAccountingSegments(diagnostics, cores, at) {
  if (diagnostics?.schemaVersion !== 2) return [];
  return diagnostics.cgroups
    .filter((group) => group.additive === true && group.available === true)
    .map((group) => {
      const memoryBytes = nonnegative(group.workingBytes);
      const cpuRawPercent = nonnegative(group.cpuRawPercent);
      const cpuPercent = wholeHostCpu(cpuRawPercent, cores);
      const processCount = nonnegative(group.processCount);
      const sampledAt = timestampMs(group.sampledAt, at);
      const memoryMeasured = memoryBytes !== null;
      const cpuMeasured = cpuPercent !== null;
      return {
        key: group.role,
        kind: group.role,
        familyId: null,
        repoId: null,
        name: group.label,
        project: null,
        active: group.populated !== false || (memoryBytes ?? 0) > 0,
        additive: true,
        exact: memoryMeasured && cpuMeasured,
        fresh: true,
        sampledAt,
        coverage: {
          measuredResources: processCount ?? 0,
          completeResources: processCount ?? 0,
          expectedResources: processCount,
          missingResources: processCount === null ? null : 0,
          staleResources: 0,
          missingTimestampResources: sampledAt === null ? 1 : 0,
          fresh: true,
          exact: memoryMeasured && cpuMeasured && sampledAt !== null,
        },
        current: {
          memoryBytes,
          stackMemoryBytes: null,
          cpuPercent,
          stackCpuPercent: null,
          cpuRawPercent,
        },
        contributors: [],
        accounting: {
          basis: 'cgroup-v2',
          currentBytes: group.currentBytes,
          workingBytes: group.workingBytes,
          anonBytes: group.anonBytes,
          shmemBytes: group.shmemBytes,
          kernelBytes: group.kernelBytes,
          processCount,
          activeChildCount: group.activeChildCount,
        },
      };
    });
}

function normalizedAgentBrowserInventory(value) {
  if (value === undefined || value === null) return { present: false, valid: false, value: null };
  if (!value || typeof value !== 'object' || Number(value.schema_version) !== 1) {
    return { present: true, valid: false, value: null };
  }
  const sampledAt = timestampMs(value.sampled_at);
  const totalsSource = value.totals && typeof value.totals === 'object' ? value.totals : {};
  const totalFields = [
    'session_count', 'process_count', 'memory_bytes', 'cpu_percent',
    'idle_session_count', 'protected_session_count', 'reaped_total',
    'reclaimed_memory_bytes',
  ];
  const totals = Object.fromEntries(totalFields.map((field) => [field, nonnegative(totalsSource[field])]));
  const policySource = value.policy && typeof value.policy === 'object' ? value.policy : {};
  const policy = {
    idle_timeout_seconds: nonnegative(policySource.idle_timeout_seconds),
    termination_grace_seconds: nonnegative(policySource.termination_grace_seconds),
  };
  const sessionsSource = Array.isArray(value.sessions) ? value.sessions : null;
  const recentReapsSource = Array.isArray(value.recent_reaps) ? value.recent_reaps : null;
  const requiredValues = [sampledAt, ...Object.values(totals), ...Object.values(policy)];
  if (requiredValues.some((item) => item === null)
    || sessionsSource === null || recentReapsSource === null) {
    return { present: true, valid: false, value: null };
  }
  const sessions = sessionsSource.map((session, index) => ({
    sessionId: String(session?.session_id ?? `session-${index + 1}`),
    state: typeof session?.state === 'string' && session.state ? session.state : 'unknown',
    uid: nonnegative(session?.uid),
    cgroupClass: typeof session?.cgroup_class === 'string' ? session.cgroup_class : null,
    agent: typeof session?.agent === 'string' ? session.agent : null,
    repositoryName: typeof session?.repository_name === 'string' ? session.repository_name : null,
    firstSeenAt: timestampMs(session?.first_seen_at),
    lastObservedAt: timestampMs(session?.last_observed_at),
    lastObservedWorkAt: timestampMs(session?.last_observed_work_at),
    idleSeconds: nonnegative(session?.idle_seconds),
    processCount: nonnegative(session?.process_count),
    memoryBytes: nonnegative(session?.memory_bytes),
    cpuPercent: nonnegative(session?.cpu_percent),
    reapEligible: session?.reap_eligible === true,
  }));
  const recentReaps = recentReapsSource.map((reap, index) => ({
    sessionId: String(reap?.session_id ?? `cleanup-${index + 1}`),
    agent: typeof reap?.agent === 'string' ? reap.agent : null,
    repositoryName: typeof reap?.repository_name === 'string' ? reap.repository_name : null,
    reapedAt: timestampMs(reap?.reaped_at, reap?.at),
    reason: typeof reap?.reason === 'string' ? reap.reason : null,
    processCount: nonnegative(reap?.process_count),
    reclaimedMemoryBytes: nonnegative(reap?.reclaimed_memory_bytes ?? reap?.memory_bytes),
  }));
  return {
    present: true,
    valid: true,
    value: {
      schemaVersion: 1,
      sampledAt,
      policy: {
        idleTimeoutSeconds: policy.idle_timeout_seconds,
        terminationGraceSeconds: policy.termination_grace_seconds,
      },
      totals: {
        sessionCount: totals.session_count,
        processCount: totals.process_count,
        memoryBytes: totals.memory_bytes,
        cpuPercent: totals.cpu_percent,
        idleSessionCount: totals.idle_session_count,
        protectedSessionCount: totals.protected_session_count,
        reapedTotal: totals.reaped_total,
        reclaimedMemoryBytes: totals.reclaimed_memory_bytes,
      },
      sessions,
      recentReaps,
    },
  };
}

function compactPerformanceSample(snapshot) {
  const memorySegments = snapshot.segments.map((segment) => ({
    key: segment.key,
    value: segment.current.stackMemoryBytes,
    observedValue: segment.current.memoryBytes,
    exact: segment.exact,
  }));
  const cpuSegments = snapshot.segments.map((segment) => ({
    key: segment.key,
    value: segment.current.stackCpuPercent,
    observedValue: segment.current.cpuPercent,
    exact: segment.exact,
  }));
  return {
    at: snapshot.sampledAt,
    window: snapshot.window,
    sampleSkewMs: snapshot.sampleSkewMs,
    exact: snapshot.exact,
    attributed: snapshot.attributed,
    residual: {
      memoryBytes: snapshot.residual.memoryBytes,
      cpuPercent: snapshot.residual.cpuPercent,
      exact: false,
    },
    coverage: snapshot.coverage,
    memory: { ...snapshot.memory, segments: memorySegments },
    cpu: { ...snapshot.cpu, segments: cpuSegments },
  };
}

/**
 * Build one reconciled whole-host composition from the host reading and the
 * inventory values returned by the same sampler tick. The helper is pure so
 * accounting and degraded-sample behavior can be regression-tested directly.
 */
export function buildPerformanceSnapshot({ host, inventory, at = Date.now(), intervalMs = 10_000 } = {}) {
  const sampledAt = timestampMs(at) ?? Date.now();
  const staleAfterMs = Math.max(MIN_PERFORMANCE_STALE_MS, intervalMs * 2);
  const cores = Number.isInteger(host?.cores) && host.cores > 0 ? host.cores : null;
  const totalBytes = nonnegative(host?.mem?.totalBytes);
  const availableRaw = nonnegative(host?.mem?.availableBytes);
  const availableBytes = totalBytes === null || availableRaw === null
    ? null
    : Math.min(totalBytes, availableRaw);
  // Never substitute RSS sums or plain `free` for Linux host use. The host
  // probe supplies MemAvailable (falling back honestly on non-Linux hosts).
  const usedBytes = totalBytes === null || availableBytes === null
    ? null
    : Math.max(0, totalBytes - availableBytes);
  const memoryBasis = typeof host?.mem?.basis === 'string'
    ? host.mem.basis : 'MemTotal-MemAvailable';
  const memoryDiagnostics = performanceMemoryDiagnostics(host?.mem?.diagnostics);
  const splitCgroupAccounting = memoryDiagnostics.schemaVersion === 2
    && memoryDiagnostics.cgroups.some((group) => group.additive === true);
  const hostCpuUsed = nonnegative(host?.cpuPercent) === null
    ? null
    : Math.min(100, nonnegative(host.cpuPercent));
  const hostCpuAvailable = hostCpuUsed === null ? null : Math.max(0, 100 - hostCpuUsed);
  const hostSampleAt = timestampMs(host?.at);
  const issues = [];
  if (totalBytes === null || availableBytes === null) {
    issues.push({ code: 'host-memory-unavailable', message: 'MemTotal or MemAvailable is unavailable.' });
  }
  if (hostCpuUsed === null || cores === null) {
    issues.push({ code: 'host-cpu-unavailable', message: 'Whole-host CPU or logical core count is unavailable.' });
  }
  if (host && hostSampleAt === null) {
    issues.push({ code: 'host-timestamp-unavailable', message: 'The host sample has no timestamp.' });
  }

  const servers = Array.isArray(inventory?.servers) ? inventory.servers : [];
  const containers = Array.isArray(inventory?.docker?.containers) ? inventory.docker.containers : [];
  const serverById = new Map(servers
    .filter((item) => item?.id != null)
    .map((item) => [String(item.id), item]));
  const containerById = new Map(containers
    .filter((item) => item?.host_resource_id != null)
    .map((item) => [String(item.host_resource_id), item]));
  const claimedServers = new Set();
  const claimedContainers = new Set();
  const segments = [];
  const sampleTimes = hostSampleAt === null ? [] : [hostSampleAt];
  const seenFamilyKeys = new Set();

  const repositoryTreesPresent = Object.hasOwn(inventory || {}, 'repository_trees');
  const trees = Array.isArray(inventory?.repository_trees) ? inventory.repository_trees : [];
  if (repositoryTreesPresent && !Array.isArray(inventory?.repository_trees)) {
    issues.push({
      code: 'repository-families-unavailable',
      message: 'The authoritative repository-family projection is unavailable; legacy rows were not substituted.',
    });
  }
  for (const tree of trees) {
    const root = tree?.root_repository || {};
    const familyId = tree?.family_id ?? root?.repo_id;
    if (familyId == null) {
      issues.push({ code: 'family-identity-missing', message: 'A repository family has no immutable identity.' });
      continue;
    }
    const key = `family:${familyId}`;
    if (seenFamilyKeys.has(key)) {
      issues.push({ code: 'duplicate-family', message: `Repository family ${familyId} was published more than once.` });
      continue;
    }
    seenFamilyKeys.add(key);
    const contributors = [];
    const localServers = new Set();
    const localContainers = new Set();
    let duplicateMembership = false;
    for (const scope of Array.isArray(tree?.scopes) ? tree.scopes : []) {
      for (const rawId of Array.isArray(scope?.server_ids) ? scope.server_ids : []) {
        const id = String(rawId);
        if (localServers.has(id)) duplicateMembership = true;
        localServers.add(id);
        if (claimedServers.has(id)) duplicateMembership = true;
        claimedServers.add(id);
      }
      for (const rawId of Array.isArray(scope?.container_resource_ids) ? scope.container_resource_ids : []) {
        const id = String(rawId);
        if (localContainers.has(id)) duplicateMembership = true;
        localContainers.add(id);
        if (claimedContainers.has(id)) duplicateMembership = true;
        claimedContainers.add(id);
      }
    }
    for (const id of localServers) {
      const server = serverById.get(id);
      if (!server || (!server.process_usage && !LIVE_SERVER_STATES.has(server.status))) continue;
      contributors.push(finalizeContributor(
        contributorFromServer(server, cores, sampledAt, staleAfterMs, intervalMs),
      ));
    }
    for (const id of localContainers) {
      const container = containerById.get(id);
      if (!container || !isContainerRunning(container)) continue;
      contributors.push(finalizeContributor(
        contributorFromContainer(container, cores, sampledAt, staleAfterMs, intervalMs),
      ));
    }
    const aggregateSampleAt = timestampMs(tree?.usage?.sampled_at);
    if (aggregateSampleAt !== null) sampleTimes.push(aggregateSampleAt);
    for (const contributor of contributors) {
      if (contributor.sampledAt !== null) sampleTimes.push(contributor.sampledAt);
    }
    const segment = makeUsageSegment({
      key,
      kind: 'project-family',
      familyId: String(familyId),
      repoId: root?.repo_id == null ? null : String(root.repo_id),
      name: root?.display_name ?? String(familyId),
      project: root?.canonical_root ?? null,
      usage: tree?.usage,
      contributors,
      aggregateSampleAt,
      expected: expectedProcesses(tree?.usage),
      duplicateMembership,
      at: sampledAt,
      cores,
      staleAfterMs,
      intervalMs,
      additive: !splitCgroupAccounting,
    });
    if (duplicateMembership) {
      issues.push({
        code: 'duplicate-family-membership',
        message: `Repository family ${familyId} repeats a resource identity; its aggregate is not exact.`,
      });
    }
    segments.push(segment);
  }

  // Compatibility with older inventories is deliberately one-way: flat
  // project rows are used only when the authoritative field is absent, never
  // alongside family/root/scope aggregates.
  if (!repositoryTreesPresent) {
    const seenProjects = new Set();
    for (const row of Array.isArray(inventory?.project_usage) ? inventory.project_usage : []) {
      const identity = row?.usage_key ?? row?.project_key ?? row?.project ?? row?.name;
      if (!identity) continue;
      const key = `proj:${identity}`;
      if (seenProjects.has(key)) {
        issues.push({ code: 'duplicate-project', message: `Legacy project ${identity} was published more than once.` });
        continue;
      }
      seenProjects.add(key);
      const contributors = [];
      for (const rawId of Array.isArray(row?.server_ids) ? row.server_ids : []) {
        const id = String(rawId);
        claimedServers.add(id);
        const server = serverById.get(id);
        if (server && (server.process_usage || LIVE_SERVER_STATES.has(server.status))) {
          contributors.push(finalizeContributor(
            contributorFromServer(server, cores, sampledAt, staleAfterMs, intervalMs),
          ));
        }
      }
      for (const rawId of Array.isArray(row?.container_resource_ids) ? row.container_resource_ids : []) {
        const id = String(rawId);
        claimedContainers.add(id);
        const container = containerById.get(id);
        if (container && isContainerRunning(container)) {
          contributors.push(finalizeContributor(
            contributorFromContainer(container, cores, sampledAt, staleAfterMs, intervalMs),
          ));
        }
      }
      const aggregateSampleAt = timestampMs(row?.sampled_at, row?.usage?.sampled_at);
      if (aggregateSampleAt !== null) sampleTimes.push(aggregateSampleAt);
      for (const contributor of contributors) {
        if (contributor.sampledAt !== null) sampleTimes.push(contributor.sampledAt);
      }
      segments.push(makeUsageSegment({
        key,
        kind: 'project',
        repoId: row?.repo_id == null ? null : String(row.repo_id),
        name: row?.display_name ?? row?.name ?? String(identity),
        project: row?.project ?? null,
        usage: row,
        contributors,
        aggregateSampleAt,
        expected: expectedProcesses(row?.usage ?? row),
        at: sampledAt,
        cores,
        staleAfterMs,
        intervalMs,
        additive: !splitCgroupAccounting,
      }));
    }
    issues.push({
      code: 'legacy-project-accounting',
      message: 'Project attribution uses legacy flat rows because repository families were not published.',
    });
  }

  segments.sort((a, b) => String(a.name ?? a.key).localeCompare(String(b.name ?? b.key))
    || String(a.key).localeCompare(String(b.key)));

  // Do not infer that every resource missing from a family is control-plane
  // work. Only producer-published ownership problems prove that an exact live
  // resource is outside all repository families; everything else stays in the
  // honest system/unclassified residual.
  const outsideFamily = problemResourceKeys(inventory);
  const otherContributors = [];
  for (const server of servers) {
    const id = server?.id == null ? null : String(server.id);
    if (!id || claimedServers.has(id) || !outsideFamily.has(`server:${id}`)) continue;
    if (!server.process_usage && !LIVE_SERVER_STATES.has(server.status)) continue;
    otherContributors.push(finalizeContributor(
      contributorFromServer(server, cores, sampledAt, staleAfterMs, intervalMs),
    ));
  }
  for (const container of containers) {
    const id = container?.host_resource_id == null ? null : String(container.host_resource_id);
    if (!id || claimedContainers.has(id) || !outsideFamily.has(`container:${id}`)) continue;
    if (!isContainerRunning(container)) continue;
    otherContributors.push(finalizeContributor(
      contributorFromContainer(container, cores, sampledAt, staleAfterMs, intervalMs),
    ));
  }
  for (const contributor of otherContributors) {
    if (contributor.sampledAt !== null) sampleTimes.push(contributor.sampledAt);
  }
  const otherMemory = otherContributors.reduce(
    (sum, item) => sum + (item.memoryBytes ?? 0),
    0,
  );
  const otherCpuRaw = otherContributors.reduce(
    (sum, item) => sum + (item.cpuRawPercent ?? 0),
    0,
  );
  const otherCoverage = segmentCoverage(
    otherContributors,
    otherContributors.length,
    { memoryBytes: otherMemory, cpuRawPercent: otherCpuRaw },
    null,
    sampledAt,
    staleAfterMs,
    intervalMs,
  );
  segments.push({
    key: 'control-other',
    kind: 'control-other',
    familyId: null,
    repoId: null,
    name: 'Control / other',
    project: null,
    active: true,
    additive: !splitCgroupAccounting,
    exact: otherCoverage.exact,
    fresh: otherCoverage.fresh,
    sampledAt: otherContributors.reduce((latest, item) => Math.max(latest, item.sampledAt ?? 0), 0) || null,
    coverage: otherCoverage,
    current: {
      memoryBytes: otherMemory,
      stackMemoryBytes: splitCgroupAccounting ? 0 : null,
      cpuPercent: wholeHostCpu(otherCpuRaw, cores),
      stackCpuPercent: splitCgroupAccounting ? 0 : null,
      cpuRawPercent: otherCpuRaw,
    },
    contributors: otherContributors,
  });

  const agentBrowserInventory = normalizedAgentBrowserInventory(inventory?.agent_browsers);
  if (agentBrowserInventory.present && !agentBrowserInventory.valid) {
    issues.push({
      code: 'agent-browser-accounting-invalid',
      message: 'The non-project agent-browser accounting sample is malformed and was not subtracted from the host residual.',
    });
  } else if (agentBrowserInventory.valid) {
    const browser = agentBrowserInventory.value;
    const browserFresh = resourceFreshness(
      browser.sampledAt,
      sampledAt,
      staleAfterMs,
      intervalMs,
    );
    sampleTimes.push(browser.sampledAt);
    segments.push({
      key: 'agent-browsers',
      kind: 'agent-browsers',
      familyId: null,
      repoId: null,
      name: 'Agent browsers',
      project: null,
      active: browser.totals.sessionCount > 0 || browser.totals.processCount > 0,
      additive: !splitCgroupAccounting,
      exact: browserFresh === true,
      fresh: browserFresh,
      sampledAt: browser.sampledAt,
      coverage: {
        measuredResources: browser.totals.processCount,
        completeResources: browser.totals.processCount,
        expectedResources: browser.totals.processCount,
        missingResources: 0,
        staleResources: browserFresh === false ? browser.totals.processCount : 0,
        missingTimestampResources: 0,
        fresh: browserFresh,
        exact: browserFresh === true,
      },
      current: {
        memoryBytes: browser.totals.memoryBytes,
        stackMemoryBytes: splitCgroupAccounting ? 0 : null,
        cpuPercent: wholeHostCpu(browser.totals.cpuPercent, cores),
        stackCpuPercent: splitCgroupAccounting ? 0 : null,
        cpuRawPercent: browser.totals.cpuPercent,
      },
      contributors: [],
      agentBrowsers: browser,
    });
  }

  const cgroupSegments = cgroupAccountingSegments(memoryDiagnostics, cores, sampledAt);
  for (const segment of cgroupSegments) {
    if (segment.sampledAt !== null) sampleTimes.push(segment.sampledAt);
    segments.push(segment);
  }
  if (splitCgroupAccounting) {
    const projectRuntime = memoryDiagnostics.cgroups.find(
      (group) => group.role === 'project-runtimes',
    );
    const repositorySegments = segments.filter((segment) => (
      segment.kind === 'project-family' || segment.kind === 'project'
    ));
    const repositoryMemoryBytes = repositorySegments.reduce(
      (sum, segment) => sum + (nonnegative(segment.current.memoryBytes) ?? 0),
      0,
    );
    const projectRuntimeBytes = projectRuntime?.available === true
      ? nonnegative(projectRuntime.workingBytes) : null;
    memoryDiagnostics.projectRuntimeCrosscheck = {
      additive: false,
      repositoryRowsAdditive: false,
      repositoryCount: repositorySegments.length,
      repositoryMemoryBytes,
      projectRuntimeBytes,
      differenceBytes: projectRuntimeBytes === null
        ? null : projectRuntimeBytes - repositoryMemoryBytes,
    };
    if (!projectRuntime || projectRuntime.available !== true || projectRuntimeBytes === null) {
      issues.push({
        code: 'project-runtime-cgroup-unavailable',
        message: 'The project-runtime slice is unavailable. Repository rows remain non-additive and the missing host attribution stays visible in System / unclassified.',
      });
    } else {
      const difference = projectRuntimeBytes - repositoryMemoryBytes;
      const tolerance = Math.max(256 * 1024 ** 2,
        Math.max(projectRuntimeBytes, repositoryMemoryBytes) * 0.1);
      if (Math.abs(difference) > tolerance) {
        issues.push({
          code: 'project-runtime-attribution-gap',
          message: `Project runtime cgroup and repository drilldowns differ by ${Math.round(difference)} bytes; the cgroup remains authoritative for the host stack.`,
        });
      }
    }
  }

  const attributedSegments = segments.filter((segment) => segment.additive === true);
  const memoryStack = proportionalStack(
    attributedSegments,
    'memoryBytes',
    'stackMemoryBytes',
    usedBytes,
    { integer: true },
  );
  const cpuStack = proportionalStack(
    attributedSegments,
    'cpuPercent',
    'stackCpuPercent',
    hostCpuUsed,
  );
  const residualBytes = usedBytes === null || memoryStack.stacked === null
    ? null
    : Math.max(0, usedBytes - memoryStack.stacked);
  const residualCpu = hostCpuUsed === null || cpuStack.stacked === null
    ? null
    : Math.max(0, hostCpuUsed - cpuStack.stacked);
  const hostFresh = resourceFreshness(hostSampleAt, sampledAt, staleAfterMs, intervalMs);
  segments.push({
    key: 'system-unclassified',
    kind: 'system-unclassified',
    familyId: null,
    repoId: null,
    name: 'System / unclassified',
    project: null,
    active: true,
    additive: true,
    exact: false,
    fresh: hostFresh,
    sampledAt: hostSampleAt,
    coverage: null,
    current: {
      memoryBytes: residualBytes,
      stackMemoryBytes: residualBytes,
      cpuPercent: residualCpu,
      stackCpuPercent: residualCpu,
      cpuRawPercent: null,
    },
    contributors: [],
  });
  segments.push({
    key: 'available',
    kind: 'available',
    familyId: null,
    repoId: null,
    name: 'Available',
    project: null,
    active: true,
    additive: true,
    exact: availableBytes !== null && hostCpuAvailable !== null && hostFresh === true,
    fresh: hostFresh,
    sampledAt: hostSampleAt,
    coverage: null,
    current: {
      memoryBytes: availableBytes,
      stackMemoryBytes: availableBytes,
      cpuPercent: hostCpuAvailable,
      stackCpuPercent: hostCpuAvailable,
      cpuRawPercent: null,
    },
    contributors: [],
  });

  const finiteTimes = sampleTimes.filter((value) => Number.isFinite(value));
  const windowStartAt = finiteTimes.length ? Math.min(...finiteTimes) : sampledAt;
  const windowEndAt = finiteTimes.length ? Math.max(...finiteTimes) : sampledAt;
  const sampleSkewMs = Math.max(0, windowEndAt - windowStartAt);
  const measurementSegments = attributedSegments.filter((segment) => segment.kind !== 'control-other'
    || segment.contributors.length > 0);
  const expectationsKnown = measurementSegments.every(
    (segment) => segment.coverage?.expectedResources !== null,
  );
  const expectedResources = expectationsKnown
    ? measurementSegments.reduce((sum, segment) => sum + segment.coverage.expectedResources, 0)
    : null;
  const measuredResources = measurementSegments.reduce(
    (sum, segment) => sum + (segment.coverage?.measuredResources ?? 0),
    0,
  );
  const missingResources = expectationsKnown
    ? measurementSegments.reduce((sum, segment) => sum + (segment.coverage?.missingResources ?? 0), 0)
    : null;
  const staleResources = measurementSegments.reduce(
    (sum, segment) => sum + (segment.coverage?.staleResources ?? 0),
    0,
  );
  const ratio = (part, whole) => {
    if (part === null || whole === null) return null;
    if (whole === 0) return part === 0 ? 1 : 0;
    return Math.min(1, Math.max(0, part / whole));
  };
  const memoryCoverageRatio = ratio(memoryStack.observed, usedBytes);
  const cpuCoverageRatio = ratio(cpuStack.observed, hostCpuUsed);
  const sourcesExact = expectationsKnown
    && measurementSegments.every((segment) => segment.exact)
    && hostFresh === true
    && sampleSkewMs <= intervalMs;
  const memoryExact = sourcesExact
    && totalBytes !== null
    && availableBytes !== null
    && memoryBasis === 'MemTotal-MemAvailable'
    && memoryStack.overage === 0;
  const cpuExact = sourcesExact
    && cores !== null
    && hostCpuUsed !== null
    && cpuStack.overage === 0;
  if (sampleSkewMs > intervalMs) {
    issues.push({
      code: 'sample-skew',
      message: `Host and attributed workload samples span ${sampleSkewMs} ms.`,
    });
  }
  if (!expectationsKnown || missingResources > 0) {
    issues.push({
      code: 'attribution-coverage-incomplete',
      message: splitCgroupAccounting
        ? 'One or more disjoint host accounting roots lack a complete process count.'
        : 'One or more repository-family samples are missing or lack a complete resource count.',
    });
  }
  if (staleResources > 0) {
    issues.push({ code: 'stale-workload-samples', message: `${staleResources} workload sample(s) are stale.` });
  }
  if ((memoryStack.overage ?? 0) > 0 || (cpuStack.overage ?? 0) > 0) {
    issues.push({
      code: 'attribution-overage',
      message: 'Attributed observations exceed the matching host total; stack values are proportionally bounded and observed values are retained.',
    });
  }

  const performance = {
    schemaVersion: PERFORMANCE_SCHEMA_VERSION,
    sampledAt,
    window: {
      startAt: windowStartAt,
      endAt: windowEndAt,
      durationMs: sampleSkewMs,
      intervalMs,
      staleAfterMs,
    },
    semantics: {
      memoryBasis: memoryBasis === 'MemTotal-MemAvailable'
        ? 'Host used memory is Linux MemTotal minus MemAvailable; available includes reclaimable cache.'
        : 'Linux MemTotal/MemAvailable was unavailable; host memory uses an explicitly labeled operating-system fallback and is not exact.',
      projectAccounting: splitCgroupAccounting
        ? 'The host stack counts the disjoint project-runtimes cgroup once. Repository families are non-additive drilldowns and cross-checks over that category.'
        : 'Legacy fallback counts each authoritative repository family once because split cgroup accounting is unavailable.',
      controlOther: splitCgroupAccounting
        ? 'Lifecycle-problem resource rows are non-additive diagnostics because their host cgroup may already be represented.'
        : 'Control / other includes only current resource identities explicitly proved outside repository families by the Coordinator; no process is assigned by name or path.',
      agentBrowsers: splitCgroupAccounting
        ? 'Agent-browser rows are a non-additive drilldown within Developer-account sessions; they never add those processes twice.'
        : 'Agent browsers is an explicit measured non-project worker category. The producer excludes sessions already contained by a repository runtime.',
      cgroupAccounting: splitCgroupAccounting
        ? 'Project runtimes, Coordinator control, Coordinator background, active tests, and developer sessions are disjoint cgroup-v2 roots and are added once. Their children are drilldowns only.'
        : 'Split cgroup-v2 accounting is unavailable; repository telemetry supplies a compatibility composition.',
      residual: 'System / unclassified is max(0, MemTotal-MemAvailable-disjoint measured roots). It can include kernel/slab/cache and shared memory accounting differences, host services, work outside the measured roots, missing telemetry, and sample skew.',
      diagnostics: 'Each diagnostic declares whether it is additive. Child cgroups, repository rows, agent-browser rows and host meminfo overlap a parent or host total and contribute zero additional bytes.',
      cpuNormalization: 'Workload CPU is divided by the host logical-core count before it is compared with or stacked against whole-host CPU capacity.',
    },
    sampleSkewMs,
    exact: memoryExact && cpuExact,
    issues,
    attributed: {
      memoryBytes: memoryStack.observed,
      stackMemoryBytes: memoryStack.stacked,
      cpuPercent: cpuStack.observed,
      stackCpuPercent: cpuStack.stacked,
    },
    residual: {
      memoryBytes: residualBytes,
      cpuPercent: residualCpu,
      exact: false,
      calculation: 'max(0, host-used-attributed)',
      includes: [
        'kernel-slab-cache',
        'host-services',
        'work-outside-measured-roots',
        'unobserved-or-stale-workloads',
      ],
      nestedCgroupsAdded: false,
      diagnostics: memoryDiagnostics,
    },
    coverage: {
      memoryRatio: memoryCoverageRatio,
      cpuRatio: cpuCoverageRatio,
      measuredResources,
      expectedResources,
      missingResources,
      staleResources,
      exact: sourcesExact,
    },
    memory: {
      basis: memoryBasis,
      totalBytes,
      usedBytes,
      availableBytes,
      attributedBytes: memoryStack.observed,
      stackAttributedBytes: memoryStack.stacked,
      residualBytes,
      overageBytes: memoryStack.overage,
      coverageRatio: memoryCoverageRatio,
      stackScale: memoryStack.scale,
      exact: memoryExact,
    },
    cpu: {
      basis: 'whole-host',
      normalization: 'raw-resource-percent/logical-cores',
      cores,
      capacityPercent: 100,
      usedPercent: hostCpuUsed,
      availablePercent: hostCpuAvailable,
      attributedPercent: cpuStack.observed,
      stackAttributedPercent: cpuStack.stacked,
      residualPercent: residualCpu,
      overagePercent: cpuStack.overage,
      coverageRatio: cpuCoverageRatio,
      stackScale: cpuStack.scale,
      exact: cpuExact,
    },
    segments,
  };
  return performance;
}

function isContainerRunning(container) {
  return isDockerContainerRunningStatus(container?.status);
}

export function createMetricsStore({ config, log, coordinator, host, maxPoints = METRICS_MAX_POINTS, now = () => Date.now() } = {}) {
  const mlog = typeof log?.child === 'function' ? log.child({ mod: 'metrics' }) : log;
  const intervalMs = Math.max(MIN_INTERVAL_MS, Number(config?.metricsIntervalMs) || 10_000);
  const retentionMs = maxPoints * intervalMs;
  const hostProbe = host ?? createHostProbe();

  // key -> { key, kind, id, name, project, points: [{t, cpu, mem}], lastSeen }
  const entities = new Map();

  // Latest full machine reading (cpu/mem/load/disks/uptime); the cpu/mem
  // pair also lands in the 'host' history ring above.
  let hostNow = null;
  let performanceNow = null;
  const performanceSamples = [];
  const performanceMetadata = new Map();

  let timer = null;
  let sampling = false;
  let observationFlight = null;
  let lastSampleAt = null;
  let lastInventoryError = null;
  let observationFailures = 0;
  let nextObservationAt = null;
  let lastObservationError = null;
  let lastHostError = null;

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
  function ingest(inventoryData, { at = now(), dedupe = true } = {}) {
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

    // The authoritative repository tree has two additional, immutable views
    // of project usage: the root repository and its whole family (root plus
    // temporary worktrees).  The Projects and Performance views address those
    // series by repository/family ID, not by the legacy path-based usage key.
    // Publish them explicitly instead of attempting a lossy key translation
    // in the UI; otherwise live values render while their history can never
    // be found.
    for (const tree of Array.isArray(inventoryData.repository_trees) ? inventoryData.repository_trees : []) {
      const root = tree?.root_repository || {};
      const familyId = tree?.family_id ?? root?.repo_id;
      const familyUsage = tree?.usage || {};
      const familyCpu = num(familyUsage.cpu_percent);
      const familyMem = num(familyUsage.memory_bytes);
      if (familyId != null && (familyCpu !== null || familyMem !== null)) {
        record(
          `family:${familyId}`,
          {
            kind: 'project-family',
            id: String(familyId),
            name: root.display_name ?? null,
            project: root.canonical_root ?? null,
          },
          t,
          familyCpu ?? 0,
          familyMem ?? 0,
          dedupe,
        );
      }

      for (const scope of Array.isArray(tree?.scopes) ? tree.scopes : []) {
        if (scope?.kind !== 'root' || scope?.repo_id == null) continue;
        const usage = scope?.usage || {};
        const cpu = num(usage.cpu_percent);
        const mem = num(usage.memory_bytes);
        if (cpu === null && mem === null) continue;
        record(
          `repo:${scope.repo_id}`,
          {
            kind: 'repository',
            id: String(scope.repo_id),
            name: scope.display_name ?? root.display_name ?? null,
            project: scope.canonical_root ?? root.canonical_root ?? null,
          },
          t,
          cpu ?? 0,
          mem ?? 0,
          dedupe,
        );
      }
    }

    prune(t);
  }

  function recordPerformance(snapshot) {
    performanceNow = snapshot;
    performanceSamples.push(compactPerformanceSample(snapshot));
    if (performanceSamples.length > maxPoints) {
      performanceSamples.splice(0, performanceSamples.length - maxPoints);
    }
    for (const segment of snapshot.segments) performanceMetadata.set(segment.key, segment);

    const retainedKeys = new Set(performanceSamples.flatMap((sample) => (
      sample.memory.segments.map((segment) => segment.key)
    )));
    for (const key of performanceMetadata.keys()) {
      if (!retainedKeys.has(key)) performanceMetadata.delete(key);
    }
  }

  function performanceHistory(limit) {
    if (!performanceNow) return null;
    const samples = performanceSamples.slice(-limit);
    const activeByKey = new Map(performanceNow.segments.map((segment) => [segment.key, segment]));
    const peakByKey = new Map();
    for (const sample of samples) {
      for (const segment of sample.memory.segments) {
        const value = nonnegative(segment.observedValue);
        if (value === null) continue;
        const peak = peakByKey.get(segment.key) || { memoryBytes: null, cpuPercent: null };
        peak.memoryBytes = peak.memoryBytes === null ? value : Math.max(peak.memoryBytes, value);
        peakByKey.set(segment.key, peak);
      }
      for (const segment of sample.cpu.segments) {
        const value = nonnegative(segment.observedValue);
        if (value === null) continue;
        const peak = peakByKey.get(segment.key) || { memoryBytes: null, cpuPercent: null };
        peak.cpuPercent = peak.cpuPercent === null ? value : Math.max(peak.cpuPercent, value);
        peakByKey.set(segment.key, peak);
      }
    }
    const currentOrder = performanceNow.segments.map((segment) => segment.key);
    const historicalOrder = [...performanceMetadata.keys()]
      .filter((key) => !activeByKey.has(key))
      .sort((a, b) => String(a).localeCompare(String(b)));
    const segments = [...currentOrder, ...historicalOrder].map((key) => {
      const current = activeByKey.get(key);
      const retained = current ?? performanceMetadata.get(key);
      return {
        ...retained,
        active: Boolean(current),
        peak: peakByKey.get(key) || { memoryBytes: null, cpuPercent: null },
      };
    });
    return { ...performanceNow, segments, samples };
  }

  /** Record one whole-machine reading (never throws, never blocks charts). */
  async function sampleHost() {
    try {
      const reading = await hostProbe.sample();
      hostNow = reading;
      lastHostError = null;
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
      return reading;
    } catch (err) {
      lastHostError = err;
      mlog?.warn?.('host sample failed', { error: err?.message ?? String(err) });
      return null;
    }
  }

  function observationErrorMessage(error) {
    return `host observation failed; using last committed inventory: ${error?.message ?? String(error)}`;
  }

  function currentSamplerError() {
    const failures = [];
    if (lastHostError) failures.push(`host sample failed: ${lastHostError?.message ?? String(lastHostError)}`);
    if (lastObservationError && lastInventoryError) {
      failures.push(`host observation failed: ${lastObservationError?.message ?? String(lastObservationError)}`);
    } else if (lastObservationError) {
      failures.push(observationErrorMessage(lastObservationError));
    }
    if (lastInventoryError) failures.push(`inventory read failed: ${lastInventoryError?.message ?? String(lastInventoryError)}`);
    return failures.length ? failures.join('; ') : null;
  }

  /**
   * Start the expensive host observation when due, without holding the
   * lightweight host/inventory sampler lock. One flight is allowed at a time;
   * its failure backoff begins when the failure is actually observed.
   */
  function startObservation(tickAt) {
    if (observationFlight) return observationFlight;
    if (nextObservationAt !== null && tickAt < nextObservationAt) return null;

    let pending;
    try {
      // Invoke synchronously so an observation is initiated before this tick's
      // pure inventory read, while deliberately not awaiting its completion.
      pending = coordinator.observeHost({
        agent: 'devops-console:metrics',
        project: config.projectRoot,
      });
    } catch (err) {
      pending = Promise.reject(err);
    }

    const flight = Promise.resolve(pending)
      .then(() => {
        observationFailures = 0;
        nextObservationAt = null;
        lastObservationError = null;
      })
      .catch((err) => {
        // A failed observation is unknown host state, not proof that retained
        // containers disappeared. Keep sampling the last committed inventory
        // and back off this expensive operation from failure completion.
        observationFailures += 1;
        const backoffMs = Math.min(
          300_000,
          intervalMs * (2 ** Math.min(10, observationFailures - 1)),
        );
        nextObservationAt = now() + backoffMs;
        lastObservationError = err;
      })
      .finally(() => {
        if (observationFlight === flight) observationFlight = null;
      });
    observationFlight = flight;
    return flight;
  }

  /** One sampler tick: machine health, non-blocking observation, then inventory. */
  async function sampleOnce() {
    if (sampling) return;
    sampling = true;
    const tickAt = now();
    try {
      // Initiate or join the observation before yielding to host sampling. If
      // an older flight completes during that await, this tick must not start
      // a second flight at the completion boundary.
      if (!config?.retainedInventory) startObservation(tickAt);
      // The machine reading must never depend on coordinator health.
      const hostReading = await sampleHost();
      const inventoryData = await coordinator.inventory({
        maxAgeMs: Math.max(1000, Math.floor(intervalMs / 2)),
      });
      const completedAt = now();
      ingest(inventoryData, { at: completedAt });
      recordPerformance(buildPerformanceSnapshot({
        host: hostReading,
        inventory: inventoryData,
        at: completedAt,
        intervalMs,
      }));
      lastSampleAt = completedAt;
      lastInventoryError = null;
    } catch (err) {
      // Coordinator down: keep the buffers, note the failure, retry next tick.
      lastInventoryError = err;
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
      now: now(),
      intervalMs,
      maxPoints,
      sampler: {
        running: timer !== null,
        lastSampleAt,
        lastError: currentSamplerError(),
        observationFailures,
        nextObservationAt,
        observationInFlight: observationFlight !== null,
      },
      // Latest whole-machine snapshot (cpu %, mem, load, disks, uptime);
      // its cpu/mem history rides in entities as kind:'host', key 'host'.
      host: hostNow,
      performance: performanceHistory(capped),
      entities: out,
    };
  }

  return { ingest, sampleOnce, start, stop, history, intervalMs };
}
