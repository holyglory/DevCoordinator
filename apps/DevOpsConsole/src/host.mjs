// Whole-machine health probe: CPU, memory, storage, load and uptime for the
// box the console runs on. Pure stdlib — os counters, /proc/meminfo where it
// exists (Linux; falls back to os.freemem elsewhere) and fs.statfs for
// disks. All raw readers are injectable so the math is unit-testable.

import { promises as fsp } from 'node:fs';
import os from 'node:os';

// These rows are deliberately disjoint where `additive` is true.  Never put
// the inclusive devcoordinator.slice parent back into this list: it contains
// projects, control, background and tests and would count the same bytes a
// second time.  Project/repository telemetry remains a non-additive drilldown
// over the project-runtimes row in metrics.mjs.
const DEFAULT_CGROUP_SLICES = [
  {
    key: 'project-runtimes',
    role: 'project-runtimes',
    path: 'devcoordinator.slice/devcoordinator-projects.slice',
    label: 'Project runtimes',
    additive: true,
    maxDepth: 1,
  },
  {
    key: 'coordinator-control',
    role: 'coordinator-control',
    path: 'devcoordinator.slice/devcoordinator-control.slice',
    label: 'Coordinator control plane',
    additive: true,
    maxDepth: 1,
  },
  {
    key: 'coordinator-background',
    role: 'coordinator-background',
    path: 'devcoordinator.slice/devcoordinator-background.slice',
    label: 'Coordinator background / scheduler',
    additive: true,
    maxDepth: 1,
  },
  {
    key: 'active-test-executions',
    role: 'active-test-executions',
    path: 'devcoordinator.slice/devcoordinator-tests.slice',
    label: 'Active test executions',
    additive: true,
    maxDepth: 2,
  },
  {
    key: 'developer-sessions',
    role: 'developer-sessions',
    path: 'user.slice',
    label: 'Developer-account sessions',
    additive: true,
    maxDepth: 2,
  },
  {
    key: 'system-services',
    role: 'system-services',
    path: 'system.slice',
    label: 'System services',
    additive: false,
    overlap: 'system-and-container-runtime',
    maxDepth: 1,
  },
];

const MAX_CGROUP_NODES = 96;

// Overall CPU% between two aggregated os.cpus() snapshots.
export function cpuPercentBetween(prev, next) {
  if (!prev || !next) return null;
  const total = next.total - prev.total;
  const idle = next.idle - prev.idle;
  if (!(total > 0) || idle < 0) return null;
  return Math.min(100, Math.max(0, (1 - idle / total) * 100));
}

export function aggregateCpuTimes(cpus) {
  let idle = 0;
  let total = 0;
  for (const cpu of Array.isArray(cpus) ? cpus : []) {
    for (const [kind, value] of Object.entries(cpu?.times ?? {})) {
      const v = Number(value) || 0;
      total += v;
      if (kind === 'idle') idle += v;
    }
  }
  return total > 0 ? { idle, total } : null;
}

// "Used" memory the way ops people mean it: total minus what applications
// could still allocate (MemAvailable counts reclaimable cache; plain "free"
// on Linux is nearly always tiny and would read as a constant alarm).
export function memoryFromMeminfo(text, totalBytes, freeBytes) {
  const total = /^MemTotal:\s+(\d+)\s*kB/m.exec(String(text ?? ''));
  const available = /^MemAvailable:\s+(\d+)\s*kB/m.exec(String(text ?? ''));
  const effectiveTotalBytes = total ? Number(total[1]) * 1024 : totalBytes;
  const availableBytes = available ? Number(available[1]) * 1024 : freeBytes;
  return {
    basis: total && available ? 'MemTotal-MemAvailable' : 'totalmem-freemem-fallback',
    totalBytes: effectiveTotalBytes,
    availableBytes,
    usedBytes: Math.max(0, effectiveTotalBytes - availableBytes),
  };
}

function meminfoByteMap(text) {
  const values = new Map();
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const match = /^([A-Za-z_()]+):\s+(\d+)\s+kB\s*$/.exec(line);
    if (match) values.set(match[1], Number(match[2]) * 1024);
  }
  return values;
}

export function memoryDiagnosticsFromMeminfo(text) {
  const values = meminfoByteMap(text);
  const field = (name) => values.has(name) ? values.get(name) : null;
  const diagnostics = {
    available: values.size > 0,
    shmemBytes: field('Shmem'),
    anonPagesBytes: field('AnonPages'),
    sUnreclaimBytes: field('SUnreclaim'),
    slabBytes: field('Slab'),
    pageTablesBytes: field('PageTables'),
    kernelStackBytes: field('KernelStack'),
  };
  return diagnostics;
}

export function cgroupMemoryFromFiles(currentText, statText) {
  const currentValue = String(currentText ?? '').trim();
  if (!currentValue) return null;
  const currentBytes = Number(currentValue);
  if (!Number.isFinite(currentBytes) || currentBytes < 0) return null;
  const stats = new Map();
  for (const line of String(statText ?? '').split(/\r?\n/)) {
    const match = /^([a-z_]+)\s+(\d+)\s*$/.exec(line);
    if (match) stats.set(match[1], Number(match[2]));
  }
  const stat = (name) => {
    const value = stats.get(name);
    return Number.isFinite(value) && value >= 0 ? value : null;
  };
  const inactiveFileBytes = stat('inactive_file');
  return {
    currentBytes,
    inactiveFileBytes,
    workingBytes: inactiveFileBytes === null
      ? null
      : Math.max(0, currentBytes - inactiveFileBytes),
    anonBytes: stat('anon'),
    shmemBytes: stat('shmem'),
    fileBytes: stat('file'),
    kernelBytes: stat('kernel'),
    slabBytes: stat('slab'),
    pageTablesBytes: stat('pagetables'),
    kernelStackBytes: stat('kernel_stack'),
    socketBytes: stat('sock'),
  };
}

export function cgroupCpuUsageFromFile(text) {
  const usage = /^usage_usec\s+(\d+)\s*$/m.exec(String(text ?? ''));
  if (!usage) return null;
  const usageUsec = Number(usage[1]);
  return Number.isFinite(usageUsec) && usageUsec >= 0 ? usageUsec : null;
}

export function cgroupCpuPercentBetween(previous, next) {
  if (!previous || !next) return null;
  const elapsedUsec = (Number(next.at) - Number(previous.at)) * 1000;
  const usedUsec = Number(next.usageUsec) - Number(previous.usageUsec);
  if (!(elapsedUsec > 0) || usedUsec < 0) return null;
  return Math.max(0, usedUsec / elapsedUsec * 100);
}

export function cgroupEventsFromFile(text) {
  const populated = /^populated\s+([01])\s*$/m.exec(String(text ?? ''));
  const frozen = /^frozen\s+([01])\s*$/m.exec(String(text ?? ''));
  return {
    populated: populated ? populated[1] === '1' : null,
    frozen: frozen ? frozen[1] === '1' : null,
  };
}

export function passwdAccountsFromFile(text) {
  const accounts = new Map();
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const fields = line.split(':');
    const uid = Number(fields[2]);
    if (fields.length >= 3 && fields[0] && Number.isInteger(uid) && uid >= 0) {
      accounts.set(uid, fields[0]);
    }
  }
  return accounts;
}

function validCgroupPath(value) {
  const parts = String(value ?? '').split('/').filter(Boolean);
  if (!parts.length || parts.some((part) => part === '.' || part === '..' || part.includes('\0'))) {
    return null;
  }
  return parts.join('/');
}

function cgroupProcessCount(text) {
  return String(text ?? '').split(/\r?\n/).filter((line) => /^\d+$/.test(line.trim())).length;
}

function childLabel(name, role, accounts) {
  const account = /^user-(\d+)\.slice$/.exec(name);
  if (role === 'developer-sessions' && account) {
    const uid = Number(account[1]);
    return {
      label: accounts.get(uid) || `UID ${uid}`,
      accountUid: uid,
      accountName: accounts.get(uid) || null,
    };
  }
  const cleaned = String(name)
    .replace(/\.(service|scope|slice)$/, '')
    .replace(/^devcoordinator-/, '')
    .replaceAll('-', ' ');
  return { label: cleaned || name, accountUid: null, accountName: null };
}

export function createHostProbe({
  cpusFn = () => os.cpus(),
  loadavgFn = () => os.loadavg(),
  uptimeFn = () => os.uptime(),
  totalmemFn = () => os.totalmem(),
  freememFn = () => os.freemem(),
  readMeminfo = () => fsp.readFile('/proc/meminfo', 'utf8'),
  readCgroupFile = (file) => fsp.readFile(file, 'utf8'),
  readCgroupEntries = (directory) => fsp.readdir(directory, { withFileTypes: true }),
  readPasswd = () => fsp.readFile('/etc/passwd', 'utf8'),
  cgroupRoot = '/sys/fs/cgroup',
  cgroupSlices = DEFAULT_CGROUP_SLICES,
  statfsFn = (mount) => fsp.statfs(mount),
  statFn = (mount) => fsp.stat(mount),
  mounts = ['/', os.homedir()],
  nowFn = () => Date.now(),
} = {}) {
  let prevCpu = null;
  const previousCgroupCpu = new Map();
  let passwdAccounts = null;

  async function accountNames() {
    if (passwdAccounts) return passwdAccounts;
    try {
      passwdAccounts = passwdAccountsFromFile(await readPasswd());
    } catch {
      passwdAccounts = new Map();
    }
    return passwdAccounts;
  }

  async function optionalCgroupRead(file) {
    try {
      return await readCgroupFile(file);
    } catch {
      return null;
    }
  }

  async function cgroupDirectories(directory) {
    try {
      const entries = await readCgroupEntries(directory);
      return (Array.isArray(entries) ? entries : [])
        .filter((entry) => typeof entry === 'string' || entry?.isDirectory?.())
        .map((entry) => typeof entry === 'string' ? entry : entry.name)
        .filter((name) => name && !name.includes('/') && name !== '.' && name !== '..')
        .sort();
    } catch {
      return null;
    }
  }

  async function sampleCgroupNode({
    relativePath, key, role, label, additive, overlap, maxDepth,
    sampledAt, accounts, depth = 0, budget,
  }) {
    if (budget.remaining <= 0) return null;
    budget.remaining -= 1;
    const base = `${String(cgroupRoot).replace(/\/$/, '')}/${relativePath}`;
    const [current, stats, cpuStat, processes, events] = await Promise.all([
      optionalCgroupRead(`${base}/memory.current`),
      optionalCgroupRead(`${base}/memory.stat`),
      optionalCgroupRead(`${base}/cpu.stat`),
      optionalCgroupRead(`${base}/cgroup.procs`),
      optionalCgroupRead(`${base}/cgroup.events`),
    ]);
    const parsed = cgroupMemoryFromFiles(current, stats);
    const cpuUsageUsec = cgroupCpuUsageFromFile(cpuStat);
    const previous = previousCgroupCpu.get(relativePath) || null;
    const cpuRawPercent = cpuUsageUsec === null ? null : cgroupCpuPercentBetween(previous, {
      at: sampledAt,
      usageUsec: cpuUsageUsec,
    });
    if (cpuUsageUsec !== null) {
      previousCgroupCpu.set(relativePath, { at: sampledAt, usageUsec: cpuUsageUsec });
    }
    const eventState = cgroupEventsFromFile(events);
    const processCount = processes === null ? null : cgroupProcessCount(processes);
    const children = [];
    let childrenAvailable = true;
    let childrenTruncated = false;
    if (depth < maxDepth) {
      const names = await cgroupDirectories(base);
      if (names === null) {
        childrenAvailable = false;
      } else {
        for (const name of names) {
          if (budget.remaining <= 0) {
            childrenTruncated = true;
            break;
          }
          const identity = childLabel(name, role, accounts);
          const child = await sampleCgroupNode({
            relativePath: `${relativePath}/${name}`,
            key: name,
            role,
            label: identity.label,
            additive: false,
            overlap: key,
            maxDepth,
            sampledAt,
            accounts,
            depth: depth + 1,
            budget,
          });
          if (child) children.push({
            ...child,
            accountUid: identity.accountUid,
            accountName: identity.accountName,
          });
        }
        children.sort((left, right) => (
          (right.workingBytes ?? right.currentBytes ?? -1)
            - (left.workingBytes ?? left.currentBytes ?? -1)
          || String(left.label).localeCompare(String(right.label))
        ));
      }
    }
    const activeChildCount = children.reduce((sum, child) => (
      sum + (child.populated === true && child.children.length === 0 ? 1 : 0)
        + child.activeChildCount
    ), 0);
    return {
      key,
      role,
      label,
      available: parsed !== null,
      additive: additive === true,
      overlap: overlap || null,
      sampledAt,
      cpuUsageUsec,
      cpuRawPercent,
      processCount,
      populated: eventState.populated ?? (processCount === null ? null : processCount > 0),
      frozen: eventState.frozen,
      activeChildCount,
      childrenAvailable,
      childrenTruncated,
      children,
      ...(parsed || {}),
    };
  }

  async function sampleCgroups(sampledAt) {
    const rows = [];
    const accounts = await accountNames();
    for (const definition of Array.isArray(cgroupSlices) ? cgroupSlices : []) {
      const key = typeof definition === 'string' ? definition : definition?.key;
      const label = typeof definition === 'string' ? definition : definition?.label;
      const relativePath = validCgroupPath(
        typeof definition === 'string' ? definition : (definition?.path || definition?.key),
      );
      if (!key || !relativePath) continue;
      const row = await sampleCgroupNode({
        relativePath,
        key,
        role: typeof definition === 'string' ? key : (definition?.role || key),
        label: label || key,
        additive: typeof definition === 'string' ? false : definition?.additive,
        overlap: typeof definition === 'string' ? null : definition?.overlap,
        maxDepth: Math.max(0, Math.min(3, Number(definition?.maxDepth) || 0)),
        sampledAt,
        accounts,
        budget: { remaining: MAX_CGROUP_NODES },
      });
      if (row) rows.push(row);
    }
    return rows;
  }

  async function sampleDisks() {
    const seenDevices = new Set();
    const disks = [];
    for (const mount of mounts) {
      if (!mount) continue;
      try {
        // One entry per underlying device: '/' and a home on the same
        // filesystem must not show up as two identical disks.
        const st = await statFn(mount);
        if (st?.dev !== undefined) {
          if (seenDevices.has(st.dev)) continue;
          seenDevices.add(st.dev);
        }
        const fs = await statfsFn(mount);
        const bsize = Number(fs.bsize) || 0;
        const totalBytes = Number(fs.blocks) * bsize;
        if (!(totalBytes > 0)) continue;
        const availableBytes = Number(fs.bavail) * bsize;
        disks.push({
          mount,
          totalBytes,
          availableBytes,
          usedBytes: Math.max(0, totalBytes - Number(fs.bfree) * bsize),
        });
      } catch {
        // Mount unreadable (permissions, platform) — skip, never throw.
      }
    }
    return disks;
  }

  async function sample() {
    const sampledAt = nowFn();
    const cpus = cpusFn();
    const nextCpu = aggregateCpuTimes(cpus);
    const cpuPercent = cpuPercentBetween(prevCpu, nextCpu);
    prevCpu = nextCpu ?? prevCpu;

    const totalBytes = Number(totalmemFn()) || 0;
    const freeBytes = Number(freememFn()) || 0;
    let meminfo = null;
    try {
      meminfo = await readMeminfo();
    } catch {
      meminfo = null; // not Linux — fall back to plain free
    }
    const mem = memoryFromMeminfo(meminfo, totalBytes, freeBytes);
    const [disks, cgroups] = await Promise.all([sampleDisks(), sampleCgroups(sampledAt)]);
    mem.diagnostics = {
      schemaVersion: 2,
      additive: false,
      stackContributionBytes: 0,
      meminfo: memoryDiagnosticsFromMeminfo(meminfo),
      cgroups,
    };

    const load = loadavgFn();
    return {
      at: sampledAt,
      cpuPercent,
      cores: Array.isArray(cpus) ? cpus.length : null,
      load: Array.isArray(load) ? load.map((n) => Number(n) || 0) : [0, 0, 0],
      uptimeSec: Number(uptimeFn()) || 0,
      mem,
      disks,
    };
  }

  return { sample };
}
