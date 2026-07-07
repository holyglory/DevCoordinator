// Whole-machine health probe: CPU, memory, storage, load and uptime for the
// box the console runs on. Pure stdlib — os counters, /proc/meminfo where it
// exists (Linux; falls back to os.freemem elsewhere) and fs.statfs for
// disks. All raw readers are injectable so the math is unit-testable.

import { promises as fsp } from 'node:fs';
import os from 'node:os';

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
  const available = /^MemAvailable:\s+(\d+)\s*kB/m.exec(String(text ?? ''));
  const availableBytes = available ? Number(available[1]) * 1024 : freeBytes;
  return {
    totalBytes,
    availableBytes,
    usedBytes: Math.max(0, totalBytes - availableBytes),
  };
}

export function createHostProbe({
  cpusFn = () => os.cpus(),
  loadavgFn = () => os.loadavg(),
  uptimeFn = () => os.uptime(),
  totalmemFn = () => os.totalmem(),
  freememFn = () => os.freemem(),
  readMeminfo = () => fsp.readFile('/proc/meminfo', 'utf8'),
  statfsFn = (mount) => fsp.statfs(mount),
  statFn = (mount) => fsp.stat(mount),
  mounts = ['/', os.homedir()],
} = {}) {
  let prevCpu = null;

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

    const load = loadavgFn();
    return {
      at: Date.now(),
      cpuPercent,
      cores: Array.isArray(cpus) ? cpus.length : null,
      load: Array.isArray(load) ? load.map((n) => Number(n) || 0) : [0, 0, 0],
      uptimeSec: Number(uptimeFn()) || 0,
      mem,
      disks: await sampleDisks(),
    };
  }

  return { sample };
}
