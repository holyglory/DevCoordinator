import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  CANONICAL_OVERVIEW,
  CANONICAL_PREFS,
  CANONICAL_SESSION,
} from '../Tools/canonical-api-fixtures.mjs';
import { buildPerformanceSnapshot } from '../src/metrics.mjs';
import { canonicalTempDir, login, makeJar, startStack } from './helpers/stack.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(APP_ROOT, '..', '..');
const GIB = 1024 ** 3;
const BASE_AT = Date.parse('2026-08-02T10:15:00.000Z');
const RAW_IDENTITIES = /family-(?:aurora|borealis)-private|repo-(?:aurora|borealis)-private|\/private\/(?:aurora|borealis)/i;
const VIEWPORTS = Object.freeze([
  { width: 320, height: 900, activation: 'keyboard' },
  { width: 390, height: 900, activation: 'touch' },
  { width: 768, height: 1000, activation: 'keyboard', refresh: true },
  { width: 981, height: 1000, activation: 'mouse' },
  { width: 1440, height: 1000, activation: 'mouse' },
]);

function loadLockedPlaywright() {
  const require = createRequire(import.meta.url);
  const locked = require(path.join(REPO_ROOT, 'ci', 'playwright', 'package.json'));
  const roots = [
    ...String(process.env.NODE_PATH || '').split(path.delimiter).filter(Boolean),
    path.join(REPO_ROOT, 'ci', 'playwright', 'node_modules'),
  ];
  for (const root of roots) {
    try {
      const manifest = require(path.join(root, 'playwright', 'package.json'));
      if (manifest.version !== locked.dependencies.playwright) {
        throw new Error(`Playwright ${manifest.version} does not match locked ${locked.dependencies.playwright}`);
      }
      return require(path.join(root, 'playwright'));
    } catch (error) {
      if (String(error.message).includes('does not match locked')) throw error;
    }
  }
  throw new Error('locked Playwright runtime is unavailable');
}

async function launchChromium(chromium, args) {
  const configured = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
  const candidates = [
    null,
    configured,
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter((item, index, values) => item === null || (item && values.indexOf(item) === index));
  const failures = [];
  for (const executablePath of candidates) {
    if (executablePath && !fs.existsSync(executablePath)) continue;
    try {
      return await chromium.launch({
        headless: true,
        args,
        ...(executablePath ? { executablePath } : {}),
      });
    } catch (error) {
      failures.push(String(error.message).split('\n')[0]);
    }
  }
  throw new Error(`could not launch Chromium: ${failures.join('; ')}`);
}

async function writeEmptyDockerFixture(directory) {
  const executable = path.join(directory, 'docker');
  await fs.promises.writeFile(executable, `#!/usr/bin/env python3
import sys

args = sys.argv[1:]
if args[:1] in (["ps"], ["stats"]):
    pass
elif args[:2] in (["network", "ls"], ["volume", "ls"]):
    pass
else:
    sys.exit(1)
`, { encoding: 'utf8', mode: 0o755 });
}

function hostFixture(version) {
  const at = BASE_AT + (version - 1) * 10_000;
  const usedBytes = (version === 1 ? 8 : 10) * GIB;
  const cgroup = (role, label, workingBytes, cpuRawPercent, processCount, extra = {}) => ({
    key: role,
    role,
    label,
    available: true,
    additive: true,
    sampledAt: at,
    currentBytes: workingBytes,
    inactiveFileBytes: 0,
    workingBytes,
    anonBytes: Math.max(0, workingBytes - 128 * 1024 ** 2),
    shmemBytes: 0,
    kernelBytes: 32 * 1024 ** 2,
    cpuRawPercent,
    processCount,
    populated: processCount > 0,
    activeChildCount: 0,
    childrenAvailable: true,
    children: [],
    ...extra,
  });
  const projectBytes = (version === 1 ? 6.25 : 7.25) * GIB;
  const developerBytes = (version === 1 ? .75 : .875) * GIB;
  return {
    at,
    cpuPercent: version === 1 ? 40 : 46,
    cores: 8,
    load: [2.4, 2.1, 1.9],
    mem: {
      basis: 'MemTotal-MemAvailable',
      usedBytes,
      totalBytes: 16 * GIB,
      availableBytes: 16 * GIB - usedBytes,
      diagnostics: {
        schemaVersion: 2,
        additive: false,
        stackContributionBytes: 0,
        meminfo: {
          available: true,
          shmemBytes: 3 * GIB,
          anonPagesBytes: 5 * GIB,
          sUnreclaimBytes: 512 * 1024 ** 2,
          slabBytes: 768 * 1024 ** 2,
          pageTablesBytes: 128 * 1024 ** 2,
          kernelStackBytes: 64 * 1024 ** 2,
        },
        cgroups: [
          cgroup('project-runtimes', 'Project runtimes', projectBytes,
            version === 1 ? 205 : 221, 18),
          cgroup('coordinator-control', 'Coordinator control plane',
            (version === 1 ? .25 : .35) * GIB, 16, 4),
          cgroup('coordinator-background', 'Coordinator background / scheduler',
            (version === 1 ? .125 : .2) * GIB, 8, 3),
          cgroup('active-test-executions', 'Active test executions',
            (version === 1 ? .125 : .3) * GIB, version === 1 ? 16 : 24, 2, {
              activeChildCount: 1,
              children: [cgroup('attempt-1.scope', 'GlobalFinance test attempt',
                (version === 1 ? .125 : .3) * GIB, version === 1 ? 16 : 24, 2, {
                  additive: false,
                  overlap: 'active-test-executions',
                })],
            }),
          cgroup('developer-sessions', 'Developer-account sessions', developerBytes,
            version === 1 ? 24 : 32, 11, {
              shmemBytes: (version === 1 ? .5 : .625) * GIB,
              children: [
                cgroup('user-1000.slice', 'holygloryTT',
                  (version === 1 ? .6 : .7) * GIB, version === 1 ? 20 : 28, 8, {
                    additive: false,
                    overlap: 'developer-sessions',
                    accountUid: 1000,
                    accountName: 'holygloryTT',
                  }),
                cgroup('user-1001.slice', 'holyglory',
                  (version === 1 ? .15 : .175) * GIB, 4, 3, {
                    additive: false,
                    overlap: 'developer-sessions',
                    accountUid: 1001,
                    accountName: 'holyglory',
                  }),
              ],
            }),
          { ...cgroup('system-services', 'System services', 1.5 * GIB, 12, 30),
            additive: false, overlap: 'system-and-container-runtime' },
        ],
      },
    },
    disks: [{
      mount: '/',
      usedBytes: 400 * GIB,
      totalBytes: 1024 * GIB,
      availableBytes: 624 * GIB,
    }],
    uptimeSec: 900_000,
  };
}

function family(id, name, memoryBytes, cpuPercent, at) {
  return {
    family_id: id,
    root_repository: {
      repo_id: `repo-${name.toLowerCase()}-private`,
      display_name: name,
      canonical_root: `/private/${name.toLowerCase()}`,
    },
    usage: {
      memory_bytes: memoryBytes,
      cpu_percent: cpuPercent,
      process_count: 0,
      sampled_at: at,
    },
    scopes: [],
  };
}

function inventoryFixture(version) {
  const at = BASE_AT + (version - 1) * 10_000;
  const additionalFamilies = [
    'Cygnus', 'Draco', 'Equuleus', 'Fornax', 'Gemini',
    'Hydra', 'Indus', 'Lupus', 'Monoceros', 'prototype',
  ].map((name, index) => family(
    `family-${name.toLowerCase()}-private`,
    name,
    name === 'prototype' ? 0 : GIB / 8,
    name === 'prototype' ? 0 : 4 + index,
    at,
  ));
  return {
    servers: [],
    docker: { available: true, containers: [] },
    repository_trees: [
      family(
        'family-aurora-private',
        'Aurora',
        (version === 1 ? 3 : 4) * GIB,
        version === 1 ? 80 : 96,
        at,
      ),
      family('family-borealis-private', 'Borealis', 2 * GIB, 40, at),
      ...additionalFamilies,
    ],
    // Deliberate duplicate compatibility data: the UI/backend must never add
    // it on top of the authoritative family segments.
    project_usage: [{
      usage_key: 'path:/private/aurora',
      name: 'Aurora duplicate',
      memory_bytes: 3 * GIB,
      cpu_percent: 80,
      sampled_at: at,
    }],
    agent_browsers: {
      schema_version: 1,
      sampled_at: at,
      policy: { idle_timeout_seconds: 900, termination_grace_seconds: 30 },
      totals: {
        session_count: 3,
        process_count: 11,
        memory_bytes: 443 * 1024 ** 2,
        cpu_percent: version === 1 ? 24 : 32,
        idle_session_count: 1,
        protected_session_count: 1,
        reaped_total: 6,
        reclaimed_memory_bytes: 3 * GIB,
      },
      sessions: [{
        session_id: 'browser-codex-aurora',
        state: 'active',
        uid: 1000,
        cgroup_class: 'agent-browser',
        agent: 'Codex',
        repository_name: 'Aurora',
        first_seen_at: at - 3_600_000,
        last_observed_at: at,
        last_observed_work_at: at - 8_000,
        idle_seconds: 8,
        process_count: 5,
        memory_bytes: 220 * 1024 ** 2,
        cpu_percent: 18,
        reap_eligible: false,
      }, {
        session_id: 'browser-claude-borealis',
        state: 'idle',
        uid: 1001,
        cgroup_class: 'agent-browser',
        agent: 'Claude',
        repository_name: 'Borealis',
        first_seen_at: at - 7_200_000,
        last_observed_at: at,
        last_observed_work_at: at - 1_200_000,
        idle_seconds: 1200,
        process_count: 3,
        memory_bytes: 151 * 1024 ** 2,
        cpu_percent: 4,
        reap_eligible: true,
      }, {
        session_id: 'browser-protected-console',
        state: 'protected',
        uid: 1000,
        cgroup_class: 'agent-browser',
        agent: 'Codex',
        repository_name: 'DevCoordinator',
        first_seen_at: at - 10_800_000,
        last_observed_at: at,
        last_observed_work_at: at - 60_000,
        idle_seconds: 60,
        process_count: 3,
        memory_bytes: 72 * 1024 ** 2,
        cpu_percent: 2,
        reap_eligible: false,
      }],
      recent_reaps: [{
        session_id: 'browser-reaped',
        agent: 'Codex',
        repository_name: 'Archived preview',
        reaped_at: at - 1_800_000,
        reason: 'idle timeout',
        process_count: 4,
        reclaimed_memory_bytes: 768 * 1024 ** 2,
      }],
    },
    unassigned_resources: [],
    lifecycle_violations: [],
  };
}

function compactPerformanceSample(snapshot) {
  const compact = (segment, metric) => ({
    key: segment.key,
    value: metric === 'memory'
      ? segment.current.stackMemoryBytes : segment.current.stackCpuPercent,
    observedValue: metric === 'memory'
      ? segment.current.memoryBytes : segment.current.cpuPercent,
    exact: segment.exact,
  });
  return {
    at: snapshot.sampledAt,
    sampleSkewMs: snapshot.sampleSkewMs,
    exact: snapshot.exact,
    memory: {
      ...snapshot.memory,
      segments: snapshot.segments.map((segment) => compact(segment, 'memory')),
    },
    cpu: {
      ...snapshot.cpu,
      segments: snapshot.segments.map((segment) => compact(segment, 'cpu')),
    },
  };
}

function metricsFixture(version) {
  const host = hostFixture(version);
  const historicalHost = structuredClone(host);
  historicalHost.at -= 10_000;
  const historicalInventory = inventoryFixture(version);
  historicalInventory.agent_browsers.sampled_at = historicalHost.at;
  const historical = buildPerformanceSnapshot({
    host: historicalHost,
    inventory: historicalInventory,
    at: historicalHost.at,
    intervalMs: 10_000,
  });
  const currentInventory = inventoryFixture(version);
  delete currentInventory.agent_browsers;
  const current = buildPerformanceSnapshot({
    host,
    inventory: currentInventory,
    at: host.at,
    intervalMs: 10_000,
  });
  const retainedBrowser = historical.segments.find((segment) => segment.key === 'agent-browsers');
  assert.ok(retainedBrowser, 'fixture must retain one historical Agent-browser segment');
  const performance = {
    ...current,
    segments: [
      ...current.segments,
      {
        ...retainedBrowser,
        active: false,
        peak: {
          memoryBytes: retainedBrowser.current.memoryBytes,
          cpuPercent: retainedBrowser.current.cpuPercent,
        },
      },
    ],
    samples: [compactPerformanceSample(historical), compactPerformanceSample(current)],
  };
  return {
    now: host.at,
    intervalMs: 10_000,
    maxPoints: 720,
    sampler: { running: true, lastSampleAt: host.at, lastError: null },
    host,
    performance,
    entities: [{
      key: 'host',
      kind: 'host',
      id: null,
      name: 'Machine',
      project: null,
      points: [[host.at, host.cpuPercent, host.mem.usedBytes]],
    }],
  };
}

function overviewFixture(stack) {
  const overview = structuredClone(CANONICAL_OVERVIEW);
  overview.console = {
    ...overview.console,
    domain: stack.domain,
    consoleHost: stack.consoleHost,
    consoleOrigin: `https://${stack.consoleHost}:${stack.httpsPort}`,
  };
  overview.inventory.repository_trees = inventoryFixture(1).repository_trees;
  overview.inventory.project_usage = inventoryFixture(1).project_usage;
  overview.inventory.servers = [];
  overview.inventory.docker = { available: true, containers: [] };
  return overview;
}

async function fulfillJson(route, body, status = 200) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    headers: { 'cache-control': 'no-store' },
    body: JSON.stringify(body),
  });
}

async function installRoutes(page, fixture, stack) {
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() !== 'GET') {
      await fulfillJson(route, { error: 'performance fixture is read-only' }, 405);
      return;
    }
    if (pathname === '/api/session') {
      await fulfillJson(route, {
        ...CANONICAL_SESSION,
        accessAdmin: false,
        lifecycleAvailable: false,
      });
      return;
    }
    if (pathname === '/api/prefs') {
      await fulfillJson(route, CANONICAL_PREFS);
      return;
    }
    if (pathname === '/api/overview') {
      await fulfillJson(route, overviewFixture(stack));
      return;
    }
    if (pathname === '/api/metrics/history') {
      fixture.metricsReads += 1;
      await fulfillJson(route, metricsFixture(fixture.version));
      return;
    }
    if (pathname === '/api/telegram') {
      await fulfillJson(route, { version: 1, bots: [], projects: [] });
      return;
    }
    await fulfillJson(route, { error: `unexpected fixture request ${pathname}` }, 500);
  });
}

async function assertPerformanceGeometry(page, viewport) {
  const geometry = await page.evaluate((width) => {
    const section = document.querySelector('#sec-perf');
    const memoryPanel = document.querySelector('#perf-memory-panel');
    const cpuPanel = document.querySelector('#perf-cpu-panel');
    const chartRegion = memoryPanel?.querySelector('.perf-chart-region');
    const legend = document.querySelector('#perf-legend');
    const rect = (node) => node ? node.getBoundingClientRect().toJSON() : null;
    return {
      width,
      documentOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      sectionOverflow: section.scrollWidth - section.clientWidth,
      section: rect(section),
      memoryPanel: rect(memoryPanel),
      cpuPanel: rect(cpuPanel),
      chartRegion: rect(chartRegion),
      legend: rect(legend),
      memoryViewBox: document.querySelector('#perf-memory-chart')?.getAttribute('viewBox'),
      cpuViewBox: document.querySelector('#perf-cpu-chart')?.getAttribute('viewBox'),
      exactData: [...document.querySelectorAll('[data-performance-data-table]')]
        .map((details) => {
          const scroll = details.querySelector('.perf-chart-data-scroll');
          const table = details.querySelector('.perf-chart-data-table');
          return {
            metric: details.getAttribute('data-performance-data-table'),
            open: details.open,
            details: rect(details),
            scroll: rect(scroll),
            scrollClientWidth: scroll?.clientWidth ?? null,
            scrollWidth: scroll?.scrollWidth ?? null,
            overflowX: scroll ? getComputedStyle(scroll).overflowX : null,
            table: rect(table),
          };
        }),
      controlsOutside: [...document.querySelectorAll('#sec-perf button, #sec-perf a')]
        .filter((node) => {
          const box = node.getBoundingClientRect();
          return box.left < -1 || box.right > window.innerWidth + 1;
        }).map((node) => node.outerHTML.slice(0, 100)),
    };
  }, viewport.width);
  assert.ok(geometry.documentOverflow <= 1, JSON.stringify(geometry));
  assert.ok(geometry.sectionOverflow <= 1, JSON.stringify(geometry));
  assert.deepEqual(geometry.controlsOutside, []);
  assert.equal(geometry.memoryViewBox, '0 0 1000 220');
  assert.equal(geometry.cpuViewBox, '0 0 1000 220');
  for (const key of ['section', 'memoryPanel', 'cpuPanel', 'chartRegion', 'legend']) {
    assert.ok(geometry[key], `${key} must render at ${viewport.width}px`);
    assert.ok(geometry[key].left >= -1 && geometry[key].right <= viewport.width + 1,
      `${key} must fit at ${viewport.width}px: ${JSON.stringify(geometry)}`);
  }
  if (viewport.width <= 768) {
    assert.ok(geometry.legend.top >= geometry.chartRegion.bottom - 1,
      `the narrow legend must stack below the chart: ${JSON.stringify(geometry)}`);
  }
  if (viewport.width <= 390) {
    assert.equal(geometry.exactData.length, 2, JSON.stringify(geometry));
    for (const data of geometry.exactData) {
      assert.equal(data.open, true,
        `${data.metric} exact values must remain expanded during phone geometry checks`);
      for (const key of ['details', 'scroll']) {
        assert.ok(data[key], `${data.metric} ${key} must render: ${JSON.stringify(geometry)}`);
        assert.ok(data[key].left >= -1 && data[key].right <= viewport.width + 1,
          `${data.metric} ${key} must not widen the page: ${JSON.stringify(geometry)}`);
      }
      assert.ok(data.table, `${data.metric} table must render after expansion`);
      if (data.scrollWidth > data.scrollClientWidth + 1) {
        assert.ok(['auto', 'scroll'].includes(data.overflowX),
          `${data.metric} wide table needs a local horizontal scroll path: ${JSON.stringify(data)}`);
      }
    }
  }
}

async function activate(locator, page, method) {
  if (method === 'touch') {
    await locator.tap();
    return;
  }
  if (method === 'keyboard') {
    await locator.focus();
    await page.keyboard.press('Enter');
    return;
  }
  await locator.click();
}

async function waitForStage(page, stage, predicate, arg) {
  try {
    return await page.waitForFunction(predicate, arg);
  } catch (error) {
    throw new Error(`${stage}: ${error.message}`, { cause: error });
  }
}

async function assertDialogFit(page, viewport) {
  const geometry = await page.locator('#perf-project-dialog').evaluate((dialog) => {
    const box = dialog.getBoundingClientRect();
    const body = dialog.querySelector('.perf-dialog-body');
    const bodyStyle = body ? getComputedStyle(body) : null;
    return {
      left: box.left,
      right: box.right,
      top: box.top,
      bottom: box.bottom,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
      horizontalOverflow: dialog.scrollWidth - dialog.clientWidth,
      verticalPath: dialog.scrollHeight <= dialog.clientHeight + 1
        || ['auto', 'scroll'].includes(getComputedStyle(dialog).overflowY)
        || ['auto', 'scroll'].includes(bodyStyle?.overflowY),
      bodyClientHeight: body?.clientHeight ?? null,
      bodyScrollHeight: body?.scrollHeight ?? null,
      bodyOverflowY: bodyStyle?.overflowY ?? null,
    };
  });
  assert.ok(geometry.left >= -1 && geometry.right <= geometry.viewportWidth + 1,
    `${viewport.width}px dialog width: ${JSON.stringify(geometry)}`);
  assert.ok(geometry.top >= -1 && geometry.bottom <= geometry.viewportHeight + 1,
    `${viewport.width}px dialog height: ${JSON.stringify(geometry)}`);
  assert.ok(geometry.horizontalOverflow <= 1, JSON.stringify(geometry));
  assert.equal(geometry.verticalPath, true);
  assert.ok(geometry.bodyClientHeight !== null && geometry.bodyScrollHeight !== null,
    'the dialog needs a bounded content body');
  if (geometry.bodyScrollHeight > geometry.bodyClientHeight + 1) {
    assert.ok(['auto', 'scroll'].includes(geometry.bodyOverflowY),
      `overflowing dialog content needs a local vertical scroll path: ${JSON.stringify(geometry)}`);
  }
}

async function assertMobileLegendLabels(page, viewport) {
  for (const legendId of ['#perf-legend', '#perf-cpu-legend']) {
    const legend = page.locator(legendId);
    const columns = legend.locator('.perf-legend-columns > span');
    assert.equal((await columns.nth(2).textContent())?.trim(), 'Current');
    assert.equal(await columns.nth(2).isVisible(), true,
      `${legendId} must visibly identify current values at ${viewport.width}px`);

    const peakHeading = columns.nth(3);
    const mobileLabels = legend.locator('.perf-legend-peak .perf-legend-mobile-label');
    const peakValues = legend.locator('.perf-legend-peak');
    assert.equal(await mobileLabels.count(), await peakValues.count(),
      `${legendId} needs one mobile Peak label for every peak value`);
    if (viewport.width <= 479) {
      assert.equal(await peakHeading.isVisible(), false,
        `${legendId} compact layout must replace its displaced Peak column heading`);
      for (let index = 0; index < await mobileLabels.count(); index += 1) {
        const label = mobileLabels.nth(index);
        assert.equal((await label.textContent())?.trim(), 'Peak');
        assert.equal(await label.isVisible(), true,
          `${legendId} peak ${index + 1} needs a visible in-row label at ${viewport.width}px`);
      }
    } else {
      assert.equal(await peakHeading.isVisible(), true);
      for (let index = 0; index < await mobileLabels.count(); index += 1) {
        assert.equal(await mobileLabels.nth(index).isVisible(), false,
          `${legendId} must avoid duplicate Peak labels at ${viewport.width}px`);
      }
    }
  }
}

async function assertSeriesEmphasis(page, trigger, metric, activation, viewport) {
  const key = await trigger.getAttribute('data-performance-emphasis-key');
  assert.ok(key);
  assert.equal(await trigger.getAttribute('data-performance-additive'), 'false',
    'the focused project/browser fixture must exercise a non-additive drilldown');
  const chart = page.locator(`#perf-${metric}-chart`);
  const readState = () => chart.evaluate((node, selectedKey) => {
    const segments = [...node.querySelectorAll('[data-performance-segment]')];
    const matching = segments.filter((segment) =>
      segment.dataset.performanceSegment === selectedKey);
    const nonmatching = segments.filter((segment) =>
      segment.dataset.performanceSegment !== selectedKey);
    return {
      highlightedKey: node.dataset.highlightedSegment || null,
      matching: matching.length,
      matchingHighlighted: matching.filter((segment) =>
        segment.classList.contains('is-series-highlighted')).length,
      matchingDimmed: matching.filter((segment) =>
        segment.classList.contains('is-series-dimmed')).length,
      nonmatching: nonmatching.length,
      nonmatchingDimmed: nonmatching.filter((segment) =>
        segment.classList.contains('is-series-dimmed')).length,
      matchingRoles: matching.map((segment) => segment.dataset.performanceSeriesRole),
      geometryExact: matching.every((segment) => {
        const value = Number(segment.dataset.performanceValue);
        const total = Number(segment.dataset.performanceTotal);
        const expected = Math.min(value, total) / total * 220;
        return Number.isFinite(expected)
          && Math.abs(Number(segment.getAttribute('height')) - expected) <= .00011;
      }),
    };
  }, key);
  const dialog = page.locator('#perf-project-dialog');
  const assertActive = async (reason) => {
    const active = await readState();
    assert.equal(active.highlightedKey, key, reason);
    assert.ok(active.matching > 0, reason);
    assert.equal(active.matchingHighlighted, active.matching, reason);
    assert.equal(active.matchingDimmed, 0, reason);
    assert.deepEqual([...new Set(active.matchingRoles)], ['drilldown'], reason);
    assert.equal(active.geometryExact, true,
      `${reason}: overlay height must equal observed value / host total`);
    assert.ok(active.nonmatching > 0, reason);
    assert.equal(active.nonmatchingDimmed, active.nonmatching, reason);
    assert.equal(await dialog.evaluate((node) => node.open), false,
      `${reason}: hover/focus must not open project details`);
  };
  const assertRestored = async (reason) => {
    await waitForStage(page, `${viewport.width}px ${reason}`, (selector) => (
      !document.querySelector(selector)?.dataset.highlightedSegment
    ), `#perf-${metric}-chart`);
    const restored = await readState();
    assert.equal(restored.highlightedKey, null, reason);
    assert.equal(restored.matchingHighlighted, 0, reason);
    assert.equal(restored.matchingDimmed, 0, reason);
    assert.equal(restored.nonmatchingDimmed, 0, reason);
  };

  // Move the physical pointer first. Clearing synthetic hover/focus while the
  // pointer still rests on an old row lets Chromium immediately reassert that
  // row before the no-highlight precondition is observed.
  await page.mouse.move(0, 0);
  await page.evaluate((selectedMetric) => {
    document.activeElement?.blur();
    for (const button of document.querySelectorAll(
      `.perf-legend-button[data-performance-metric="${selectedMetric}"]`,
    )) {
      button.dispatchEvent(new PointerEvent('pointerleave', { pointerType: 'mouse' }));
      button.dispatchEvent(new FocusEvent('blur'));
    }
  }, metric);
  await waitForStage(page, `${viewport.width}px initial ${metric} emphasis reset`, (selector) => (
    !document.querySelector(selector)?.dataset.highlightedSegment
  ), `#perf-${metric}-chart`);

  if (activation === 'touch') {
    await trigger.evaluate((node) => node.dispatchEvent(new PointerEvent('pointerenter', {
      pointerType: 'touch',
    })));
    await assertRestored('touch pointer entry must not create sticky hover emphasis');
    return;
  }

  await trigger.evaluate((node) => node.blur());

  await trigger.hover();
  await assertActive('mouse hover must emphasize its project');
  await page.mouse.move(0, 0);
  await assertRestored('pointer leave must restore the complete stack');

  await trigger.focus();
  await assertActive('keyboard focus must emphasize its project');
  await trigger.evaluate((node) => {
    node.blur();
    node.dispatchEvent(new FocusEvent('blur'));
  });
  await assertRestored('keyboard blur must restore the complete stack');

  await trigger.focus();
  await trigger.dispatchEvent('pointerenter', { pointerType: 'mouse' });
  await trigger.dispatchEvent('pointerleave', { pointerType: 'mouse' });
  await assertActive('focused project must remain emphasized after pointer leave');
  await trigger.evaluate((node) => {
    node.blur();
    node.dispatchEvent(new FocusEvent('blur'));
  });
  await assertRestored('blur after pointer leave must clear the final emphasis source');

  await trigger.dispatchEvent('pointerenter', { pointerType: 'mouse' });
  await trigger.focus();
  await trigger.evaluate((node) => {
    node.blur();
    node.dispatchEvent(new FocusEvent('blur'));
  });
  await assertActive('hovered project must remain emphasized after blur');
  await trigger.dispatchEvent('pointerleave', { pointerType: 'mouse' });
  await assertRestored('pointer leave after blur must clear the final emphasis source');
}

async function assertZeroSeriesDoesNotEmphasize(page, trigger, metric) {
  const chart = page.locator(`#perf-${metric}-chart`);
  const assertClear = async (reason) => {
    const state = await chart.evaluate((node) => ({
      highlighted: node.dataset.highlightedSegment || null,
      highlightedCount: node.querySelectorAll('.is-series-highlighted').length,
      dimmedCount: node.querySelectorAll('.is-series-dimmed').length,
      overlayCount: node.querySelectorAll('[data-performance-series-role="drilldown"]').length,
    }));
    assert.deepEqual(state, {
      highlighted: null,
      highlightedCount: 0,
      dimmedCount: 0,
      overlayCount: 0,
    }, reason);
  };
  await page.mouse.move(0, 0);
  await trigger.hover();
  await assertClear('a 0/0 repository hover must leave the host chart unchanged');
  await page.mouse.move(0, 0);
  await trigger.focus();
  await assertClear('a 0/0 repository focus must leave the host chart unchanged');
  await trigger.evaluate((node) => node.blur());
  await assertClear('leaving a 0/0 repository must retain the unmodified chart');
}

async function assertHistoricalBrowserOverlay(page, trigger) {
  const expected = 443 * 1024 ** 2;
  await page.mouse.move(0, 0);
  await trigger.hover();
  const overlay = await page.locator(
    '#perf-memory-chart [data-performance-series-role="drilldown"]',
  ).evaluateAll((nodes) => nodes.map((node) => ({
    key: node.dataset.performanceSegment,
    value: Number(node.dataset.performanceValue),
    total: Number(node.dataset.performanceTotal),
    height: Number(node.getAttribute('height')),
  })));
  assert.ok(overlay.length > 0, 'historical Agent-browser use must remain visible on demand');
  assert.equal(Math.max(...overlay.map((item) => item.value)), expected,
    'the exact retained 443 MiB peak must drive the overlay');
  assert.equal(overlay.every((item) => item.key === 'agent-browsers'), true,
    'Agent browsers must never borrow Developer-account session geometry');
  assert.equal(overlay.every((item) => Math.abs(item.height
    - Math.min(item.value, item.total) / item.total * 220) <= .00011), true,
  'Agent-browser overlay height must be on the host-total chart scale');
  assert.equal(await page.locator(
    '#perf-memory-chart [data-performance-segment="developer-sessions"].is-series-highlighted',
  ).count(), 0, 'the containing developer-session stack must remain a dimmed context, not the selected series');
  await page.mouse.move(0, 0);
}

async function assertRefreshEmphasis(page, fixture) {
  const refresh = async () => {
    const before = fixture.metricsReads;
    fixture.version += 1;
    const response = page.waitForResponse((candidate) => (
      new URL(candidate.url()).pathname === '/api/metrics/history'
      && candidate.request().method() === 'GET'
    ));
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    await response;
    assert.ok(fixture.metricsReads > before);
  };
  let aurora = page.locator('#perf-legend .perf-legend-button')
    .filter({ hasText: 'Aurora' }).first();
  await aurora.evaluate((node) => node.dispatchEvent(new PointerEvent('pointerenter', {
    pointerType: 'mouse',
  })));
  assert.equal(await page.locator('#perf-memory-chart').getAttribute('data-highlighted-segment'),
    await aurora.getAttribute('data-performance-emphasis-key'));
  await refresh();
  await waitForStage(page, 'refresh clears removed hover emphasis', () => (
    !document.querySelector('#perf-memory-chart')?.dataset.highlightedSegment
  ));

  aurora = page.locator('#perf-legend .perf-legend-button')
    .filter({ hasText: 'Aurora' }).first();
  const browser = page.locator(
    '#perf-legend .perf-legend-button[data-performance-kind="agent-browsers"]',
  );
  const auroraKey = await aurora.getAttribute('data-performance-emphasis-key');
  const browserKey = await browser.getAttribute('data-performance-emphasis-key');
  await aurora.focus();
  await browser.evaluate((node) => node.dispatchEvent(new PointerEvent('pointerenter', {
    pointerType: 'mouse',
  })));
  assert.equal(await page.locator('#perf-memory-chart').getAttribute('data-highlighted-segment'),
    browserKey, 'current hover should temporarily override the focused series');
  await refresh();
  await waitForStage(page, 'refresh restores focused legend emphasis', (key) => (
    document.activeElement?.dataset.performanceEmphasisKey === key
    && document.querySelector('#perf-memory-chart')?.dataset.highlightedSegment === key
  ), auroraKey);
  assert.notEqual(await page.locator('#perf-memory-chart').getAttribute('data-highlighted-segment'),
    browserKey, 'removed hover DOM must not leave stale state that masks restored focus');
  await page.locator('#perf-legend .perf-legend-button')
    .filter({ hasText: 'Aurora' }).first().evaluate((node) => node.blur());
  await waitForStage(page, 'refresh focus blur clears emphasis', () => (
    !document.querySelector('#perf-memory-chart')?.dataset.highlightedSegment
  ));
}

async function openAndAssertExactSampleData(page, viewport) {
  const firstSampleAt = BASE_AT - 10_000;
  const expectedLocalTime = await page.evaluate((at) => new Date(at).toLocaleString([], {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: 3,
    timeZoneName: 'short',
  }), firstSampleAt);
  for (const metric of ['memory', 'cpu']) {
    const disclosure = page.locator(`[data-performance-data-table="${metric}"]`);
    assert.equal(await disclosure.count(), 1);
    assert.equal(
      (await disclosure.locator('summary').textContent())?.trim(),
      metric === 'memory' ? 'Exact memory sample data' : 'Exact CPU sample data',
    );
    const summary = disclosure.locator('summary');
    if (viewport.activation === 'touch') {
      await summary.tap();
    } else {
      await summary.focus();
      assert.equal(await summary.evaluate((node) => node === document.activeElement), true,
        `${metric} exact-data summary must receive keyboard focus`);
      await page.keyboard.press('Enter');
    }
    await disclosure.locator('.perf-chart-data-table').waitFor();
    assert.equal(await disclosure.getAttribute('open'), '',
      `${metric} exact data must open through ${viewport.activation}`);

    const firstSample = disclosure.locator('[data-performance-sample]').first();
    assert.ok(await disclosure.locator('[data-performance-sample]').count() >= 1);
    assert.equal(await firstSample.getAttribute('data-performance-sample'), String(firstSampleAt));
    const time = firstSample.locator('time');
    assert.equal(await time.getAttribute('datetime'), new Date(firstSampleAt).toISOString());
    assert.equal((await time.textContent())?.trim(), expectedLocalTime,
      `${metric} sample must display the browser-local time without losing its ISO instant`);

    const chartKeys = await page.locator(
      `#perf-${metric}-chart [data-performance-segment]`,
    ).evaluateAll((nodes) => [...new Set(nodes.map((node) => (
      node.getAttribute('data-performance-segment')
    )).filter(Boolean))]);
    const cells = await firstSample.locator('[data-performance-table-segment]').evaluateAll(
      (nodes) => nodes.map((node) => ({
        key: node.getAttribute('data-performance-table-segment'),
        value: node.textContent.trim(),
      })),
    );
    const values = new Map(cells.map((cell) => [cell.key, cell.value]));
    for (const key of chartKeys) {
      assert.ok(values.has(key), `${metric} exact row is missing chart segment ${key}`);
      assert.notEqual(values.get(key), '', `${metric} segment ${key} needs an exact value`);
      assert.match(values.get(key), metric === 'memory' ? /(?:^|\s)(?:B|KiB|MiB|GiB|TiB)$/ : /%$/,
        `${metric} segment ${key} must retain its visible unit`);
    }
  }
}

async function exerciseViewport(browser, stack, sessionCookie, viewport) {
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    ignoreHTTPSErrors: true,
    locale: 'en-US',
    timezoneId: 'Asia/Dubai',
    colorScheme: 'dark',
    reducedMotion: 'reduce',
    hasTouch: viewport.activation === 'touch',
  });
  const fixture = { version: 1, metricsReads: 0 };
  try {
    await context.addCookies([{
      name: sessionCookie.name,
      value: sessionCookie.value,
      domain: sessionCookie.hostOnly ? sessionCookie.domain : `.${sessionCookie.domain}`,
      path: sessionCookie.path,
      secure: sessionCookie.secure,
      httpOnly: sessionCookie.httpOnly,
      sameSite: 'Lax',
    }]);
    const page = await context.newPage();
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    await installRoutes(page, fixture, stack);
    await page.goto(`https://${stack.consoleHost}:${stack.httpsPort}/#/performance`, {
      waitUntil: 'networkidle',
    });

    const dashboard = page.locator('.performance-dashboard');
    await dashboard.waitFor();
    assert.equal(await dashboard.count(), 1);
    assert.equal(await page.locator('#perf-memory-chart').count(), 1);
    assert.equal(await page.locator('#perf-cpu-chart').count(), 1);
    assert.equal(await page.locator('#perf-accounting-note').count(), 0,
      'the standalone accounting explanation must not return');
    assert.equal(await page.locator('.perf-card').count(), 0,
      'per-resource chart cards must not return');
    assert.ok(await page.locator('#perf-memory-chart [data-performance-segment]').count() >= 4);
    assert.ok(await page.locator('#perf-cpu-chart [data-performance-segment]').count() >= 3);

    const visibleText = await dashboard.innerText();
    for (const label of [
      'Attributed working set',
      'Host stack · disjoint categories',
      'Estimated System & unattributed',
      'Project runtimes',
      'Coordinator control plane',
      'Coordinator background / scheduler',
      'Active test executions',
      'Developer-account sessions',
      'Agent browsers',
      'Available',
      'Accounting coverage',
      'Sample skew',
      'normalized to host capacity',
    ]) {
      assert.match(visibleText, new RegExp(label, 'i'), `${viewport.width}px missing ${label}`);
    }
    assert.doesNotMatch(visibleText, RAW_IDENTITIES,
      'opaque repository identities and private paths must not become visible copy');

    const memoryLegend = page.locator('#perf-legend');
    const projectLegendButtons = memoryLegend.locator(
      '.perf-legend-button[data-performance-kind="project-family"]',
    );
    assert.equal(await projectLegendButtons.count(), 12);
    assert.equal(await memoryLegend.locator(
      '.perf-legend-button[data-performance-kind="agent-browsers"]',
    ).count(), 1);
    assert.ok(await memoryLegend.locator('.perf-legend-item').count() >= 2);
    const projectColors = await projectLegendButtons.locator('.perf-legend-swatch')
      .evaluateAll((nodes) => nodes.map((node) => getComputedStyle(node).backgroundColor));
    assert.equal(projectColors.length, 12,
      'the populated fleet fixture must exercise the complete twelve-color palette');
    assert.equal(new Set(projectColors).size, projectColors.length,
      'visible repository swatches must not collide');
    const rgb = (color) => (color.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
    for (let left = 0; left < projectColors.length; left += 1) {
      for (let right = left + 1; right < projectColors.length; right += 1) {
        assert.ok(Math.hypot(...rgb(projectColors[left]).map((value, index) =>
          value - rgb(projectColors[right])[index])) >= 50,
        `repository swatches are too similar: ${projectColors[left]} / ${projectColors[right]}`);
      }
    }
    const legendColorsByKey = await projectLegendButtons.evaluateAll(
      (nodes) => Object.fromEntries(nodes.map((node) => [
        node.dataset.performanceKey,
        getComputedStyle(node.querySelector('.perf-legend-swatch')).backgroundColor,
      ])),
    );
    assert.equal(Object.keys(legendColorsByKey).length, 12);
    assert.equal(await projectLegendButtons.evaluateAll((nodes) => nodes.every((node) => (
      node.dataset.performanceAdditive === 'false'
      && node.dataset.performanceEmphasisKey === node.dataset.performanceKey
    ))), true,
    'each repository drilldown must select its own exact observed-value history');
    const projectEmphasisKeys = await projectLegendButtons.evaluateAll((nodes) => (
      nodes.map((node) => node.dataset.performanceEmphasisKey)
    ));
    assert.equal(new Set(projectEmphasisKeys).size, projectEmphasisKeys.length,
      'distinct repositories must never share one aggregate highlight key');
    assert.equal(projectEmphasisKeys.includes('project-runtimes'), false,
      'a repository must never claim the aggregate Project runtimes bars as its own');
    assert.ok(await page.locator(
      '#perf-memory-chart [data-performance-segment="project-runtimes"]',
    ).count() > 0, 'the disjoint project-runtime root must be visible in the host stack');
    assert.equal(await page.locator(
      '#perf-memory-chart [data-performance-key^="family:"]',
    ).count(), 0, 'repository drilldowns must not be added to their aggregate host root');
    const agentBrowserColor = await memoryLegend.locator(
      '.perf-legend-button[data-performance-kind="agent-browsers"] .perf-legend-swatch',
    ).evaluate((node) => getComputedStyle(node).backgroundColor);
    assert.equal(projectColors.includes(agentBrowserColor), false,
      'measured agent browsers need a category color distinct from every repository');
    assert.equal(await memoryLegend.locator(
      '.perf-legend-button[data-performance-kind="agent-browsers"]',
    ).getAttribute('data-performance-emphasis-key'), 'agent-browsers',
    'Agent browsers must select its exact history rather than Developer-account sessions');
    assert.equal(await page.locator('#perf-project-dialog').count(), 1,
      'all project controls must share one stable dialog');

    const diagnostics = page.locator('#perf-residual-diagnostics');
    assert.equal(await diagnostics.evaluate((node) => node.open), false,
      'residual diagnostics should be collapsed by default');
    assert.equal(await diagnostics.locator('.perf-residual-diagnostics-note').isVisible(), false,
      'closed diagnostics must not leave off-panel text in rendered geometry');
    await diagnostics.locator(':scope > summary').click();
    const diagnosticText = await diagnostics.innerText();
    assert.match(diagnosticText, /Stack categories are added once\./);
    assert.match(diagnosticText, /PSS is not inferred\./);
    assert.match(diagnosticText, /Coordinator control plane/);
    assert.match(diagnosticText, /Coordinator background \/ scheduler/);
    assert.match(diagnosticText, /Active test executions/);
    assert.match(diagnosticText, /Developer(?:-account| \/ user)? sessions/i);
    assert.match(diagnosticText, /shared(?:[-\s])memory|shmem/i,
      'accessible diagnostics may use the compound adjective shared-memory or the counter name Shmem');
    assert.ok(await diagnostics.locator('[data-performance-diagnostic]').count() >= 6);
    const developerSessions = diagnostics.locator(
      '[data-performance-diagnostic="cgroup:developer-sessions"]',
    );
    await developerSessions.locator(':scope > summary').click();
    assert.match(await developerSessions.innerText(), /holygloryTT/);
    assert.match(await developerSessions.innerText(), /holyglory/);

    await assertMobileLegendLabels(page, viewport);
    if (viewport.width <= 390) {
      await openAndAssertExactSampleData(page, viewport);
    } else {
      assert.equal(await page.locator('[data-performance-data-table]').count(), 2);
    }

    await assertPerformanceGeometry(page, viewport);

    const trigger = memoryLegend.locator('.perf-legend-button').filter({ hasText: 'Aurora' }).first();
    await assertSeriesEmphasis(page, trigger, 'memory', viewport.activation, viewport);
    if (viewport.width === 1440) {
      const prototype = memoryLegend.locator('.perf-legend-button')
        .filter({ hasText: 'prototype' }).first();
      assert.deepEqual(await prototype.locator('.perf-legend-value').allTextContents(), ['0 B', 'Peak 0 B']);
      await assertZeroSeriesDoesNotEmphasize(page, prototype, 'memory');
    }
    if (viewport.refresh) await assertRefreshEmphasis(page, fixture);
    const currentTrigger = memoryLegend.locator('.perf-legend-button')
      .filter({ hasText: 'Aurora' }).first();
    await activate(currentTrigger, page, viewport.activation);
    const dialog = page.locator('#perf-project-dialog');
    await dialog.waitFor({ state: 'visible' });
    assert.equal(await page.locator('#perf-memory-chart').getAttribute('data-highlighted-segment'), null,
      'activating project detail must clear transient chart emphasis before the modal opens');
    assert.equal(await page.locator('#perf-memory-chart .is-series-highlighted, #perf-memory-chart .is-series-dimmed').count(), 0,
      'modal activation must leave no transient highlight classes behind');
    assert.equal(await dialog.getAttribute('open'), '');
    assert.equal(await page.locator('#perf-project-dialog-title').textContent(), 'Aurora');
    assert.equal(
      await page.locator('#perf-project-dialog-close').evaluate((node) => node === document.activeElement),
      true,
      'the modal must move focus to its close control',
    );
    assert.doesNotMatch(await dialog.innerText(), RAW_IDENTITIES);
    await assertDialogFit(page, viewport);

    if (viewport.refresh) {
      const before = fixture.metricsReads;
      fixture.version += 1;
      const refreshed = page.waitForResponse((response) => (
        new URL(response.url()).pathname === '/api/metrics/history'
        && response.request().method() === 'GET'
      ));
      await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
      await refreshed;
      assert.ok(fixture.metricsReads > before);
      await waitForStage(page, `${viewport.width}px dialog refresh`, () => (
        document.querySelector('#perf-project-dialog')?.open
        && /4(?:\.0)? GiB/.test(document.querySelector('#perf-project-dialog-body')?.textContent || '')
      ));
      assert.equal(await page.locator('#perf-project-dialog-title').textContent(), 'Aurora');
      assert.equal(await dialog.getAttribute('open'), '',
        'metrics refresh must update the selected project in place');
    }

    if (viewport.width === 390 || viewport.width === 981) {
      await page.locator('#perf-project-dialog-close').click();
    } else {
      await page.keyboard.press('Escape');
    }
    await waitForStage(page, `${viewport.width}px project dialog close`, () => (
      !document.querySelector('#perf-project-dialog')?.open
    ));
    await waitForStage(page, `${viewport.width}px project dialog focus restoration`, () => (
      document.activeElement?.matches('#perf-legend .perf-legend-button')
      && /Aurora/.test(document.activeElement.textContent || '')
    ));
    assert.equal(
      await memoryLegend.locator('.perf-legend-button').filter({ hasText: 'Aurora' }).first()
        .evaluate((node) => node === document.activeElement),
      true,
      'close/Escape must restore focus after ordinary renders and refresh replacement',
    );

    const browserTrigger = memoryLegend.locator(
      '.perf-legend-button[data-performance-kind="agent-browsers"]',
    );
    assert.deepEqual(await browserTrigger.locator('.perf-legend-value').allTextContents(),
      ['0 B', 'Peak 443 MiB']);
    await assertSeriesEmphasis(page, browserTrigger, 'memory', viewport.activation, viewport);
    if (viewport.width === 1440) await assertHistoricalBrowserOverlay(page, browserTrigger);
    await activate(browserTrigger, page, viewport.activation);
    await dialog.waitFor({ state: 'visible' });
    assert.equal(await page.locator('#perf-project-dialog-title').textContent(), 'Agent browsers');
    const browserDetail = await dialog.innerText();
    for (const label of [
      'Worker sessions', 'Current sessions', 'Last observed work', 'Idle', 'Protected',
      'Processes', 'Recent cleanup', 'reaped', 'reclaimed',
    ]) {
      assert.match(browserDetail, new RegExp(label, 'i'),
        `${viewport.width}px browser detail missing ${label}`);
    }
    assert.doesNotMatch(browserDetail, /last used/i,
      'worker telemetry must never claim it observed human browser use');
    assert.equal(await dialog.locator('.perf-agent-session').count(), 3,
      'bounded worker rows must render the current fixture without exposing internal identifiers');
    assert.doesNotMatch(browserDetail, /browser-codex-aurora|browser-claude-borealis|browser-protected-console/,
      'opaque session identifiers must not become normal dialog content');
    await assertDialogFit(page, viewport);
    await page.locator('#perf-project-dialog-close').click();
    await waitForStage(page, `${viewport.width}px browser dialog close`, () => (
      !document.querySelector('#perf-project-dialog')?.open
    ));
    assert.deepEqual(pageErrors, []);
  } finally {
    await context.close();
  }
}

test('Performance composition, project dialog and responsive structure survive every acceptance width',
  { timeout: 180_000 }, async () => {
    const { chromium } = loadLockedPlaywright();
    const fakeDockerDir = await canonicalTempDir('devops-console-performance-browser-');
    await writeEmptyDockerFixture(fakeDockerDir);
    let stack;
    let browser;
    try {
      stack = await startStack({
        allowedEmails: [CANONICAL_SESSION.email],
        claims: { email: CANONICAL_SESSION.email, name: CANONICAL_SESSION.name },
        coordinatorEnv: { PATH: `${fakeDockerDir}${path.delimiter}${process.env.PATH ?? ''}` },
      });
      const jar = makeJar();
      const loginResult = await login(stack, jar);
      const sessionCookie = jar.get('dc_session');
      assert.equal(loginResult.status, 200);
      assert.ok(sessionCookie);
      browser = await launchChromium(
        chromium,
        [`--host-resolver-rules=MAP ${stack.consoleHost} 127.0.0.1`],
      );
      const failures = [];
      for (const viewport of VIEWPORTS) {
        try {
          await exerciseViewport(browser, stack, sessionCookie, viewport);
        } catch (error) {
          failures.push(new Error(
            `${viewport.width}x${viewport.height} (${viewport.activation}): ${error.message}`,
            { cause: error },
          ));
        }
      }
      if (failures.length) {
        throw new AggregateError(
          failures,
          `Performance viewport matrix found ${failures.length} independent failure(s):\n`
            + failures.map((error, index) => `${index + 1}. ${error.message}`).join('\n'),
        );
      }
    } finally {
      await browser?.close();
      await stack?.close();
      await fs.promises.rm(fakeDockerDir, { recursive: true, force: true });
    }
  });
