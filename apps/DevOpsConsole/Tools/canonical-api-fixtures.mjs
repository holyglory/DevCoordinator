// Fixed, explicitly isolated data for canonical Console screenshots.
//
// These values are not sampled from a developer machine or deployment. They
// exercise the real UI with stable, portable records whose only source is this
// fixture. Keep factual-looking identifiers under /fixtures and example.test.

export const CANONICAL_FIXTURE_ID = 'devops-console-canonical-v1';
export const CANONICAL_NOW = Date.parse('2026-01-15T12:00:00.000Z');

const project = '/fixtures/projects/sample-api';
const usageKey = `path:${project}`;

export const CANONICAL_SESSION = Object.freeze({
  email: 'operator@example.test',
  name: 'Fixture Operator',
});

export const CANONICAL_PREFS = Object.freeze({
  version: 1,
  hidden: { servers: [], docker: [], projects: [] },
});

export const CANONICAL_OVERVIEW = Object.freeze({
  console: {
    domain: 'example.test',
    consoleHost: 'console.example.test',
    consoleOrigin: 'https://console.example.test',
    devInsecureHttp: false,
    tls: {
      subject: '*.example.test',
      issuer: 'Fixture Certificate Authority',
      notAfter: '2035-01-15T12:00:00.000Z',
    },
  },
  coordinator: {
    ok: true,
    url: 'http://127.0.0.1:29876',
    lastOkAt: '2026-01-15T12:00:00.000Z',
    lastError: null,
  },
  routes: [
    {
      slug: 'sample-api',
      title: 'Sample API',
      auth: 'google',
      target: { kind: 'server', serverId: 'fixture-server-web' },
      resolved: { host: '127.0.0.1', port: 3417, reason: null },
    },
  ],
  inventory: {
    coordinator_home: '/fixtures/state/coordinator',
    state_path: '/fixtures/state/coordinator/state.json',
    urls: ['http://127.0.0.1:3417'],
    leases: [],
    backups: [],
    postgres: [],
    port_assignments: [
      { project, name: 'web', port: 3417, agent: 'fixture-agent' },
      { project, name: 'worker', port: 3418, agent: 'fixture-agent' },
    ],
    servers: [
      {
        id: 'fixture-server-web',
        key: `${project}::web`,
        name: 'web',
        role: 'web',
        project,
        agent: 'fixture-agent',
        status: 'running',
        pid: 41001,
        port: 3417,
        url: 'http://127.0.0.1:3417',
        url_is_current: true,
        missing_command: false,
        health: { ok: true, classification: 'healthy', status: 200 },
        process_usage: { cpu_percent: 3.4, memory_bytes: 78_643_200 },
      },
      {
        id: 'fixture-server-worker',
        key: `${project}::worker`,
        name: 'worker',
        role: 'worker',
        project,
        agent: 'fixture-agent',
        status: 'stopped',
        pid: null,
        port: 3418,
        url: null,
        url_is_current: false,
        missing_command: false,
        health: { ok: false, classification: 'stopped' },
        process_usage: null,
      },
    ],
    docker: {
      available: true,
      error: null,
      stats_error: null,
      postgres: [{ name: 'sample-api-db' }],
      containers: [
        {
          name: 'sample-api-db',
          image: 'postgres:17',
          status: 'Up 12 minutes',
          state: 'running',
          ports: '127.0.0.1:55432->5432/tcp',
          stats: { cpu_percent: 1.1, memory_usage_bytes: 48_234_496 },
        },
      ],
    },
    project_usage: [
      {
        usage_key: usageKey,
        project_key: 'sample-api',
        name: 'sample-api',
        project,
        cpu_percent: 4.5,
        memory_bytes: 126_877_696,
        process_count: 2,
        server_ids: ['fixture-server-web', 'fixture-server-worker'],
        container_names: ['sample-api-db'],
      },
    ],
    recent_events: [],
  },
});

const points = [
  [CANONICAL_NOW - 40_000, 2.1, 115_343_360],
  [CANONICAL_NOW - 30_000, 3.0, 118_489_088],
  [CANONICAL_NOW - 20_000, 3.7, 121_634_816],
  [CANONICAL_NOW - 10_000, 4.2, 124_780_544],
  [CANONICAL_NOW, 4.5, 126_877_696],
];

export const CANONICAL_METRICS = Object.freeze({
  intervalMs: 10_000,
  sampler: { lastError: null },
  host: null,
  entities: [
    { key: `proj:${usageKey}`, kind: 'project', name: 'sample-api', project, points },
    { key: 'srv:fixture-server-web', kind: 'server', name: 'web', project, points },
    { key: 'dock:sample-api-db', kind: 'docker', name: 'sample-api-db', project, points },
  ],
});

export function canonicalApiResponse(url, method = 'GET') {
  const parsed = new URL(url);
  if (method !== 'GET') return null;
  if (parsed.pathname === '/api/session') return CANONICAL_SESSION;
  if (parsed.pathname === '/api/prefs') return CANONICAL_PREFS;
  if (parsed.pathname === '/api/overview') return CANONICAL_OVERVIEW;
  if (parsed.pathname === '/api/metrics/history') return CANONICAL_METRICS;
  return null;
}
