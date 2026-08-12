// Fixed, explicitly isolated data for canonical Console screenshots.
//
// These values are not sampled from a developer machine or deployment. They
// exercise the real UI with stable, portable records whose only source is this
// fixture. Keep factual-looking identifiers under /fixtures and example.test.

export const CANONICAL_FIXTURE_ID = 'devops-console-canonical-v1';
export const CANONICAL_NOW = Date.parse('2026-01-15T12:00:00.000Z');

const rootProject = '/fixtures/projects/sample-api';
const temporaryProject = '/fixtures/worktrees/sample-api-preview';
const rootRepoId = 'fixture-repo-sample-api';
const temporaryRepoId = 'fixture-repo-sample-api-preview';
const familyId = 'fixture-family-sample-api';
const workerId = 'fixture-server-worker';
const previewServerId = 'fixture-server-preview';
const databaseResourceId = 'fixture-container-database';
const previewResourceId = 'fixture-container-preview-cache';
const databaseBindingId = 'fixture-database-binding';

export const CANONICAL_SESSION = Object.freeze({
  email: 'operator@example.test',
  name: 'Fixture Operator',
  accessAdmin: true,
});

export const CANONICAL_PREFS = Object.freeze({
  version: 1,
  hidden: { servers: [], docker: [], projects: [] },
});

export const CANONICAL_TELEGRAM = Object.freeze({
  version: 1,
  bots: [],
  projects: [],
});

export const CANONICAL_ACCESS = Object.freeze({ users: [], resources: [] });
export const CANONICAL_INVITES = Object.freeze({ requests: [] });
export const CANONICAL_ARCHIVES = Object.freeze({ archives: [] });
export const CANONICAL_BUGS = Object.freeze({
  schema_version: 1,
  revision: 'fixture-empty-bugs',
  bugs: [],
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
        title: 'Sample API preview',
        auth: 'google',
        target: { kind: 'server', serverId: previewServerId },
        resolved: { host: '127.0.0.1', port: 3419, reason: null },
      },
    ],
    inventory: {
      coordinator_home: '/fixtures/state/coordinator',
      state_path: '/fixtures/state/coordinator/state.json',
      urls: ['http://127.0.0.1:3419'],
      leases: [],
      backups: [],
      postgres: [],
      port_assignments: [
        { project: rootProject, name: 'queue-worker', port: 3418, agent: 'fixture-agent' },
        { project: temporaryProject, name: 'preview-web', port: 3419, agent: 'fixture-agent' },
      ],
      servers: [
        {
          id: workerId,
          key: `${rootProject}::queue-worker`,
          name: 'queue-worker',
          role: 'worker',
          project: rootProject,
          agent: 'fixture-agent',
          status: 'running',
          pid: 41001,
          port: 3418,
          url: null,
          url_is_current: false,
          missing_command: false,
          health: { ok: true, classification: 'healthy' },
          process_usage: { cpu_percent: 2.8, memory_bytes: 57_671_680 },
          supervision: {
            keep_alive: true,
            desired_state: 'running',
            state: 'running',
            breaker: {
              state: 'armed', crash_limit: 10, window_seconds: 300,
              crash_count_in_window: 1,
            },
            recent_crashes: [],
          },
        },
        {
          id: previewServerId,
          key: `${temporaryProject}::preview-web`,
          name: 'preview-web',
          role: 'web',
          project: temporaryProject,
          agent: 'fixture-agent',
          status: 'running',
          pid: 41002,
          port: 3419,
          url: 'http://127.0.0.1:3419',
          url_is_current: true,
          missing_command: false,
          health: { ok: true, classification: 'healthy', status: 200 },
          process_usage: { cpu_percent: 1.7, memory_bytes: 44_040_192 },
        },
      ],
      docker: {
        available: true,
        error: null,
        stats_error: null,
        postgres: [{
          database_binding_id: databaseBindingId,
          docker_resource_id: databaseResourceId,
          host_resource_id: databaseResourceId,
          name: 'sample-api-db',
        }],
        containers: [
          {
            host_resource_id: databaseResourceId,
            docker_resource_id: databaseResourceId,
            name: 'sample-api-db',
            image: 'postgres:17',
            status: 'Up 12 minutes',
            state: 'running',
            ports: '127.0.0.1:55432->5432/tcp',
            stats: { cpu_percent: 1.1, memory_usage_bytes: 48_234_496 },
          },
          {
            host_resource_id: previewResourceId,
            docker_resource_id: previewResourceId,
            name: 'preview-cache',
            image: 'redis:8',
            status: 'Up 4 minutes',
            state: 'running',
            ports: '127.0.0.1:56379->6379/tcp',
            stats: { cpu_percent: 0.6, memory_usage_bytes: 20_971_520 },
          },
        ],
      },
      repositories: [
        {
          repo_id: rootRepoId,
          host_id: 'fixture-host',
          canonical_root: rootProject,
          display_name: 'Sample API',
        },
        {
          repo_id: temporaryRepoId,
          host_id: 'fixture-host',
          canonical_root: temporaryProject,
          display_name: 'Sample API preview',
        },
      ],
      resources: {
        servers: [
          { server_definition_id: workerId, repo_id: rootRepoId },
          { server_definition_id: previewServerId, repo_id: temporaryRepoId },
        ],
        docker: [
          { docker_resource_id: databaseResourceId, repo_id: rootRepoId },
          { docker_resource_id: previewResourceId, repo_id: temporaryRepoId },
        ],
        databases: [{
          database_binding_id: databaseBindingId,
          docker_resource_id: databaseResourceId,
          repo_id: rootRepoId,
          database_name: 'sample_api',
          lifecycle: 'running',
        }],
      },
      observations: {
        docker: [
          { docker_resource_id: databaseResourceId },
          { docker_resource_id: previewResourceId },
        ],
        databases: [{ database_binding_id: databaseBindingId }],
      },
      unassigned_resources: [],
      lifecycle_violations: [],
      repository_trees: [{
        family_id: familyId,
        root_repository: {
          repo_id: rootRepoId,
          canonical_root: rootProject,
          display_name: 'Sample API',
        },
        usage: { cpu_percent: 6.2, memory_bytes: 170_917_888, process_count: 4 },
        scopes: [
          {
            repo_id: rootRepoId,
            kind: 'root',
            canonical_root: rootProject,
            display_name: 'Sample API',
            run_id: null,
            expires_at: null,
            kill_after_run: false,
            usage: { cpu_percent: 3.9, memory_bytes: 105_906_176, process_count: 2 },
            server_ids: [workerId],
            container_resource_ids: [databaseResourceId],
            database_binding_ids: [databaseBindingId],
          },
          {
            repo_id: temporaryRepoId,
            kind: 'temporary',
            canonical_root: temporaryProject,
            display_name: 'Sample API preview',
            run_id: 'fixture-preview-run',
            expires_at: '2026-01-15T13:00:00.000Z',
            kill_after_run: true,
            usage: { cpu_percent: 2.3, memory_bytes: 65_011_712, process_count: 2 },
            server_ids: [previewServerId],
            container_resource_ids: [previewResourceId],
            database_binding_ids: [],
          },
        ],
      }],
      project_usage: [
        {
          usage_key: `path:${rootProject}`,
          project_key: 'sample-api',
          name: 'Sample API',
          project: rootProject,
          cpu_percent: 6.2,
          memory_bytes: 170_917_888,
          process_count: 4,
          server_ids: [workerId, previewServerId],
          container_resource_ids: [databaseResourceId, previewResourceId],
        },
      ],
      recent_events: [],
    },
});

const points = [
  [CANONICAL_NOW - 40_000, 3.8, 150_994_944],
  [CANONICAL_NOW - 30_000, 4.6, 156_237_824],
  [CANONICAL_NOW - 20_000, 5.2, 161_480_704],
  [CANONICAL_NOW - 10_000, 5.8, 166_723_584],
  [CANONICAL_NOW, 6.2, 170_917_888],
];

export const CANONICAL_METRICS = Object.freeze({
  intervalMs: 10_000,
  sampler: { lastError: null },
  host: null,
  entities: [
    { key: `family:${familyId}`, kind: 'project', name: 'Sample API', project: rootProject, points },
    { key: `repo:${rootRepoId}`, kind: 'project', name: 'Sample API root', project: rootProject, points },
    { key: `srv:${workerId}`, kind: 'server', name: 'queue-worker', project: rootProject, points },
    { key: `srv:${previewServerId}`, kind: 'server', name: 'preview-web', project: temporaryProject, points },
    { key: 'dock:sample-api-db', kind: 'docker', name: 'sample-api-db', project: rootProject, points },
    { key: 'dock:preview-cache', kind: 'docker', name: 'preview-cache', project: temporaryProject, points },
  ],
});

export function canonicalApiResponse(url, method = 'GET') {
  const parsed = new URL(url);
  if (method !== 'GET') return null;
  if (parsed.pathname === '/api/session') return CANONICAL_SESSION;
  if (parsed.pathname === '/api/prefs') return CANONICAL_PREFS;
  if (parsed.pathname === '/api/overview') return CANONICAL_OVERVIEW;
  if (parsed.pathname === '/api/metrics/history') return CANONICAL_METRICS;
  if (parsed.pathname === '/api/telegram') return CANONICAL_TELEGRAM;
  if (parsed.pathname === '/api/access') return CANONICAL_ACCESS;
  if (parsed.pathname === '/api/access/requests') return CANONICAL_INVITES;
  if (parsed.pathname === '/api/lifecycle/list') return CANONICAL_ARCHIVES;
  if (parsed.pathname === '/api/bugs') return CANONICAL_BUGS;
  return null;
}
