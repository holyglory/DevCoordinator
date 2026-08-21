// Console REST API (/api/*). The router only dispatches here for the console
// host after session validation; this module still re-checks the session and
// enforces the Origin check on every mutation. Only the fixed endpoint set
// below reaches the authenticated, loopback-only coordinator.

import { CoordError } from './coordinator.mjs';
import { PrefsError } from './prefs.mjs';
import { RouteError, publishedContainerPorts } from './routes.mjs';
import { AccessError, CONSOLE_GRANT, routeGrant } from './access.mjs';
import { TelegramServiceError } from './telegram.mjs';
import { UpstreamAuthError } from './upstream-auth.mjs';
import { BugStoreError } from './bugs.mjs';
import { EdgePublicationProducerError } from '../edge/publication-producer.mjs';

const BODY_LIMIT = 64 * 1024;
// One transfer may contain the complete bounded open registry (2,048 records
// at 16 KiB each), plus its envelope. The route-specific limit must therefore
// accept every bundle that this Console can export.
const BUG_IMPORT_BODY_LIMIT = 40 * 1024 * 1024;
const SERVER_ACTIONS = new Set(['stop', 'restart']);
const WORKER_ACTIONS = new Set(['start', 'stop', 'restart', 'remove']);
const DOCKER_ACTIONS = new Set(['start', 'stop', 'restart']);
const PROJECT_ACTIONS = new Set(['start', 'stop', 'restart']);
const LIFECYCLE_ACTIONS = new Set(['archive', 'purge']);
const LIFECYCLE_TARGET_KINDS = new Set(['project', 'server', 'container', 'worktree']);
const CONTAINER_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
const RUNTIME_ARTIFACT_KINDS = new Set([
  'service', 'run', 'diagnostic', 'docker', 'database_stack', 'worker_attempt',
]);
const RUNTIME_ARTIFACT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RUNTIME_ARTIFACT_MAX_BYTES = 1024 * 1024;
const TAIL_MAX = 5000;
const TELEGRAM_PROJECT_CATALOG_MAX_AGE_MS = 15_000;
const TELEGRAM_PROJECT_CATALOG_MAX_STALE_MS = 5 * 60_000;
const TELEGRAM_PROJECT_CATALOG_COLD_WAIT_MS = 1_000;
const TELEGRAM_PROJECT_CATALOG_LOG_COOLDOWN_MS = 30_000;
const TEST_REPO_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.@-]{0,255}$/;
const TEST_ENTITY_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$/;
const TEST_INTENTS = new Set(['change', 'checkpoint', 'handoff', 'release', 'manual']);
const TEST_WAIT_CODES = new Set(['host_memory']);
const TEST_WAIT_SOURCES = new Set(['fixed_default']);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// Preserve the distinction between a transport failure and an HTTP response
// from the Coordinator. The UI must not call a reachable service
// "unreachable" merely because that service rejected or failed a request.
export function coordinatorOverviewView(base, error = null) {
  if (!error) {
    return {
      ...base,
      failureKind: null,
      errorStatus: null,
    };
  }
  const status = Number.isInteger(error?.status) ? error.status : 0;
  const maintenance = error?.classification === 'maintenance';
  return {
    ...base,
    ok: false,
    failureKind: maintenance ? 'maintenance' : status > 0 ? 'request' : 'transport',
    errorStatus: status > 0 ? status : null,
    lastError: maintenance ? null : error?.message ?? String(error),
    ...(maintenance ? {
      maintenance: {
        active: true,
        retryAfterSeconds: error.retryAfterSeconds ?? 30,
      },
    } : {}),
  };
}

export function createConsoleApi({
  config, log, coordinator, routeStore, upstreamAuthStore, accessStore, guard, certManager, metrics, prefs,
  telegram = null,
  bugStore = null,
  efficiencyStore = null,
  edgePublication = null,
}) {
  const clog = typeof log?.child === 'function' ? log.child({ mod: 'api' }) : log;
  let telegramProjectCatalogLastLog = { key: null, at: 0 };

  function sendJson(res, status, payload) {
    const body = JSON.stringify(payload);
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': Buffer.byteLength(body),
      'cache-control': 'no-store',
    });
    res.end(body);
  }

  function sendRuntimeArtifact(res, kind, id, text) {
    const body = Buffer.from(text, 'utf8');
    if (body.length > RUNTIME_ARTIFACT_MAX_BYTES) {
      throw new ApiError(502, 'coordinator returned an oversized runtime log artifact');
    }
    res.writeHead(200, {
      'content-type': 'text/plain; charset=utf-8',
      'content-length': body.length,
      'content-disposition': `inline; filename="${kind}-${id}.log"`,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    });
    res.end(body);
  }

  async function publishMutation(reason, operation) {
    if (!edgePublication) return operation();
    const completed = await edgePublication.mutate(operation, { reason });
    return completed.result;
  }

  async function readJsonBody(req, { limit = BODY_LIMIT } = {}) {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
      size += chunk.length;
      if (size > limit) {
        // Early exit destroys the request stream via the async iterator.
        throw new ApiError(400, `request body exceeds the ${Math.floor(limit / 1024)}KB limit`);
      }
      chunks.push(chunk);
    }
    if (size === 0) return {};
    let parsed;
    try {
      parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new ApiError(400, 'request body must be valid JSON');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new ApiError(400, 'request body must be a JSON object');
    }
    return parsed;
  }

  function requireString(value, field) {
    if (typeof value !== 'string' || !value.trim()) {
      throw new ApiError(400, `${field} is required`);
    }
    return value.trim();
  }

  function requireTestRepoId(value) {
    const repoId = requireString(value, 'repo_id');
    if (!TEST_REPO_ID_RE.test(repoId)) throw new ApiError(400, 'repo_id must be an immutable repository id');
    return repoId;
  }

  function requireTestEntityId(value, field = 'run_id') {
    const entityId = requireString(value, field);
    if (!TEST_ENTITY_ID_RE.test(entityId)) throw new ApiError(400, `${field} is invalid`);
    return entityId;
  }

  function googleTestActor(session) {
    const email = String(session?.email || '').trim().toLowerCase();
    if (!email || email.length > 240 || /[\u0000-\u001f\u007f]/.test(email)) {
      throw new ApiError(401, 'authenticated Google identity is invalid');
    }
    return `google:${email}`;
  }

  function testRepositoryView(repository) {
    return {
      repo_id: repository.repo_id,
      display_name: repository.display_name || repository.repo_id,
      setup_status: repository.setup_status || repository.manifest_status || 'unknown',
    };
  }

  function optionalTestNumber(value, { integer = false } = {}) {
    if (value === null) return null;
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return undefined;
    if (integer && !Number.isInteger(value)) return undefined;
    return value;
  }

  function optionalTestTimestamp(value) {
    if (value === null) return null;
    if (typeof value === 'number') {
      return Number.isFinite(value) && value >= 0 ? value : undefined;
    }
    if (typeof value !== 'string' || value.length > 64 || !Number.isFinite(Date.parse(value))) {
      return undefined;
    }
    return value;
  }

  function testWaitView(wait) {
    if (!wait || typeof wait !== 'object' || Array.isArray(wait)
      || !TEST_WAIT_CODES.has(wait.code)) return null;
    const view = { code: wait.code };
    for (const field of ['required_mib', 'available_mib', 'reserve_mib']) {
      const value = optionalTestNumber(wait[field]);
      if (value !== undefined) view[field] = value;
    }
    for (const field of ['since', 'observed_at']) {
      const value = optionalTestTimestamp(wait[field]);
      if (value !== undefined) view[field] = value;
    }
    if (TEST_WAIT_SOURCES.has(wait.source)) view.source = wait.source;
    return view;
  }

  function testUsageView(usage) {
    if (!usage || typeof usage !== 'object' || Array.isArray(usage)
      || typeof usage.available !== 'boolean') return null;
    const view = { available: usage.available };
    for (const field of ['peak_memory_mib', 'cpu_seconds']) {
      const value = optionalTestNumber(usage[field]);
      if (value !== undefined) view[field] = value;
    }
    for (const field of ['measured_executions', 'total_executions']) {
      const value = optionalTestNumber(usage[field], { integer: true });
      if (value !== undefined) view[field] = value;
    }
    return view;
  }

  function testRunSummaryView(summary) {
    const view = { ...(summary || {}) };
    delete view.usage;
    const usage = testUsageView(summary?.usage);
    if (usage) view.usage = usage;
    return view;
  }

  function testExecutionView(execution) {
    const view = {};
    for (const field of [
      'execution_id', 'generation', 'repository_generation', 'systemd_unit',
      'systemd_invocation_id', 'launch_confirmed', 'launch_deadline_at',
      'started_at', 'deadline_at', 'last_observed_at',
    ]) {
      if (Object.hasOwn(execution || {}, field)) view[field] = execution[field];
    }
    if (execution?.output_progress && typeof execution.output_progress === 'object'
      && !Array.isArray(execution.output_progress)) {
      view.output_progress = { ...execution.output_progress };
    }
    return view;
  }

  function testRunView(run, actions = {}) {
    const view = {};
    for (const field of [
      'run_id', 'repository_id', 'repo_id', 'plan_id', 'actor', 'intent',
      'source_mode', 'source_fingerprint', 'execution_fingerprint', 'state',
      'conclusion', 'failure_classification', 'priority', 'queued_at',
      'started_at', 'finished_at', 'cancel_reason', 'created_at', 'updated_at',
      'target_count', 'completed_target_count', 'queue_seconds', 'wall_seconds',
      'aggregate_test_seconds', 'passed_count', 'failed_count', 'skipped_count',
      'error_count', 'failure_record_count', 'artifact_count',
    ]) {
      if (Object.hasOwn(run || {}, field)) view[field] = run[field];
    }
    const wait = testWaitView(run?.wait);
    if (wait) view.wait = wait;
    const usage = testUsageView(run?.usage);
    if (usage) view.usage = usage;
    if (Array.isArray(run?.targets)) {
      view.targets = run.targets.map((target) => {
        const item = {};
        for (const field of [
          'target_id', 'target_name', 'wave_index', 'shard_index', 'shard_count',
          'state', 'estimated_seconds', 'queued_at', 'started_at', 'finished_at',
        ]) {
          if (Object.hasOwn(target || {}, field)) item[field] = target[field];
        }
        const targetWait = testWaitView(target?.wait);
        if (targetWait) item.wait = targetWait;
        const targetUsage = testUsageView(target?.usage);
        if (targetUsage) item.usage = targetUsage;
        if (target?.execution && typeof target.execution === 'object'
          && !Array.isArray(target.execution)) item.execution = testExecutionView(target.execution);
        return item;
      });
    }
    return { ...view, ...actions };
  }

  function testSetupView(setup, repoId) {
    const view = {
      schema_version: setup?.schema_version ?? 1,
      repo_id: repoId,
      status: setup?.status || setup?.setup_status || 'unknown',
    };
    for (const field of ['manifest_schema', 'manifest_fingerprint']) {
      if (Object.hasOwn(setup || {}, field)) view[field] = setup[field];
    }
    if (Array.isArray(setup?.targets)) {
      view.targets = setup.targets.map((target) => {
        if (typeof target === 'string') return target;
        const item = {};
        for (const field of ['name', 'driver', 'reporter', 'network']) {
          if (typeof target?.[field] === 'string') item[field] = target[field];
        }
        for (const field of ['fixtures', 'depends_on']) {
          if (Array.isArray(target?.[field])) item[field] = target[field].map(String);
        }
        return item;
      });
    }
    for (const field of ['intents']) {
      if (Array.isArray(setup?.[field])) view[field] = setup[field].map(String);
    }
    for (const field of ['issues', 'input_coverage_gaps']) {
      if (!Array.isArray(setup?.[field])) continue;
      view[field] = setup[field].map((issue) => {
        if (typeof issue === 'string') return issue;
        const item = {};
        for (const key of ['code', 'message', 'detail']) {
          if (typeof issue?.[key] === 'string') item[key] = issue[key];
        }
        if (typeof issue?.path === 'string' && !issue.path.startsWith('/')) item.path = issue.path;
        return item;
      });
    }
    if (setup?.target_graph && typeof setup.target_graph === 'object' && !Array.isArray(setup.target_graph)) {
      view.target_graph = Object.fromEntries(Object.entries(setup.target_graph).map(([name, dependencies]) => [
        name, Array.isArray(dependencies) ? dependencies.map(String) : [],
      ]));
    }
    if (Array.isArray(setup?.capabilities)) view.capabilities = setup.capabilities.map(String);
    if (Array.isArray(setup?.network_requirements)) {
      view.network_requirements = setup.network_requirements.map(String);
    }
    if (setup?.isolation && typeof setup.isolation === 'object' && !Array.isArray(setup.isolation)) {
      view.isolation = {};
      for (const field of ['network', 'private_scratch', 'kill_after_run']) {
        if (Object.hasOwn(setup.isolation, field)) view.isolation[field] = setup.isolation[field];
      }
    }
    if (Array.isArray(setup?.fixtures)) view.fixtures = setup.fixtures.map(String);
    else if (setup?.fixtures && typeof setup.fixtures === 'object') {
      view.fixtures = Object.keys(setup.fixtures).sort();
    }
    return view;
  }

  function filterTestFleet(fleet, repositories, { preserveAggregateMetrics = false } = {}) {
    const byId = new Map((fleet?.repositories || []).map((item) => [item?.repo_id, item]));
    const visible = repositories.map((repository) => byId.get(repository.repo_id) || {
      repo_id: repository.repo_id,
      display_name: repository.display_name || repository.repo_id,
      setup_status: repository.setup_status || repository.manifest_status || 'unknown',
      last_activity_at: null,
      state: 'idle',
      summary: {
        run_count: 0, running_count: 0, test_count: 0, test_seconds: 0,
        wall_seconds: 0, passed_count: 0, failure_count: 0,
        test_failure_count: 0, infrastructure_failure_count: 0,
        attempt_count: 0, failed_run_count: 0, infrastructure_count: 0,
        pass_rate: null, flake_rate: null,
        parallel_efficiency_ratio: null, p95_queue_wait_seconds: null,
      },
      hourly: [],
    });
    const allowed = new Set(visible.map((item) => item.repo_id));
    const additive = [
      'run_count', 'running_count', 'test_count', 'test_seconds', 'wall_seconds',
      'passed_count', 'failure_count', 'failed_run_count', 'distinct_test_count',
      'flaky_test_count', 'infrastructure_count', 'attempt_count',
    ];
    const summary = Object.fromEntries(additive.map((key) => [key, 0]));
    summary.test_failure_count = 0;
    summary.infrastructure_failure_count = 0;
    for (const repository of visible) {
      for (const key of additive) summary[key] += Number(repository.summary?.[key] || 0);
      // New producers use the explicit failure-kind counters. During a
      // same-server rolling replacement an older retained payload can still
      // expose their historical aliases, so aggregate either contract once.
      summary.test_failure_count += Number(
        repository.summary?.test_failure_count
          ?? repository.summary?.failed_run_count
          ?? 0,
      );
      summary.infrastructure_failure_count += Number(
        repository.summary?.infrastructure_failure_count
          ?? repository.summary?.infrastructure_count
          ?? 0,
      );
    }
    // Preserve the historical aggregate names for older Console consumers,
    // while keeping both pairs semantically identical.
    summary.failed_run_count = summary.test_failure_count;
    summary.infrastructure_count = summary.infrastructure_failure_count;
    summary.repository_count = visible.length;
    summary.returned_repository_count = visible.length;
    summary.repositories_with_activity = visible.filter((item) => (
      Number(item.summary?.test_count || 0) > 0
      || Number(item.summary?.run_count || 0) > 0
      || Number(item.summary?.attempt_count || 0) > 0
      || Number(item.summary?.test_seconds || 0) > 0
    )).length;
    summary.parallel_efficiency_ratio = summary.wall_seconds > 0
      ? summary.test_seconds / summary.wall_seconds : null;
    const decided = summary.passed_count + summary.failure_count;
    summary.pass_rate = decided > 0 ? summary.passed_count / decided : null;
    summary.flake_rate = summary.distinct_test_count > 0
      ? summary.flaky_test_count / summary.distinct_test_count : null;
    // Percentiles, avoided-work estimates, and scheduler-capacity fields are
    // not additive. Preserve the coordinator aggregate when the complete
    // configured fleet is represented.
    summary.p95_queue_wait_seconds = preserveAggregateMetrics
      ? (fleet?.summary?.p95_queue_wait_seconds ?? null) : null;
    summary.avoided_work = preserveAggregateMetrics && fleet?.summary?.avoided_work
      && typeof fleet.summary.avoided_work === 'object'
      ? { ...fleet.summary.avoided_work }
      : { available: false, test_count: null, test_seconds: null };

    const hourKeys = Array.isArray(fleet?.hours) ? fleet.hours : [];
    const sourceCapacity = new Map((fleet?.capacity || []).map((cell) => [
      String(cell?.hour_start ?? ''), cell,
    ]));
    const capacity = hourKeys.map((hour) => {
      const key = String(hour);
      let testSeconds = 0;
      let testCount = 0;
      let failureCount = 0;
      let infrastructureCount = 0;
      let activeRepositoryCount = 0;
      for (const repository of visible) {
        const cell = (repository.hourly || []).find((candidate) => (
          String(candidate?.hour_start ?? candidate?.timestamp ?? '') === key
        ));
        if (!cell) continue;
        testSeconds += Number(cell.test_seconds || 0);
        testCount += Number(cell.test_count || 0);
        failureCount += Number(cell.failure_count || 0);
        infrastructureCount += Number(cell.infrastructure_count || 0);
        if (Number(cell.test_seconds || 0) > 0) activeRepositoryCount += 1;
      }
      const retained = preserveAggregateMetrics && sourceCapacity.get(key)
        && typeof sourceCapacity.get(key) === 'object'
        ? sourceCapacity.get(key) : {};
      return {
        ...retained,
        hour_start: key, test_seconds: testSeconds, test_count: testCount,
        failure_count: failureCount, infrastructure_count: infrastructureCount,
        active_repository_count: activeRepositoryCount,
        p95_queue_wait_seconds: preserveAggregateMetrics
          ? (retained.p95_queue_wait_seconds ?? null) : null,
      };
    });
    return {
      ...fleet,
      summary,
      repositories: visible,
      capacity,
      attention: (fleet?.attention || []).filter((item) => allowed.has(item?.repo_id)),
    };
  }

  function requireExactFields(value, fields, label) {
    const expected = new Set(fields);
    const supplied = Object.keys(value || {});
    const unexpected = supplied.filter((field) => !expected.has(field));
    const missing = fields.filter((field) => !Object.hasOwn(value || {}, field));
    if (unexpected.length || missing.length) {
      throw new ApiError(400, `${label} fields are invalid`);
    }
  }

  function requireFields(value, required, optional, label) {
    const allowed = new Set([...required, ...optional]);
    const supplied = Object.keys(value || {});
    const unexpected = supplied.filter((field) => !allowed.has(field));
    const missing = required.filter((field) => !Object.hasOwn(value || {}, field));
    if (unexpected.length || missing.length) {
      throw new ApiError(400, `${label} fields are invalid`);
    }
  }

  function requireTestTargetNames(value) {
    if (value === undefined) return [];
    const targets = requireStringArray(value, 'requested_targets', { maxItems: 256 });
    for (const target of targets) {
      if (Buffer.byteLength(target, 'utf8') > 128 || /[\u0000-\u001f\u007f]/.test(target)) {
        throw new ApiError(400, 'requested_targets contains an invalid target name');
      }
    }
    return targets;
  }

  async function requireKnownTestRepository(repoId) {
    const catalog = await coordinator.testRepositories();
    const repositories = Array.isArray(catalog?.repositories) ? catalog.repositories : [];
    const repository = repositories.find((item) => item?.repo_id === repoId);
    if (!repository) throw new ApiError(404, 'repository is not configured for tests');
    return repository;
  }

  function requireTestSourceSelector(value, repoId) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new ApiError(400, 'source must be a typed repository source selector');
    }
    requireExactFields(
      value,
      ['schema_version', 'kind', 'repository_id', 'repository_generation'],
      'test source',
    );
    if (value.schema_version !== 1 || !['original', 'temporary'].includes(value.kind)) {
      throw new ApiError(400, 'test source selector is unsupported');
    }
    const repositoryId = requireTestRepoId(value.repository_id);
    if (!Number.isInteger(value.repository_generation) || value.repository_generation < 0) {
      throw new ApiError(400, 'test source repository_generation is invalid');
    }
    if (value.kind === 'original' && repositoryId !== repoId) {
      throw new ApiError(400, 'original test source must identify the selected repository');
    }
    return {
      schema_version: 1,
      kind: value.kind,
      repository_id: repositoryId,
      repository_generation: value.repository_generation,
    };
  }

  function boundedSourceLabel(value, fallback) {
    const label = typeof value === 'string' ? value.trim() : '';
    if (!label || label.length > 160 || /[\u0000-\u001f\u007f]/.test(label)) return fallback;
    return label;
  }

  function authoritativeTestSourceCatalog(inventory, repoId) {
    if (!inventory || typeof inventory !== 'object' || Array.isArray(inventory)
      || !Array.isArray(inventory.repository_trees)
      || !Array.isArray(inventory.repositories)) {
      throw new ApiError(409, 'test source authority is unavailable');
    }
    const trees = inventory.repository_trees.filter(
      (tree) => tree?.root_repository?.repo_id === repoId,
    );
    if (trees.length !== 1) {
      throw new ApiError(409, 'test source authority is contradictory');
    }
    const tree = trees[0];
    if (typeof tree.family_id !== 'string' || !tree.family_id
      || !Array.isArray(tree.scopes)) {
      throw new ApiError(409, 'test source authority is incomplete');
    }
    const rootScopes = tree.scopes.filter(
      (scope) => scope?.kind === 'root' && scope?.repo_id === repoId,
    );
    if (rootScopes.length !== 1) {
      throw new ApiError(409, 'original test source authority is contradictory');
    }
    const rootRepository = inventory.repositories.filter(
      (repository) => repository?.repo_id === repoId,
    );
    if (rootRepository.length !== 1
      || rootRepository[0]?.canonical_root !== rootScopes[0]?.canonical_root) {
      throw new ApiError(409, 'original test source identity is stale');
    }
    const rootGeneration = rootRepository[0]?.generation;
    if (!Number.isInteger(rootGeneration) || rootGeneration < 0) {
      throw new ApiError(409, 'original test source generation is unavailable');
    }

    const sources = [{
      selector: {
        schema_version: 1,
        kind: 'original',
        repository_id: repoId,
        repository_generation: rootGeneration,
      },
      label: 'Original repository',
      detail: boundedSourceLabel(tree.root_repository.display_name, repoId),
      temporaryRoot: null,
    }];
    const seen = new Set([repoId]);
    for (const scope of tree.scopes) {
      if (scope?.kind !== 'temporary') continue;
      const sourceRepoId = typeof scope.repo_id === 'string' ? scope.repo_id.trim() : '';
      if (!TEST_REPO_ID_RE.test(sourceRepoId)) {
        throw new ApiError(409, 'temporary test source authority is malformed');
      }
      if (seen.has(sourceRepoId)) {
        throw new ApiError(409, 'temporary test source identity is duplicated');
      }
      seen.add(sourceRepoId);
      if (typeof scope.canonical_root !== 'string' || !scope.canonical_root.startsWith('/')
        || scope.canonical_root === rootScopes[0].canonical_root) {
        throw new ApiError(409, 'temporary test source authority is incomplete');
      }
      const repository = inventory.repositories.filter(
        (candidate) => candidate?.repo_id === sourceRepoId,
      );
      if (repository.length !== 1 || repository[0]?.canonical_root !== scope.canonical_root) {
        throw new ApiError(409, 'temporary test source identity is stale');
      }
      const generation = repository[0]?.generation;
      if (!Number.isInteger(generation) || generation < 0) {
        throw new ApiError(409, 'temporary test source generation is unavailable');
      }
      sources.push({
        selector: {
          schema_version: 1,
          kind: 'temporary',
          repository_id: sourceRepoId,
          repository_generation: generation,
        },
        label: boundedSourceLabel(scope.display_name, `Temporary worktree ${sources.length}`),
        detail: scope.expires_at ? `Expires ${String(scope.expires_at)}` : 'Configured worktree',
        temporaryRoot: scope.canonical_root,
      });
    }
    return { familyId: tree.family_id, sources };
  }

  function testSourceCatalogView(repoId, catalog) {
    return {
      schema_version: 1,
      repository_id: repoId,
      default_source: catalog.sources[0].selector,
      sources: catalog.sources.map(({ selector, label, detail }) => ({
        selector, label, detail,
      })),
    };
  }

  async function resolveTestSource(repoId, selector) {
    // Every source is generation-bound against a fresh server inventory at
    // the moment of planning. The browser supplies only opaque identities;
    // host paths never cross the public API boundary.
    const inventory = await coordinator.inventory({ maxAgeMs: 0 });
    const catalog = authoritativeTestSourceCatalog(inventory, repoId);
    const match = catalog.sources.find((source) => (
      source.selector.kind === selector.kind
      && source.selector.repository_id === selector.repository_id
      && source.selector.repository_generation === selector.repository_generation
    ));
    if (!match) {
      throw new ApiError(409, 'test source is stale or no longer configured');
    }
    return match;
  }

  function requireContainer(value) {
    if (typeof value !== 'string' || !CONTAINER_RE.test(value)) {
      throw new ApiError(400, 'name must be a valid container name or id');
    }
    return value;
  }

  function clampTail(value, fallback) {
    if (value === undefined || value === null) return fallback;
    let n = value;
    if (typeof n === 'string' && /^\d+$/.test(n.trim())) n = Number(n.trim());
    if (!Number.isInteger(n) || n < 1 || n > TAIL_MAX) {
      throw new ApiError(400, `tail must be an integer between 1 and ${TAIL_MAX}`);
    }
    return n;
  }

  function boundedInteger(value, fallback, minimum, maximum, field) {
    const raw = value === null || value === undefined || value === '' ? fallback : Number(value);
    if (!Number.isInteger(raw) || raw < minimum || raw > maximum) {
      throw new ApiError(400, `${field} must be an integer between ${minimum} and ${maximum}`);
    }
    return raw;
  }

  function publicUrl(slug) {
    // Scheme/port follow the deployment (http + explicit port in dev mode);
    // in production this yields exactly https://<slug>.<domain>.
    const origin = new URL(config.consoleOrigin);
    const port = origin.port ? `:${origin.port}` : '';
    return `${origin.protocol}//${slug}.${config.domain}${port}`;
  }

  async function resolveSafe(slug, inventoryData = null) {
    try {
      // Overview route resolution receives its exact inventory snapshot so it
      // cannot fan out into another Coordinator read or contradict the rows
      // rendered beside it. Proxy-time resolution omits this argument and
      // remains independently live.
      return await routeStore.resolve(slug, coordinator, inventoryData);
    } catch (err) {
      return { port: null, reason: err?.message ?? String(err) };
    }
  }

  function toRouteView(route, resolved) {
    const { instanceId: _privateInstanceId, ...publicRoute } = route;
    const view = {
      ...publicRoute,
      url: publicUrl(route.slug),
      upstreamAuth: upstreamAuthStore?.describe(route.slug) ?? { configured: false },
      resolved: { port: resolved?.port ?? null },
    };
    if (resolved?.reason) view.resolved.reason = resolved.reason;
    if (resolved?.server?.status) view.resolved.serverStatus = resolved.server.status;
    if (resolved?.container?.status) view.resolved.containerStatus = resolved.container.status;
    return view;
  }

  async function accessResources() {
    const resources = [{
      id: CONSOLE_GRANT,
      kind: 'console',
      host: config.consoleHost,
      title: 'DevOps Console',
      auth: 'google',
      target: 'Full server and route control',
    }];
    for (const route of routeStore.list()) {
      let target;
      if (route.kind === 'server') target = `${route.serverName} · ${route.project}`;
      else if (route.kind === 'docker') target = `${route.containerName}:${route.containerPort}`;
      else target = `127.0.0.1:${route.port}`;
      resources.push({
        id: routeGrant(route.slug),
        kind: 'route',
        host: `${route.slug}.${config.domain}`,
        title: route.title || route.serverName || route.containerName || route.slug,
        auth: route.auth,
        target,
      });
    }
    return resources;
  }

  function requireAccessAdmin(session) {
    if (!accessStore?.isAdmin(session?.email)) {
      throw new ApiError(403, 'only configured Console owners can manage access');
    }
  }

  function requireLifecycleAdmin(session) {
    requireAccessAdmin(session);
    if (config.lifecycleEnabled !== true) {
      throw new ApiError(503, 'Archive management is not activated on this Console');
    }
  }

  function requireLifecycleIdentity(body) {
    const targetKind = requireString(body.target_kind, 'target_kind');
    const targetId = requireString(body.target_id, 'target_id');
    const canonicalKind = targetKind === 'repository' ? 'project' : targetKind;
    if (!LIFECYCLE_TARGET_KINDS.has(canonicalKind)) {
      throw new ApiError(400, 'target_kind must be project, server, container or worktree');
    }
    if (targetId.length > 300 || /[\u0000-\u001f\u007f]/.test(targetId)) {
      throw new ApiError(400, 'target_id is invalid');
    }
    return { target_kind: canonicalKind, target_id: targetId };
  }

  function lifecycleReason(value, fallback) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value !== 'string') throw new ApiError(400, 'reason must be a string');
    const reason = value.trim();
    if (!reason) return fallback;
    if (reason.length > 300) throw new ApiError(400, 'reason must be at most 300 characters');
    return reason;
  }

  function archiveRows(value) {
    const rows = Array.isArray(value) ? value : value?.archives;
    if (!Array.isArray(rows) || rows.some((row) => !row || typeof row !== 'object' || Array.isArray(row))) {
      throw new ApiError(502, 'coordinator returned an invalid lifecycle archive collection');
    }
    return rows.map((row) => {
      const normalized = {
        ...row,
        target_kind: row.target_kind === 'repository' ? 'project' : row.target_kind,
      };
      if (
        !LIFECYCLE_TARGET_KINDS.has(normalized.target_kind)
        || typeof normalized.target_id !== 'string'
        || !normalized.target_id.trim()
        || normalized.target_id.length > 300
        || /[\u0000-\u001f\u007f]/.test(normalized.target_id)
      ) {
        throw new ApiError(502, 'coordinator returned an invalid lifecycle archive identity');
      }
      return normalized;
    });
  }

  function activeLifecycleTarget(inventory, identity) {
    if (identity.target_kind === 'project') {
      return (inventory?.repositories || []).find((row) => row?.repo_id === identity.target_id) || null;
    }
    if (identity.target_kind === 'server') {
      return (inventory?.servers || []).find((row) => row?.id === identity.target_id) || null;
    }
    if (identity.target_kind === 'container') {
      return (inventory?.docker?.containers || [])
        .find((row) => row?.host_resource_id === identity.target_id) || null;
    }
    return null;
  }

  async function handleLifecycleList(res, session) {
    requireLifecycleAdmin(session);
    try {
      const result = await coordinator.lifecycleArchives();
      sendJson(res, 200, { archives: archiveRows(result) });
    } catch (error) {
      if (error?.status !== 502) throw error;
      const result = await coordinator.lifecycleArchives({ maxAgeMs: -1 });
      sendJson(res, 200, { archives: archiveRows(result) });
    }
  }

  async function handleLifecyclePlan(req, res, session) {
    requireLifecycleAdmin(session);
    const body = await readJsonBody(req);
    const identity = requireLifecycleIdentity(body);
    if (!LIFECYCLE_ACTIONS.has(body.action)) {
      throw new ApiError(400, "action must be 'archive' or 'purge'");
    }

    if (body.action === 'archive') {
      const inventory = await coordinator.inventory({ maxAgeMs: 0 });
      const active = activeLifecycleTarget(inventory, identity);
      if (!active) {
        throw new ApiError(404, 'active lifecycle target not found');
      }
      if (
        identity.target_kind === 'container'
        && active.metadata_source === 'coordinator_ephemeral'
      ) {
        throw new ApiError(
          409,
          'broker-owned ephemeral containers must use their TTL-aware finish lifecycle',
        );
      }
    } else {
      const archives = archiveRows(await coordinator.lifecycleArchives());
      const archived = archives.find(
        (row) => row?.target_kind === identity.target_kind && row?.target_id === identity.target_id,
      );
      if (!archived) throw new ApiError(404, 'archived lifecycle target not found');
      if (archived.removable !== true) {
        throw new ApiError(409, 'archived lifecycle target is not currently removable');
      }
    }

    const plan = await coordinator.lifecyclePlan({
      ...identity,
      action: body.action,
      reason: lifecycleReason(
        body.reason,
        `${body.action} requested via DevOps Console by ${session.email}`,
      ),
    });
    sendJson(res, 200, { plan });
  }

  async function handleLifecycleApply(req, res, session) {
    requireLifecycleAdmin(session);
    const body = await readJsonBody(req);
    const payload = {
      plan_id: requireString(body.plan_id, 'plan_id'),
      plan_fingerprint: requireString(body.plan_fingerprint, 'plan_fingerprint'),
      confirmation_phrase: '',
    };
    if (Object.hasOwn(body, 'confirmation_phrase')) {
      if (typeof body.confirmation_phrase !== 'string') {
        throw new ApiError(400, 'confirmation_phrase must be a string');
      }
      payload.confirmation_phrase = body.confirmation_phrase;
    }
    const result = await coordinator.lifecycleApply(payload);
    sendJson(res, 200, { result });
  }

  async function handleLifecycleRestore(req, res, session) {
    requireLifecycleAdmin(session);
    const body = await readJsonBody(req);
    const identity = requireLifecycleIdentity(body);
    const archives = archiveRows(await coordinator.lifecycleArchives());
    const archived = archives.find(
      (row) => row?.target_kind === identity.target_kind && row?.target_id === identity.target_id,
    );
    if (!archived) throw new ApiError(404, 'archived lifecycle target not found');
    if (archived.restorable !== true) {
      throw new ApiError(409, 'archived lifecycle target is not currently restorable');
    }
    const result = await coordinator.lifecycleRestore({
      ...identity,
      reason: lifecycleReason(
        body.reason,
        `restore requested via DevOps Console by ${session.email}`,
      ),
    });
    sendJson(res, 200, { result });
  }

  async function accessView() {
    const users = accessStore.list();
    return {
      version: 1,
      users,
      resources: await accessResources(),
      invitedCount: users.filter((user) => !user.owner).length,
    };
  }

  async function handleAccessGet(res, session) {
    requireAccessAdmin(session);
    sendJson(res, 200, await accessView());
  }

  async function handleAccessAdd(req, res, session) {
    requireAccessAdmin(session);
    const body = await readJsonBody(req);
    const added = await publishMutation('access-user-added', () => (
      accessStore.addUser({ email: body.email, grants: body.grants ?? [] })
    ));
    clog?.info?.('access user added', {
      admin: session.email,
      email: added.email,
      grants: added.grants,
    });
    sendJson(res, 201, await accessView());
  }

  async function handleAccessGrant(req, res, session, email) {
    requireAccessAdmin(session);
    const body = await readJsonBody(req);
    const updated = await publishMutation('access-grant-changed', () => (
      accessStore.setGrant(email, body.resource, body.allowed)
    ));
    clog?.info?.('access grant changed', {
      admin: session.email,
      email: updated.email,
      resource: body.resource,
      allowed: body.allowed,
    });
    sendJson(res, 200, await accessView());
  }

  async function handleAccessRemove(res, session, email) {
    requireAccessAdmin(session);
    const removed = await publishMutation('access-user-removed', () => accessStore.removeUser(email));
    clog?.info?.('access user removed', { admin: session.email, email: removed.email });
    sendJson(res, 200, await accessView());
  }

  function handleAccessRequestsGet(res, session, searchParams) {
    requireAccessAdmin(session);
    const status = searchParams.get('status') || 'pending';
    sendJson(res, 200, {
      version: 1,
      pendingCount: accessStore.pendingRequestCount(),
      requests: accessStore.listRequests({ status }),
    });
  }

  async function handleAccessRequestDecision(req, res, session, requestId) {
    requireAccessAdmin(session);
    const body = await readJsonBody(req);
    const decided = await publishMutation('access-request-decided', () => (
      accessStore.decideRequest(requestId, body.decision, session.email)
    ));
    clog?.info?.('access request decided', {
      admin: session.email,
      requestId: decided.id,
      email: decided.email,
      resource: decided.resource,
      decision: decided.status,
    });
    sendJson(res, 200, {
      request: decided,
      pendingCount: accessStore.pendingRequestCount(),
      access: await accessView(),
    });
  }

  function requireStringArray(value, field, { maxItems = 500 } = {}) {
    if (!Array.isArray(value) || value.length > maxItems) {
      throw new ApiError(400, `${field} must be an array with at most ${maxItems} items`);
    }
    const items = value.map((item) => requireString(item, field));
    if (new Set(items).size !== items.length) {
      throw new ApiError(400, `${field} must not contain duplicates`);
    }
    return items;
  }

  function requireTelegram() {
    if (!telegram) throw new ApiError(503, 'Telegram control is unavailable');
    return telegram;
  }

  function boundedCoordinatorError(error) {
    const raw = String(error?.message ?? error ?? 'Coordinator inventory unavailable');
    const message = raw
      .replace(/[\u0000-\u001f\u007f]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 240);
    return {
      code: typeof error?.code === 'string' ? error.code.slice(0, 128) : null,
      classification: typeof error?.classification === 'string'
        ? error.classification.slice(0, 64) : null,
      status: Number.isInteger(error?.status) ? error.status : null,
      error: message || 'Coordinator inventory unavailable',
    };
  }

  function logTelegramProjectCatalog(level, message, fields) {
    const key = [level, message, fields?.reason, fields?.code, fields?.classification]
      .map((value) => String(value ?? ''))
      .join(':');
    const now = Date.now();
    if (
      telegramProjectCatalogLastLog.key === key
      && now - telegramProjectCatalogLastLog.at < TELEGRAM_PROJECT_CATALOG_LOG_COOLDOWN_MS
    ) return;
    telegramProjectCatalogLastLog = { key, at: now };
    clog?.[level]?.(message, fields);
  }

  async function telegramProjectInventory() {
    if (typeof coordinator.inventoryForOverview !== 'function') {
      return {
        inventory: await coordinator.inventory({
          maxAgeMs: TELEGRAM_PROJECT_CATALOG_MAX_AGE_MS,
        }),
        state: 'fresh',
        ageMs: 0,
        refreshing: false,
        error: null,
      };
    }
    const snapshot = await coordinator.inventoryForOverview({
      maxAgeMs: TELEGRAM_PROJECT_CATALOG_MAX_AGE_MS,
      maxStaleMs: TELEGRAM_PROJECT_CATALOG_MAX_STALE_MS,
      maxWaitMs: TELEGRAM_PROJECT_CATALOG_COLD_WAIT_MS,
    });
    if (!snapshot?.inventory) {
      if (snapshot?.error) {
        logTelegramProjectCatalog('error', 'Telegram project catalog inventory unavailable', {
          reason: 'inventory_refresh_failed',
          state: snapshot.state ?? null,
          ageMs: Number.isFinite(snapshot.ageMs) ? snapshot.ageMs : null,
          ...boundedCoordinatorError(snapshot.error),
        });
        throw snapshot.error;
      }
      const error = new ApiError(503, 'Coordinator repository catalog is still warming');
      logTelegramProjectCatalog('warn', 'Telegram project catalog inventory is still warming', {
        reason: 'cold_inventory_pending',
        state: snapshot?.state ?? null,
        ageMs: Number.isFinite(snapshot?.ageMs) ? snapshot.ageMs : null,
        refreshing: snapshot?.refreshing === true,
      });
      throw error;
    }
    if (snapshot.error) {
      logTelegramProjectCatalog('warn', 'Telegram project catalog is using retained inventory', {
        reason: 'background_refresh_failed',
        state: snapshot.state ?? null,
        ageMs: Number.isFinite(snapshot.ageMs) ? snapshot.ageMs : null,
        refreshing: snapshot.refreshing === true,
        ...boundedCoordinatorError(snapshot.error),
      });
    }
    return snapshot;
  }

  async function telegramProjects() {
    const snapshot = await telegramProjectInventory();
    const inventory = snapshot.inventory;
    if (!Array.isArray(inventory?.repositories)) {
      logTelegramProjectCatalog('error', 'Telegram project catalog inventory is malformed', {
        reason: 'repositories_not_array',
        state: snapshot.state ?? null,
        ageMs: Number.isFinite(snapshot.ageMs) ? snapshot.ageMs : null,
      });
      throw new ApiError(502, 'coordinator returned an invalid repository collection');
    }
    const repositoryIds = new Set();
    const projects = inventory.repositories.map((repository, index) => {
      const id = repository?.repo_id;
      if (typeof id !== 'string' || !TEST_REPO_ID_RE.test(id)) {
        logTelegramProjectCatalog('error', 'Telegram project catalog identity is malformed', {
          reason: 'repository_identity_invalid',
          state: snapshot.state ?? null,
          ageMs: Number.isFinite(snapshot.ageMs) ? snapshot.ageMs : null,
          repositoryIndex: index,
        });
        throw new ApiError(502, 'coordinator returned an invalid repository identity');
      }
      if (repositoryIds.has(id)) {
        logTelegramProjectCatalog('error', 'Telegram project catalog identity is duplicated', {
          reason: 'repository_identity_duplicated',
          state: snapshot.state ?? null,
          ageMs: Number.isFinite(snapshot.ageMs) ? snapshot.ageMs : null,
          repositoryIndex: index,
        });
        throw new ApiError(502, 'coordinator returned a duplicate repository identity');
      }
      repositoryIds.add(id);
      return {
        id,
        name: repository.display_name || repository.name || id,
        path: repository.canonical_root || repository.project_root || null,
      };
    });
    projects.sort((a, b) => String(a.name).localeCompare(String(b.name)) || a.id.localeCompare(b.id));
    return projects;
  }

  async function telegramView(session) {
    const service = requireTelegram();
    const [managedBots, projects] = await Promise.all([
      service.listBots({ email: session.email }),
      telegramProjects(),
    ]);
    const bots = await Promise.all(managedBots.map(async (bot) => ({
      id: bot.id,
      label: bot.label ?? null,
      username: bot.username ?? null,
      firstName: bot.firstName ?? null,
      ownerEmail: bot.ownerEmail,
      enabled: bot.enabled !== false,
      projects: Array.isArray(bot.projects) ? [...bot.projects] : [],
      createdAt: bot.createdAt ?? null,
      updatedAt: bot.updatedAt ?? null,
      lastPollAt: bot.lastPollAt ?? null,
      lastUpdateAt: bot.lastUpdateAt ?? null,
      lastDeliveryAt: bot.lastDeliveryAt ?? null,
      lastError: bot.lastError ?? null,
      hasToken: bot.hasToken === true,
      authorizations: (await service.listAuthorizationQueue({
        email: session.email,
        botId: bot.id,
        status: null,
      })).map((request) => ({
        id: request.id,
        botId: request.botId,
        botUsername: request.botUsername ?? null,
        telegramUserId: request.telegramUserId,
        username: request.username ?? null,
        firstName: request.firstName ?? null,
        lastName: request.lastName ?? null,
        languageCode: request.languageCode ?? null,
        status: request.status,
        requestedAt: request.requestedAt,
        decidedAt: request.decidedAt ?? null,
        decidedBy: request.decidedBy ?? null,
      })),
    })));
    return { version: 1, bots, projects };
  }

  async function handleTelegramGet(res, session) {
    sendJson(res, 200, await telegramView(session));
  }

  async function handleTelegramRegister(req, res, session) {
    const body = await readJsonBody(req);
    const registered = await requireTelegram().registerBot({
      email: session.email,
      token: body.token, // public-artifact-guard: allow text-secret -- runtime request-value plumbing, not a literal credential
      label: body.label,
      takeoverWebhook: body.takeOver === true,
    });
    clog?.info?.('Telegram bot registered', { owner: session.email });
    sendJson(res, 201, { ...(await telegramView(session)), registeredBotId: registered.id });
  }

  async function handleTelegramRemove(res, session, botId) {
    await requireTelegram().removeBot({ email: session.email, botId });
    clog?.info?.('Telegram bot removed', { actor: session.email, botId });
    sendJson(res, 200, await telegramView(session));
  }

  async function handleTelegramProjects(req, res, session, botId) {
    const service = requireTelegram();
    const body = await readJsonBody(req);
    const repoIds = requireStringArray(body.projectIds, 'projectIds');
    const projects = await telegramProjects();
    const known = new Set(projects.map((project) => project.id));
    if (repoIds.some((repoId) => !known.has(repoId))) {
      throw new ApiError(404, 'one or more coordinator repositories no longer exist');
    }
    if (typeof service.setProjects === 'function') {
      await service.setProjects({ email: session.email, botId, repoIds });
    } else {
      const bot = (await service.listBots({ email: session.email }))
        .find((candidate) => String(candidate.id) === String(botId));
      if (!bot) throw new TelegramServiceError(404, 'bot_not_found', 'Telegram bot not found');
      const current = new Set((bot.projects || []).map(String));
      for (const repoId of new Set([...current, ...repoIds])) {
        const assigned = repoIds.includes(repoId);
        if (current.has(repoId) !== assigned) {
          await service.assignProject({ email: session.email, botId, repoId, assigned });
        }
      }
    }
    clog?.info?.('Telegram bot projects changed', { actor: session.email, botId, count: repoIds.length });
    sendJson(res, 200, await telegramView(session));
  }

  async function handleTelegramAuthorizationDecision(req, res, session, botId, requestId) {
    const service = requireTelegram();
    const body = await readJsonBody(req);
    const request = (await service.listAuthorizationQueue({
      email: session.email,
      botId,
      status: null,
    })).find((candidate) => candidate.id === requestId);
    if (!request) throw new TelegramServiceError(404, 'request_not_found', 'authorization request not found');
    await service.decideAuthorization({ email: session.email, requestId, decision: body.decision });
    clog?.info?.('Telegram authorization decided', {
      actor: session.email,
      botId,
      requestId,
      decision: body.decision,
    });
    sendJson(res, 200, await telegramView(session));
  }

  async function routeViews(inventoryData, inventoryError = null) {
    const unavailable = inventoryError?.message
      || (inventoryData ? null : 'current Coordinator inventory is still loading');
    return Promise.all(
      routeStore.list().map(async (route) => {
        // Fixed-port routes need no Coordinator evidence. Server and Docker
        // routes fail immediately with the one overview error rather than
        // starting another request with a 60-second inventory deadline.
        if (!inventoryData && route.kind !== 'port') {
          return toRouteView(route, { port: null, reason: unavailable });
        }
        return toRouteView(route, await resolveSafe(route.slug, inventoryData));
      }),
    );
  }

  function normProject(value) {
    let v = String(value ?? '');
    while (v.length > 1 && v.endsWith('/')) v = v.slice(0, -1);
    return v;
  }

  // The existing kind:'server' route mapped to this coordinator server, if any.
  function findServerRoute(server) {
    const proj = normProject(server.project);
    return (
      routeStore
        .list()
        .find((r) => r.kind === 'server' && normProject(r.project) === proj && r.serverName === server.name) || null
    );
  }

  async function handleOverview(res, { fresh = false } = {}) {
    let inventoryData = null;
    let coordErr = null;
    let inventoryState = 'error';
    let inventoryAgeMs = null;
    let inventoryRefreshing = false;
    if (typeof coordinator.inventoryForOverview === 'function') {
      const snapshot = await coordinator.inventoryForOverview(fresh
        ? { maxAgeMs: 0, maxStaleMs: 0, maxWaitMs: 250 }
        : undefined);
      inventoryData = snapshot.inventory;
      coordErr = snapshot.error;
      inventoryState = snapshot.state;
      inventoryAgeMs = snapshot.ageMs;
      inventoryRefreshing = snapshot.refreshing;
    } else {
      try {
        inventoryData = await coordinator.inventory({ maxAgeMs: fresh ? 0 : 5000 });
        inventoryState = 'fresh';
        inventoryAgeMs = 0;
      } catch (err) {
        coordErr = err;
      }
    }
    // Piggyback available snapshots into the history buffers so charts stay
    // live while somebody is watching, between background sampler ticks.
    if (inventoryData) metrics?.ingest(inventoryData);
    const base = coordinator.status();
    const coordView = {
      ...coordinatorOverviewView(base, coordErr),
      inventoryState,
      inventoryAgeMs,
      inventoryRefreshing,
    };
    const routes = await routeViews(inventoryData, coordErr);
    sendJson(res, 200, {
      console: {
        version: config.version,
        domain: config.domain,
        consoleHost: config.consoleHost,
        now: new Date().toISOString(),
        tls: typeof certManager?.info === 'function' ? certManager.info() : null,
        devInsecureHttp: Boolean(config.devInsecureHttp),
      },
      coordinator: coordView,
      inventory: inventoryData,
      routes,
    });
  }

  async function handleRouteCreate(req, res) {
    const body = await readJsonBody(req);
    const route = await publishMutation('route-created', async () => {
      const requestedSlug = typeof body.slug === 'string' ? body.slug.trim().toLowerCase() : '';
      if (requestedSlug && !routeStore.get(requestedSlug)) {
        // A deleted hostname must never resurrect grants if the same slug is
        // assigned to a different server later.
        await accessStore.clearResource(routeGrant(requestedSlug));
        await upstreamAuthStore?.remove(requestedSlug);
      }
      return routeStore.create({
        slug: body.slug,
        kind: body.kind,
        port: body.port,
        project: body.project,
        serverName: body.serverName,
        containerName: body.containerName,
        containerPort: body.containerPort,
        auth: body.auth,
        title: body.title,
      });
    });
    sendJson(res, 201, toRouteView(route, await resolveSafe(route.slug)));
  }

  async function handleEdgePublicationReconcile(res) {
    if (!edgePublication) throw new ApiError(404, 'stable-edge publication is not enabled for this Console');
    const publication = await edgePublication.reconcile({ reason: 'user-publication-retry' });
    sendJson(res, 200, { publication });
  }

  async function handleRoutePatch(req, res, slug) {
    const body = await readJsonBody(req);
    const patch = {};
    for (const key of ['auth', 'title', 'port', 'project', 'serverName', 'containerName', 'containerPort', 'kind']) {
      if (Object.hasOwn(body, key)) patch[key] = body[key];
    }
    if (Object.keys(patch).length === 0) {
      throw new ApiError(400, 'no updatable fields in request body');
    }
    const route = await publishMutation('route-updated', async () => {
      const updated = await routeStore.update(slug, patch);
      if (updated.auth === 'public') await upstreamAuthStore?.remove(updated.slug);
      return updated;
    });
    sendJson(res, 200, toRouteView(route, await resolveSafe(route.slug)));
  }

  async function handleRouteDelete(res, slug) {
    await publishMutation('route-removed', async () => {
      const existing = routeStore.get(slug);
      if (existing) await upstreamAuthStore?.remove(existing.slug);
      const removed = await routeStore.remove(slug);
      await accessStore.clearResource(routeGrant(removed.slug));
      return removed;
    });
    sendJson(res, 200, { ok: true });
  }

  async function handleRouteUpstreamAuthSet(req, res, session, slug) {
    requireAccessAdmin(session);
    const body = await readJsonBody(req);
    const result = await publishMutation('route-upstream-credential-set', async () => {
      const route = routeStore.get(slug);
      if (!route) throw new ApiError(404, 'route not found');
      if (route.auth !== 'google') {
        throw new ApiError(400, 'upstream credentials can be configured only for a Google-protected route');
      }
      const upstreamAuth = await upstreamAuthStore.set(route.slug, {
        scheme: body.scheme,
        username: body.username,
        secret: body.secret, // public-artifact-guard: allow text-secret -- runtime request field, never literal credential material
      });
      return { route, upstreamAuth };
    });
    clog?.info?.('route upstream credential configured', {
      admin: session.email,
      slug: result.route.slug,
      scheme: result.upstreamAuth.scheme,
    });
    sendJson(res, 200, { slug: result.route.slug, upstreamAuth: result.upstreamAuth });
  }

  async function handleRouteUpstreamAuthRemove(res, session, slug) {
    requireAccessAdmin(session);
    const result = await publishMutation('route-upstream-credential-removed', async () => {
      const route = routeStore.get(slug);
      if (!route) throw new ApiError(404, 'route not found');
      return { route, removed: await upstreamAuthStore.remove(route.slug) };
    });
    clog?.info?.('route upstream credential removed', {
      admin: session.email,
      slug: result.route.slug,
      removed: result.removed,
    });
    sendJson(res, 200, { slug: result.route.slug, upstreamAuth: { configured: false } });
  }

  async function handleServerAction(req, res, session) {
    const body = await readJsonBody(req);
    const id = requireString(body.id, 'id');
    if (!SERVER_ACTIONS.has(body.action)) {
      throw new ApiError(400, "action must be 'stop' or 'restart'");
    }
    const servers = await coordinator.serversRaw();
    const server = Array.isArray(servers) ? servers.find((s) => s?.id === id) : null;
    if (!server) throw new ApiError(404, 'server not found');
    const payload = {
      agent: `devops-console:${session.email}`,
      project: server.project,
      name: server.name,
      reason:
        typeof body.reason === 'string' && body.reason.trim()
          ? body.reason.trim().slice(0, 300)
          : `${body.action} requested via DevOps Console`,
    };
    const result =
      body.action === 'stop'
        ? await coordinator.serverStop(payload)
        : await coordinator.serverRestart(payload);
    sendJson(res, 200, { server: result });
  }

  function optionalBoolean(body, field) {
    if (!Object.hasOwn(body, field)) return undefined;
    if (typeof body[field] !== 'boolean') {
      throw new ApiError(400, `${field} must be a boolean`);
    }
    return body[field];
  }

  function exactServerRuntimeContext(inventory, serverId, { requireSupervision = false } = {}) {
    if (!Array.isArray(inventory?.repository_trees)) {
      throw new ApiError(409, 'worker actions require an authoritative repository tree');
    }
    const servers = Array.isArray(inventory?.servers) ? inventory.servers : [];
    const serverMatches = servers.filter((server) => String(server?.id ?? '') === serverId);
    if (serverMatches.length !== 1) {
      throw new ApiError(
        serverMatches.length ? 409 : 404,
        serverMatches.length
          ? 'worker identity is duplicated in inventory'
          : 'worker not found',
      );
    }

    const associations = [];
    for (const tree of inventory.repository_trees) {
      const root = tree?.root_repository;
      for (const scope of Array.isArray(tree?.scopes) ? tree.scopes : []) {
        if (!Array.isArray(scope?.server_ids) || !scope.server_ids.some(
          (id) => String(id) === serverId,
        )) continue;
        associations.push({ tree, root, scope });
      }
    }
    if (associations.length !== 1) {
      throw new ApiError(
        409,
        associations.length
          ? 'worker belongs to more than one repository scope; action was refused'
          : 'worker has no authoritative repository scope; action was refused',
      );
    }
    const [{ root, scope }] = associations;
    const rootRepo = root?.canonical_root;
    const effectiveRepo = scope?.canonical_root;
    if (
      typeof rootRepo !== 'string' || !rootRepo.startsWith('/')
      || typeof effectiveRepo !== 'string' || !effectiveRepo.startsWith('/')
      || !['root', 'temporary'].includes(scope?.kind)
      || (scope.kind === 'root' && effectiveRepo !== rootRepo)
    ) {
      throw new ApiError(409, 'worker repository scope is incomplete or contradictory');
    }
    const server = serverMatches[0];
    if (requireSupervision && (!server.supervision || typeof server.supervision !== 'object')) {
      throw new ApiError(409, 'this server is not a supervised worker');
    }
    if (typeof server.name !== 'string' || !server.name) {
      throw new ApiError(409, 'worker has no canonical service name');
    }
    return {
      server,
      rootRepo,
      temporaryRepo: scope.kind === 'temporary' ? effectiveRepo : null,
    };
  }

  function exactWorkerContext(inventory, serverId) {
    return exactServerRuntimeContext(inventory, serverId, { requireSupervision: true });
  }

  function exactDockerRuntimeContext(inventory, resourceId) {
    if (!Array.isArray(inventory?.repository_trees)) {
      throw new ApiError(409, 'container logs require an authoritative repository tree');
    }
    const containers = Array.isArray(inventory?.docker?.containers)
      ? inventory.docker.containers : [];
    const containerMatches = containers.filter((container) => (
      String(container?.host_resource_id ?? container?.docker_resource_id ?? '') === resourceId
    ));
    if (containerMatches.length !== 1) {
      throw new ApiError(
        containerMatches.length ? 409 : 404,
        containerMatches.length
          ? 'container identity is duplicated in inventory'
          : 'container not found',
      );
    }

    const associations = [];
    for (const tree of inventory.repository_trees) {
      const root = tree?.root_repository;
      for (const scope of Array.isArray(tree?.scopes) ? tree.scopes : []) {
        if (!Array.isArray(scope?.container_resource_ids) || !scope.container_resource_ids.some(
          (id) => String(id) === resourceId,
        )) continue;
        associations.push({ root, scope });
      }
    }
    if (associations.length !== 1) {
      throw new ApiError(
        409,
        associations.length
          ? 'container belongs to more than one repository scope; log read was refused'
          : 'container has no authoritative repository scope; log read was refused',
      );
    }
    const [{ root, scope }] = associations;
    const rootRepo = root?.canonical_root;
    const effectiveRepo = scope?.canonical_root;
    const container = containerMatches[0];
    if (
      typeof rootRepo !== 'string' || !rootRepo.startsWith('/')
      || typeof effectiveRepo !== 'string' || !effectiveRepo.startsWith('/')
      || !['root', 'temporary'].includes(scope?.kind)
      || (scope.kind === 'root' && effectiveRepo !== rootRepo)
      || !['docker_labels', 'coordinator_sidecar', 'catalog_association'].includes(
        container?.metadata_source,
      )
      || (typeof container.project === 'string' && container.project !== effectiveRepo)
    ) {
      throw new ApiError(409, 'container repository scope is incomplete or contradictory');
    }
    if (typeof container.name !== 'string' || !container.name) {
      throw new ApiError(409, 'container has no canonical display name');
    }
    return {
      container,
      rootRepo,
      temporaryRepo: scope.kind === 'temporary' ? effectiveRepo : null,
    };
  }

  async function handleWorkerAction(req, res, session) {
    const body = await readJsonBody(req);
    const allowedFields = new Set([
      'id', 'action', 'reason', 'keep_alive', 'rearm_crash_loop',
      'remove_plan_id', 'remove_plan_fingerprint', 'remove_confirmation_phrase',
    ]);
    const unknown = Object.keys(body).filter((field) => !allowedFields.has(field));
    if (unknown.length) {
      throw new ApiError(400, `unsupported worker action field: ${unknown.join(', ')}`);
    }
    const id = requireString(body.id, 'id');
    const action = requireString(body.action, 'action');
    if (!WORKER_ACTIONS.has(action)) {
      throw new ApiError(400, "action must be 'start', 'stop', 'restart' or 'remove'");
    }
    if (action === 'remove') requireAccessAdmin(session);

    const keepAlive = optionalBoolean(body, 'keep_alive');
    const rearmCrashLoop = optionalBoolean(body, 'rearm_crash_loop');
    if (action === 'remove' && (keepAlive !== undefined || rearmCrashLoop !== undefined)) {
      throw new ApiError(400, 'worker removal cannot change supervision policy');
    }
    if (action === 'stop' && (keepAlive !== undefined || rearmCrashLoop !== undefined)) {
      throw new ApiError(400, 'stop is a distinct desired-stopped action and accepts no policy fields');
    }

    const removalFields = [
      'remove_plan_id', 'remove_plan_fingerprint', 'remove_confirmation_phrase',
    ];
    const suppliedRemovalFields = removalFields.filter((field) => Object.hasOwn(body, field));
    if (action !== 'remove' && suppliedRemovalFields.length) {
      throw new ApiError(400, 'removal plan fields are valid only for action remove');
    }
    if (suppliedRemovalFields.length !== 0 && suppliedRemovalFields.length !== removalFields.length) {
      throw new ApiError(400, 'all exact removal plan fields are required together');
    }

    const inventory = await coordinator.inventory({ maxAgeMs: 0 });
    const context = exactWorkerContext(inventory, id);
    const options = {
      reason: lifecycleReason(
        body.reason,
        `${action} worker requested via DevOps Console by ${session.email}`,
      ),
    };
    if (keepAlive !== undefined) options.keep_alive = keepAlive;
    if (rearmCrashLoop !== undefined) options.rearm_crash_loop = rearmCrashLoop;
    for (const field of suppliedRemovalFields) {
      if (field === 'remove_confirmation_phrase') {
        if (typeof body[field] !== 'string') {
          throw new ApiError(400, `${field} must be a string`);
        }
        options[field] = body[field];
      } else {
        options[field] = requireString(body[field], field);
      }
    }

    const request = {
      schema_version: 1,
      action,
      agent: `devops-console:${session.email}`,
      root_repo: context.rootRepo,
      temporary_repo: context.temporaryRepo,
      target: { kind: 'service', id, name: context.server.name },
      purpose: 'development',
      ttl_seconds: null,
      kill_after_run: false,
      options,
    };
    let runtime;
    try {
      runtime = await coordinator.runtimeAction(request);
    } catch (error) {
      // A blocked removal is still a useful, read-only plan. Preserve its
      // exact blockers for the review dialog; every mutation failure remains
      // an HTTP error.
      if (
        action === 'remove'
        && error instanceof CoordError
        && error.status === 409
        && error.body?.classification === 'worker_remove_blocked'
      ) {
        runtime = error.body;
      } else {
        throw error;
      }
    }
    if (
      !runtime || runtime.schema_version !== 1 || runtime.action !== action
      || runtime.target?.kind !== 'service' || String(runtime.target?.id ?? '') !== id
    ) {
      throw new ApiError(502, 'coordinator returned a worker result for a different target');
    }
    clog?.info?.('worker lifecycle requested', {
      actor: session.email,
      action,
      workerId: id,
      classification: runtime.classification,
    });
    sendJson(res, 200, { runtime });
  }

  // Assign / change / remove the subdomain of a coordinator server in one call.
  // Body: { id, slug, auth? }. Empty slug unassigns. Reuses the route store, so
  // slug validation, reserved names, and the coordinator-port guard all apply.
  async function handleServerSubdomain(req, res, session) {
    const body = await readJsonBody(req);
    const id = requireString(body.id, 'id');
    // Fresh read: mapping a specific server must not miss one that started
    // within the raw-servers cache window.
    const servers = await coordinator.serversRaw({ maxAgeMs: 0 });
    const server = Array.isArray(servers) ? servers.find((s) => s?.id === id) : null;
    if (!server) throw new ApiError(404, 'server not found');
    if (!server.project || !server.name) {
      throw new ApiError(400, 'server is missing project/name and cannot be mapped to a subdomain');
    }
    const rawSlug = typeof body.slug === 'string' ? body.slug.trim() : '';
    const authGiven = Object.hasOwn(body, 'auth') ? body.auth : undefined;
    const outcome = await publishMutation('server-subdomain-changed', async () => {
      const existing = findServerRoute(server);

      // Unassign: remove the mapped route (idempotent when none exists).
      if (!rawSlug) {
        if (existing) {
          await upstreamAuthStore?.remove(existing.slug);
          await routeStore.remove(existing.slug);
          await accessStore.clearResource(routeGrant(existing.slug));
        }
        return { route: null, status: 200, previousSlug: existing?.slug ?? null };
      }

      // Same slug already mapped: only the access level (or nothing) can change.
      if (existing && existing.slug === rawSlug) {
        const route = authGiven === undefined
          ? existing
          : await routeStore.update(existing.slug, { auth: authGiven });
        if (route.auth === 'public') await upstreamAuthStore?.remove(route.slug);
        return { route, status: 200, previousSlug: existing.slug };
      }

      // New or renamed mapping: create the new route (validates + enforces
      // uniqueness), then drop the old one so a server maps to a single subdomain.
      const occupied = routeStore.get(rawSlug);
      if (occupied && rawSlug === occupied.slug) throw new ApiError(409, `route '${rawSlug}' already exists`);
      if (!occupied) {
        await accessStore.clearResource(routeGrant(rawSlug));
        await upstreamAuthStore?.remove(rawSlug);
      }
      const route = await routeStore.create({
        slug: rawSlug,
        kind: 'server',
        project: server.project,
        serverName: server.name,
        auth: authGiven ?? existing?.auth,
        title: existing?.title,
      });
      if (existing) {
        if (route.auth === 'google') await upstreamAuthStore?.move(existing.slug, route.slug);
        else await upstreamAuthStore?.remove(existing.slug);
        await accessStore.moveResource(routeGrant(existing.slug), routeGrant(route.slug));
        await routeStore.remove(existing.slug);
      }
      return { route, status: 201, previousSlug: existing?.slug ?? null };
    });
    if (!outcome.route) {
      clog?.info?.('server subdomain removed', { server: server.name, slug: outcome.previousSlug });
      return sendJson(res, outcome.status, { route: null });
    }
    clog?.info?.('server subdomain assigned', {
      server: server.name,
      slug: outcome.route.slug,
      auth: outcome.route.auth,
    });
    return sendJson(res, outcome.status, {
      route: toRouteView(outcome.route, await resolveSafe(outcome.route.slug)),
    });
  }

  // The existing kind:'docker' route publishing this container, if any.
  function findDockerRoute(name) {
    return routeStore.list().find((r) => r.kind === 'docker' && r.containerName === name) || null;
  }

  // Assign / change / remove the subdomain of a docker container in one call.
  // Body: { name, slug, auth?, port? }. Empty slug unassigns. `port` is the
  // container-side port and is only needed when the container publishes more
  // than one — the published host port is resolved live on every request.
  async function handleDockerSubdomain(req, res, session) {
    const body = await readJsonBody(req);
    const name = requireContainer(body.name);
    // Fresh read: mapping a container must not miss one that started within
    // the inventory cache window.
    const inventoryData = await coordinator.inventory({ maxAgeMs: 0 });
    const docker = inventoryData?.docker;
    if (!docker || docker.available === false) {
      throw new ApiError(400, 'docker is unavailable on this machine');
    }
    const container = (Array.isArray(docker.containers) ? docker.containers : [])
      .find((c) => c?.name === name);
    if (!container) throw new ApiError(404, 'container not found');
    const rawSlug = typeof body.slug === 'string' ? body.slug.trim() : '';

    if (rawSlug && container.metadata_source === 'coordinator_ephemeral') {
      throw new ApiError(
        409,
        'broker-owned ephemeral containers cannot receive durable routes',
      );
    }
    if (
      rawSlug
      && (
      !container.project
      || !['docker_labels', 'coordinator_sidecar', 'catalog_association'].includes(
        container.metadata_source,
      )
      )
    ) {
      throw new ApiError(
        400,
        'container has no repository association; catalog it before assigning a route',
      );
    }

    const authGiven = Object.hasOwn(body, 'auth') ? body.auth : undefined;
    const options = publishedContainerPorts(container.ports);
    const outcome = await publishMutation('docker-subdomain-changed', async () => {
      const existing = findDockerRoute(name);

      // Unassign: remove the mapped route (idempotent when none exists).
      if (!rawSlug) {
        if (existing) {
          await upstreamAuthStore?.remove(existing.slug);
          await routeStore.remove(existing.slug);
          await accessStore.clearResource(routeGrant(existing.slug));
        }
        return { route: null, status: 200, previousSlug: existing?.slug ?? null };
      }

      // An explicit container-side port must be currently published, so a typo
      // cannot silently create a route that never resolves — EXCEPT when it is
      // the route's existing port (auth changes and renames must keep working
      // while the container is stopped or republished elsewhere).
      let requestedPort;
      if (body.port !== undefined && body.port !== null && body.port !== '') {
        const p = Number(body.port);
        if (!Number.isInteger(p) || p < 1 || p > 65535) {
          throw new ApiError(400, 'port must be a container port between 1 and 65535');
        }
        if (p !== existing?.containerPort && !options.some((o) => o.containerPort === p)) {
          const published = options.map((o) => o.containerPort).join(', ') || 'none';
          throw new ApiError(400, `container does not publish port ${p} (published: ${published})`);
        }
        requestedPort = p;
      }

      // Same slug already mapped: only access level / container port can
      // change, and the port only when explicitly requested — never silently
      // repointed to whatever happens to be published right now.
      if (existing && existing.slug === rawSlug) {
        const patch = {};
        if (authGiven !== undefined) patch.auth = authGiven;
        if (requestedPort !== undefined && existing.containerPort !== requestedPort) {
          patch.containerPort = requestedPort;
        }
        const route = Object.keys(patch).length
          ? await routeStore.update(existing.slug, patch)
          : existing;
        if (route.auth === 'public') await upstreamAuthStore?.remove(route.slug);
        return { route, status: 200, previousSlug: existing.slug };
      }

      // Renames keep the existing port; a brand-new mapping picks the only
      // published port or demands an explicit choice.
      let containerPort = requestedPort ?? existing?.containerPort;
      if (containerPort === undefined) {
        if (options.length === 1) {
          containerPort = options[0].containerPort;
        } else if (options.length === 0) {
          throw new ApiError(400, 'container publishes no host ports — publish one (compose "ports:") and start the container, then try again');
        } else {
          const published = options.map((o) => o.containerPort).join(', ');
          throw new ApiError(400, `container publishes several ports (${published}) — pass "port" to choose one`);
        }
      }

      // New or renamed mapping: create the new route (validates + enforces
      // uniqueness), then drop the old one so a container maps to one subdomain.
      const occupied = routeStore.get(rawSlug);
      if (occupied && rawSlug === occupied.slug) throw new ApiError(409, `route '${rawSlug}' already exists`);
      if (!occupied) {
        await accessStore.clearResource(routeGrant(rawSlug));
        await upstreamAuthStore?.remove(rawSlug);
      }
      const route = await routeStore.create({
        slug: rawSlug,
        kind: 'docker',
        containerName: name,
        containerPort,
        auth: authGiven ?? existing?.auth,
        title: existing?.title,
      });
      if (existing) {
        if (route.auth === 'google') await upstreamAuthStore?.move(existing.slug, route.slug);
        else await upstreamAuthStore?.remove(existing.slug);
        await accessStore.moveResource(routeGrant(existing.slug), routeGrant(route.slug));
        await routeStore.remove(existing.slug);
      }
      return { route, status: 201, previousSlug: existing?.slug ?? null };
    });
    if (!outcome.route) {
      clog?.info?.('docker subdomain removed', { container: name, slug: outcome.previousSlug });
      return sendJson(res, outcome.status, { route: null });
    }
    clog?.info?.('docker subdomain assigned', {
      container: name,
      slug: outcome.route.slug,
      auth: outcome.route.auth,
      containerPort: outcome.route.containerPort,
    });
    return sendJson(res, outcome.status, {
      route: toRouteView(outcome.route, await resolveSafe(outcome.route.slug)),
    });
  }

  function handleMetricsHistory(res, searchParams) {
    if (!metrics) {
      return sendJson(res, 200, {
        entities: [], host: null, performance: null, sampler: { running: false },
      });
    }
    const rawLimit = searchParams.get('limit');
    let limit;
    if (rawLimit !== null) {
      limit = Number(rawLimit);
      if (!Number.isInteger(limit) || limit < 1) {
        throw new ApiError(400, 'limit must be a positive integer');
      }
    }
    return sendJson(res, 200, metrics.history(limit ? { limit } : undefined));
  }

  async function handlePortLease(req, res, session) {
    const body = await readJsonBody(req);
    const payload = {
      agent: `devops-console:${session.email}`,
      project:
        typeof body.project === 'string' && body.project.trim() ? body.project.trim() : config.projectRoot,
      purpose:
        typeof body.purpose === 'string' && body.purpose.trim()
          ? body.purpose.trim().slice(0, 120)
          : 'devops-console',
    };
    if (body.preferred !== undefined && body.preferred !== null && body.preferred !== '') {
      const preferred = Number(body.preferred);
      if (!Number.isInteger(preferred) || preferred < 1 || preferred > 65535) {
        throw new ApiError(400, 'preferred must be a port between 1 and 65535');
      }
      payload.preferred = preferred;
      // A preferred port outside the default 3000-3999 range would be rejected
      // by the coordinator, so pin the range to the requested port.
      payload.range = String(preferred);
    }
    if (body.ttl !== undefined && body.ttl !== null && body.ttl !== '') {
      const ttl = Number(body.ttl);
      if (!Number.isInteger(ttl)) throw new ApiError(400, 'ttl must be an integer number of seconds');
      payload.ttl = ttl; // ttl <= 0 means the lease never expires
    }
    const lease = await coordinator.leasePort(payload);
    sendJson(res, 201, { lease });
  }

  async function handlePortRelease(req, res, session) {
    const body = await readJsonBody(req);
    const leaseId = requireString(body.lease_id, 'lease_id');
    const inventoryData = await coordinator.inventory({ maxAgeMs: 0 });
    const ownedLease = (inventoryData?.leases || []).find((lease) => lease?.id === leaseId);
    if (!ownedLease?.project) throw new ApiError(400, 'matching lease not found');
    const lease = await coordinator.releasePort({
      lease_id: leaseId,
      agent: `devops-console:${session.email}`,
      project: ownedLease.project,
    });
    sendJson(res, 200, { lease });
  }

  // Remove a durable port assignment (the pin survives everything else, so
  // this is the only console path that frees a pinned port).
  async function handlePortUnassign(req, res, session) {
    const body = await readJsonBody(req);
    const payload = { agent: `devops-console:${session.email}` };
    if (typeof body.name === 'string' && body.name.trim()) {
      payload.name = body.name.trim();
      payload.project = requireString(body.project, 'project');
    } else {
      const port = Number(body.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new ApiError(400, 'unassign needs a server name + project, or a port');
      }
      payload.port = port;
      if (typeof body.project === 'string' && body.project.trim()) payload.project = body.project.trim();
      if (body.force === true) payload.force = true;
      if (!payload.project && !payload.force) {
        // A bare port with no project always names another project's pin from
        // the coordinator's perspective, so demand the explicit confirmation
        // it will require anyway instead of a guaranteed downstream refusal.
        throw new ApiError(400, 'unassigning by bare port removes another project\'s pin — pass force: true to confirm');
      }
    }
    const assignment = await coordinator.unassignPort(payload);
    sendJson(res, 200, { assignment });
  }

  async function handleServerLogs(req, res, session) {
    const body = await readJsonBody(req);
    const unknown = Object.keys(body).filter((field) => field !== 'id');
    if (unknown.length) {
      throw new ApiError(400, `unsupported server log field: ${unknown.join(', ')}`);
    }
    const id = requireString(body.id, 'id');
    const inventory = await coordinator.inventory({ maxAgeMs: 0 });
    const context = exactServerRuntimeContext(inventory, id);
    const runtime = await coordinator.runtimeAction({
      schema_version: 1,
      action: 'capture_logs',
      agent: `devops-console:${session.email}`,
      root_repo: context.rootRepo,
      temporary_repo: context.temporaryRepo,
      target: { kind: 'service', id, name: context.server.name },
      purpose: 'development',
      ttl_seconds: null,
      kill_after_run: false,
      options: {},
    });
    const artifact = runtime?.artifact;
    const content = runtime?.artifact_content;
    if (
      !runtime || runtime.schema_version !== 1 || runtime.ok !== true
      || runtime.action !== 'capture_logs'
      || runtime.target?.kind !== 'service' || String(runtime.target?.id ?? '') !== id
      || !artifact || typeof artifact !== 'object' || Array.isArray(artifact)
      || !content || typeof content !== 'object' || Array.isArray(content)
      || !RUNTIME_ARTIFACT_ID_RE.test(String(artifact.artifact_id ?? ''))
      || content.artifact_id !== artifact.artifact_id
      || typeof content.text !== 'string'
      || Buffer.byteLength(content.text, 'utf8') > RUNTIME_ARTIFACT_MAX_BYTES
    ) {
      throw new ApiError(502, 'coordinator returned an invalid exact-service log artifact');
    }
    sendJson(res, 200, { text: content.text, artifact: {
      artifact_id: artifact.artifact_id,
      captured_at: artifact.captured_at ?? null,
      retained: false,
      truncated: artifact.truncated === true,
    } });
  }

  // Whole-project runtime control (starts declared dependencies before web
  // servers, preserves pinned ports). Slow by nature: compose pulls and
  // health waits can take minutes; the coordinator client allows 300s.
  async function handleProjectAction(req, res, session) {
    const body = await readJsonBody(req);
    const project = requireString(body.project, 'project');
    if (!PROJECT_ACTIONS.has(body.action)) {
      throw new ApiError(400, "action must be 'start', 'stop' or 'restart'");
    }
    const operationId = body.operation_id == null
      ? null
      : requireString(body.operation_id, 'operation_id');
    if (operationId !== null && (!UUID_RE.test(operationId) || operationId.toLowerCase() !== operationId)) {
      throw new ApiError(400, 'operation_id must be a canonical UUID');
    }
    // Only repos the coordinator can vouch for may be acted on: either it
    // already tracks them (inventory) or they carry a declared runtime the
    // coordinator recognizes (first start of a new project). An arbitrary
    // path with neither must not become a command-execution vector.
    const inventoryData = await coordinator.inventory();
    let known = (inventoryData?.project_usage || []).some(
      (row) => row?.project && row.project === project,
    );
    if (!known) {
      try {
        const status = await coordinator.projectStatus({ project });
        // 'declared' means a runtime config exists; otherwise accept only
        // real services (the synthetic type:'runtime' placeholder that says
        // "nothing found here" does not count).
        known = status?.declared === true
          || (Array.isArray(status?.services)
            && status.services.some((svc) => svc?.type && svc.type !== 'runtime'));
      } catch {
        known = false;
      }
    }
    if (!known) throw new ApiError(404, 'unknown project — nothing registered and no declared runtime');
    const result = await coordinator.projectAction(body.action, {
      agent: `devops-console:${session.email}`,
      project,
      ...(operationId === null ? {} : { operation_id: operationId }),
    });
    if (operationId !== null && result?.operation_id !== operationId) {
      throw new ApiError(502, 'coordinator returned a contradictory project operation ID');
    }
    sendJson(res, 200, { result });
  }

  function handlePrefsGet(res) {
    sendJson(res, 200, prefs.get());
  }

  async function handlePrefsPatch(req, res) {
    const body = await readJsonBody(req);
    // Deltas only: {hide:{kind:[keys]}, unhide:{kind:[keys]}}. Whole-list
    // replacement is deliberately unsupported — a stale client snapshot must
    // never be able to wipe hides made elsewhere.
    const updated = await prefs.applyHiddenDelta({ hide: body.hide, unhide: body.unhide });
    sendJson(res, 200, updated);
  }

  async function handleDockerAction(req, res, session) {
    const body = await readJsonBody(req);
    const name = requireContainer(body.name);
    if (!DOCKER_ACTIONS.has(body.action)) {
      throw new ApiError(400, "action must be 'start', 'stop' or 'restart'");
    }
    const inventoryData = await coordinator.inventory({ maxAgeMs: 0 });
    const container = (inventoryData?.docker?.containers || []).find((item) => item?.name === name);
    if (!container) throw new ApiError(404, 'container not found');
    if (container.metadata_source === 'coordinator_ephemeral') {
      throw new ApiError(
        409,
        'broker-owned ephemeral containers must use ephemeral status, renew or finish',
      );
    }
    if (!container.project || !['docker_labels', 'coordinator_sidecar', 'catalog_association'].includes(
      container.metadata_source,
    )) {
      throw new ApiError(400, 'container has no repository association; catalog it before mutation');
    }
    const result = await coordinator.dockerAction(name, body.action, {
      agent: `devops-console:${session.email}`,
      project: container.project,
    });
    sendJson(res, 200, result);
  }

  async function handleDockerLogs(req, res, session) {
    const body = await readJsonBody(req);
    const unknown = Object.keys(body).filter((field) => field !== 'resource_id');
    if (unknown.length) {
      throw new ApiError(400, `unsupported container log field: ${unknown.join(', ')}`);
    }
    const resourceId = requireString(body.resource_id, 'resource_id');
    if (Buffer.byteLength(resourceId, 'utf8') > 255 || /[\u0000-\u001f\u007f]/.test(resourceId)) {
      throw new ApiError(400, 'resource_id is invalid');
    }
    const inventory = await coordinator.inventory({ maxAgeMs: 0 });
    const context = exactDockerRuntimeContext(inventory, resourceId);
    const runtime = await coordinator.runtimeAction({
      schema_version: 1,
      action: 'capture_logs',
      agent: `devops-console:${session.email}`,
      root_repo: context.rootRepo,
      temporary_repo: context.temporaryRepo,
      target: { kind: 'docker', id: resourceId, name: context.container.name },
      purpose: 'development',
      ttl_seconds: null,
      kill_after_run: false,
      options: {},
    });
    const artifact = runtime?.artifact;
    const content = runtime?.artifact_content;
    const text = content?.text;
    if (
      !runtime || runtime.schema_version !== 1 || runtime.ok !== true
      || runtime.action !== 'capture_logs'
      || runtime.target?.kind !== 'docker'
      || String(runtime.target?.id ?? '') !== resourceId
      || !artifact || typeof artifact !== 'object' || Array.isArray(artifact)
      || !content || typeof content !== 'object' || Array.isArray(content)
      || !RUNTIME_ARTIFACT_ID_RE.test(String(artifact.artifact_id ?? ''))
      || content.artifact_id !== artifact.artifact_id
      || typeof text !== 'string'
      || Buffer.byteLength(text, 'utf8') > RUNTIME_ARTIFACT_MAX_BYTES
    ) {
      throw new ApiError(502, 'coordinator returned an invalid exact-container log artifact');
    }
    sendJson(res, 200, {
      text,
      artifact: {
        artifact_id: artifact.artifact_id,
        captured_at: artifact.captured_at ?? null,
        retained: runtime.classification === 'retained',
        truncated: artifact.truncated === true,
      },
    });
  }

  async function handleRuntimeArtifact(res, rawKind, rawId) {
    const kind = safeDecode(rawKind);
    const id = safeDecode(rawId);
    if (!RUNTIME_ARTIFACT_KINDS.has(kind) || !RUNTIME_ARTIFACT_ID_RE.test(id)) {
      throw new ApiError(404, 'runtime log artifact not found');
    }
    let artifact;
    try {
      artifact = await coordinator.runtimeArtifact(kind, id.toLowerCase());
    } catch (error) {
      if (error instanceof CoordError && error.status === 404) {
        throw new ApiError(404, 'runtime log artifact is unavailable');
      }
      throw error;
    }
    if (
      !artifact
      || typeof artifact !== 'object'
      || Array.isArray(artifact)
      || typeof artifact.text !== 'string'
    ) {
      throw new ApiError(502, 'coordinator returned an invalid runtime log artifact');
    }
    return sendRuntimeArtifact(res, kind, id.toLowerCase(), artifact.text);
  }

  function handleError(res, err) {
    let status = 500;
    let message = 'internal error';
    if (err instanceof EdgePublicationProducerError) {
      status = 503;
      message = 'The change was saved, but the public edge could not activate it. Existing public routes remain unchanged.';
      clog?.warn?.('saved route/access state is awaiting stable-edge publication', {
        code: err.code,
        error: err.cause?.message || err.message,
      });
    } else if (
      err instanceof ApiError
      || err instanceof RouteError
      || err instanceof PrefsError
      || err instanceof AccessError
      || err instanceof TelegramServiceError
      || err instanceof UpstreamAuthError
      || err instanceof BugStoreError
    ) {
      status = Number.isInteger(err.status) ? err.status : 500;
      // A 401 from Telegram means the submitted bot token is invalid; it is
      // not a Console-session failure. Returning 401 here would make the UI
      // reload into Google sign-in and hide the actionable token error.
      if (err instanceof TelegramServiceError && err.status === 401) status = 400;
      message = err.message;
    } else if (err instanceof CoordError) {
      // The coordinator answered with a client error (e.g. "matching lease
      // not found"): pass it through as 400. Lifecycle conflicts and
      // incomplete HTTP-200 reports preserve 409 so the reviewed operation is
      // never mistaken for a validation typo. Anything else — unreachable,
      // timeout, 5xx — is a gateway failure and stays 502.
      const maintenance = err.classification === 'maintenance';
      status = maintenance
        ? 503
        : err.status === 409 ? 409 : err.status >= 400 && err.status < 500 ? 400 : 502;
      message = maintenance
        ? 'Live controls are temporarily paused for maintenance.'
        : err.message;
    } else {
      clog?.error?.('console api internal error', { error: err?.stack ?? String(err) });
    }
    if (res.headersSent) {
      res.destroy();
      return;
    }
    const payload = { error: message };
    if (err instanceof EdgePublicationProducerError) {
      payload.code = err.code || 'edge_publication_failed';
      payload.classification = 'edge_publication';
      payload.scope = 'local';
      payload.saved = true;
      payload.retryable = true;
      payload.retryPath = '/api/edge-publication/reconcile';
    }
    if (err instanceof CoordError && err.classification === 'maintenance') {
      payload.code = err.code || 'maintenance_in_progress';
      payload.classification = 'maintenance';
      payload.retryAfterSeconds = err.retryAfterSeconds ?? 30;
    }
    if (err instanceof TelegramServiceError && typeof err.code === 'string') payload.code = err.code;
    if (
      err instanceof TelegramServiceError
      && err.code === 'telegram_rate_limited'
      && Number.isFinite(err.retryAfter)
    ) payload.retryAfter = err.retryAfter;
    sendJson(res, status, payload);
  }

  function safeDecode(segment) {
    try {
      return decodeURIComponent(segment);
    } catch {
      throw new ApiError(404, 'not found');
    }
  }

  async function handle(req, res, session) {
    try {
      if (!session || !session.email) throw new ApiError(401, 'unauthenticated');
      const method = req.method ?? 'GET';
      let pathname;
      let searchParams;
      try {
        const parsed = new URL(req.url ?? '/', 'http://console.internal');
        pathname = parsed.pathname;
        searchParams = parsed.searchParams;
      } catch {
        throw new ApiError(400, 'invalid request path');
      }
      const mutating = method === 'POST' || method === 'PATCH' || method === 'DELETE';
      if (mutating && !guard.checkOrigin(req)) {
        throw new ApiError(403, 'cross-origin request rejected');
      }

      // The open-bug registry is intentionally routed before every
      // Coordinator-backed endpoint. It remains usable while the system it
      // diagnoses is unavailable, warming, or in maintenance.
      if (method === 'GET' && pathname === '/api/bugs') {
        if (!bugStore) throw new ApiError(503, 'Open Coordinator bugs are temporarily unavailable.');
        return sendJson(res, 200, await bugStore.listOpen());
      }
      if (method === 'GET' && pathname === '/api/bugs/export') {
        if (!bugStore) throw new ApiError(503, 'Open Coordinator bugs are temporarily unavailable.');
        return sendJson(res, 200, await bugStore.exportOpen());
      }
      if (method === 'POST' && pathname === '/api/bugs/import') {
        requireAccessAdmin(session);
        if (!bugStore) throw new ApiError(503, 'Open Coordinator bugs are temporarily unavailable.');
        const body = await readJsonBody(req, { limit: BUG_IMPORT_BODY_LIMIT });
        return sendJson(res, 200, await bugStore.importOpen(body));
      }
      const bugMatch = pathname.match(/^\/api\/bugs\/([^/]+)$/);
      if (bugMatch && method === 'DELETE') {
        requireAccessAdmin(session);
        if (!bugStore) throw new ApiError(503, 'Open Coordinator bugs are temporarily unavailable.');
        return sendJson(res, 200, await bugStore.close(safeDecode(bugMatch[1])));
      }

      if (method === 'GET' && pathname === '/api/efficiency') {
        if (!efficiencyStore) {
          return sendJson(res, 200, { schema_version: 1, available: false, repositories: [] });
        }
        const projection = await efficiencyStore.list();
        if (!projection.available) return sendJson(res, 200, projection);
        let names = new Map();
        try {
          const inventory = await coordinator.inventory({ maxAgeMs: 5000 });
          names = new Map((inventory?.repositories || []).map((repository) => [
            repository?.repo_id,
            repository?.display_name || repository?.name || repository?.repo_id,
          ]));
        } catch { /* retained efficiency projection remains independently readable */ }
        return sendJson(res, 200, {
          ...projection,
          repositories: projection.repositories.map((repository) => ({
            ...repository,
            display_name: names.get(repository.repository_id) || 'Repository unavailable',
          })),
        });
      }

      if (method === 'GET' && pathname === '/api/overview') {
        return await handleOverview(res, { fresh: searchParams.get('fresh') === '1' });
      }
      if (method === 'GET' && pathname === '/api/tests/repositories') {
        const catalog = await coordinator.testRepositories();
        const repositories = (catalog?.repositories || [])
          .filter((repository) => repository && TEST_REPO_ID_RE.test(String(repository.repo_id || '')))
          .map((repository) => testRepositoryView(repository));
        return sendJson(res, 200, { schema_version: 1, repositories });
      }
      const testSourcesMatch = pathname.match(/^\/api\/tests\/repositories\/([^/]+)\/sources$/);
      if (method === 'GET' && testSourcesMatch) {
        const repoId = requireTestRepoId(safeDecode(testSourcesMatch[1]));
        await requireKnownTestRepository(repoId);
        const inventory = await coordinator.inventory({ maxAgeMs: 0 });
        const catalog = authoritativeTestSourceCatalog(inventory, repoId);
        return sendJson(res, 200, testSourceCatalogView(repoId, catalog));
      }
      const testSetupMatch = pathname.match(/^\/api\/tests\/repositories\/([^/]+)\/setup$/);
      if (method === 'GET' && testSetupMatch) {
        const repoId = requireTestRepoId(safeDecode(testSetupMatch[1]));
        await requireKnownTestRepository(repoId);
        const setup = await coordinator.testRepositorySetup({ repoId });
        if ((setup?.repository_id ?? setup?.repo_id) !== repoId) {
          throw new ApiError(502, 'coordinator returned contradictory test setup identity');
        }
        return sendJson(res, 200, testSetupView(setup, repoId));
      }
      if (method === 'POST' && pathname === '/api/tests/plan') {
        const body = await readJsonBody(req);
        requireFields(
          body,
          ['repo_id', 'intent', 'operation_id', 'source'],
          ['requested_targets'],
          'test plan',
        );
        const repoId = requireTestRepoId(body.repo_id);
        const intent = requireString(body.intent, 'intent');
        const operationId = requireString(body.operation_id, 'operation_id');
        const sourceSelector = requireTestSourceSelector(body.source, repoId);
        if (!UUID_RE.test(operationId) || operationId.toLowerCase() !== operationId) {
          throw new ApiError(400, 'operation_id must be a canonical UUID');
        }
        if (!TEST_INTENTS.has(intent)) throw new ApiError(400, 'intent is invalid');
        const requestedTargets = requireTestTargetNames(body.requested_targets);
        if (requestedTargets.length && intent !== 'manual') {
          throw new ApiError(400, 'requested_targets are supported only for manual intent');
        }
        await requireKnownTestRepository(repoId);
        const resolvedSource = await resolveTestSource(repoId, sourceSelector);
        const result = await coordinator.testPlan({
          repoId,
          intent,
          requestedTargets,
          operationId,
          source: {
            schemaVersion: 1,
            kind: resolvedSource.selector.kind,
            repositoryId: resolvedSource.selector.repository_id,
            repositoryGeneration: resolvedSource.selector.repository_generation,
            temporaryRoot: resolvedSource.temporaryRoot,
          },
        });
        const returnedRepoId = result?.repository_id ?? result?.repo_id;
        if (
          returnedRepoId !== repoId
          || typeof result?.plan_id !== 'string'
          || !result.plan_id
          || result?.operation_id !== operationId
        ) {
          throw new ApiError(502, 'coordinator returned an invalid repository test plan');
        }
        const returnedSource = result?.plan?.source;
        if (resolvedSource.selector.kind === 'temporary' && (
          !returnedSource || typeof returnedSource !== 'object'
          || returnedSource.temporary_root !== resolvedSource.temporaryRoot
        )) {
          throw new ApiError(502, 'coordinator returned a contradictory temporary test source');
        }
        if (returnedSource && typeof returnedSource === 'object' && (
          (returnedSource.repository_id !== undefined && returnedSource.repository_id !== repoId)
          || (resolvedSource.selector.kind === 'original' && returnedSource.temporary_root != null)
        )) {
          throw new ApiError(502, 'coordinator returned a contradictory repository test source');
        }
        return sendJson(res, 200, {
          ...result,
          source_selector: resolvedSource.selector,
          source_label: resolvedSource.label,
        });
      }
      if (method === 'GET' && pathname === '/api/tests/runs') {
        const repoId = requireTestRepoId(searchParams.get('repo_id'));
        if ([...searchParams.keys()].some((name) => name !== 'repo_id')) {
          throw new ApiError(400, 'current test runs accept only repo_id');
        }
        await requireKnownTestRepository(repoId);
        const result = await coordinator.testRuns({ repoId });
        if ((result?.repository_id ?? result?.repo_id) !== repoId || !Array.isArray(result?.runs)) {
          throw new ApiError(502, 'coordinator returned contradictory current test runs');
        }
        const activeStates = new Set(['queued', 'running', 'cancelling']);
        const runs = result.runs.map((run) => {
          return testRunView(run, {
            can_cancel: activeStates.has(run.state),
          });
        });
        return sendJson(res, 200, { schema_version: 1, repo_id: repoId, runs });
      }
      if (method === 'POST' && pathname === '/api/tests/runs') {
        const body = await readJsonBody(req);
        requireExactFields(body, ['repo_id', 'plan_id', 'operation_id'], 'test submission');
        const repoId = requireTestRepoId(body.repo_id);
        const planId = requireString(body.plan_id, 'plan_id');
        const operationId = requireString(body.operation_id, 'operation_id');
        if (planId.length > 255 || /[\u0000-\u001f\u007f]/.test(planId)) {
          throw new ApiError(400, 'plan_id is invalid');
        }
        if (!UUID_RE.test(operationId)) throw new ApiError(400, 'operation_id must be a UUID');
        await requireKnownTestRepository(repoId);
        const result = await coordinator.submitTestRun({
          repoId, planId, operationId, actor: googleTestActor(session),
        });
        const returnedRepoId = result?.repository_id ?? result?.repo_id;
        if (returnedRepoId !== repoId || typeof result?.run_id !== 'string' || !result.run_id) {
          throw new ApiError(502, 'coordinator returned an invalid repository test submission');
        }
        return sendJson(res, 202, result);
      }
      const testRunMatch = pathname.match(
        /^\/api\/tests\/repositories\/([^/]+)\/runs\/([^/]+)(?:\/(summary|failures|artifacts|cancel))?$/,
      );
      if (testRunMatch) {
        const repoId = requireTestRepoId(safeDecode(testRunMatch[1]));
        const runId = requireTestEntityId(safeDecode(testRunMatch[2]));
        const action = testRunMatch[3] || 'detail';
        await requireKnownTestRepository(repoId);
        const status = await coordinator.testRunStatus({ repoId, runId });
        if ((status?.repository_id ?? status?.repo_id) !== repoId) {
          throw new ApiError(404, 'test run does not exist in this repository');
        }
        if (method === 'GET' && action === 'detail') {
          const summary = await coordinator.testRunSummary({ repoId, runId });
          if ((summary?.repository_id ?? summary?.repo_id) !== repoId) {
            throw new ApiError(502, 'coordinator returned contradictory test run detail');
          }
          return sendJson(res, 200, {
            ...testRunView(status),
            summary: testRunSummaryView(summary),
          });
        }
        if (method === 'GET' && action === 'summary') {
          const summary = await coordinator.testRunSummary({ repoId, runId });
          if ((summary?.repository_id ?? summary?.repo_id) !== repoId) {
            throw new ApiError(502, 'coordinator returned contradictory test run summary');
          }
          return sendJson(res, 200, testRunSummaryView(summary));
        }
        if (method === 'GET' && ['failures', 'artifacts'].includes(action)) {
          const rawAfter = searchParams.get('after');
          const limit = boundedInteger(searchParams.get('limit'), 50, 1, 50, 'limit');
          const after = rawAfter;
          if (after !== null) requireTestEntityId(after, 'after');
          const operation = {
            failures: coordinator.testRunFailures,
            artifacts: coordinator.testRunArtifacts,
          }[action];
          const evidence = await operation({ repoId, runId, after, limit });
          if ((evidence?.repository_id ?? evidence?.repo_id) !== repoId) {
            throw new ApiError(502, 'coordinator returned contradictory test evidence');
          }
          return sendJson(res, 200, evidence);
        }
        if (method === 'POST' && action === 'cancel') {
          const body = await readJsonBody(req);
          requireExactFields(body, ['reason', 'operation_id'], 'test cancellation');
          const reason = requireString(body.reason, 'reason');
          const operationId = requireString(body.operation_id, 'operation_id');
          if (reason.length > 512 || /[\u0000-\u001f\u007f]/.test(reason)) throw new ApiError(400, 'reason is invalid');
          if (!UUID_RE.test(operationId)) throw new ApiError(400, 'operation_id must be a UUID');
          const result = await coordinator.cancelTestRun({
            repoId, runId, reason, operationId, actor: googleTestActor(session),
          });
          if ((result?.repository_id ?? result?.repo_id) !== repoId) {
            throw new ApiError(502, 'coordinator returned contradictory cancellation identity');
          }
          return sendJson(res, 200, result);
        }
      }
      if (method === 'GET' && pathname === '/api/metrics/history') {
        return handleMetricsHistory(res, searchParams);
      }
      const runtimeArtifactMatch = pathname.match(
        /^\/api\/runtime\/artifacts\/([^/]+)\/([^/]+)$/,
      );
      if (runtimeArtifactMatch && method === 'GET') {
        return await handleRuntimeArtifact(
          res,
          runtimeArtifactMatch[1],
          runtimeArtifactMatch[2],
        );
      }
      if (method === 'GET' && pathname === '/api/session') {
        return sendJson(res, 200, {
          email: session.email,
          name: session.name ?? null,
          pic: session.pic ?? null,
          exp: session.exp ?? null,
          accessAdmin: accessStore.isAdmin(session.email),
          lifecycleAvailable: config.lifecycleEnabled === true,
          efficiencyAvailable: efficiencyStore !== null,
        });
      }
      if (method === 'GET' && pathname === '/api/access') {
        // Await the async handler inside this try/catch. Returning its promise
        // directly would let an authorization rejection escape to the outer
        // HTML router, which converted the intended JSON 403 into a 500 page.
        return await handleAccessGet(res, session);
      }
      if (method === 'GET' && pathname === '/api/access/requests') {
        return handleAccessRequestsGet(res, session, searchParams);
      }
      const accessRequestDecisionMatch = pathname.match(/^\/api\/access\/requests\/([^/]+)\/decision$/);
      if (accessRequestDecisionMatch && method === 'POST') {
        return await handleAccessRequestDecision(
          req,
          res,
          session,
          safeDecode(accessRequestDecisionMatch[1]),
        );
      }
      if (method === 'POST' && pathname === '/api/access/users') {
        return await handleAccessAdd(req, res, session);
      }
      const accessUserMatch = pathname.match(/^\/api\/access\/users\/([^/]+)$/);
      if (accessUserMatch && method === 'PATCH') {
        return await handleAccessGrant(req, res, session, safeDecode(accessUserMatch[1]));
      }
      if (accessUserMatch && method === 'DELETE') {
        return await handleAccessRemove(res, session, safeDecode(accessUserMatch[1]));
      }
      if (method === 'GET' && pathname === '/api/telegram') {
        return await handleTelegramGet(res, session);
      }
      if (method === 'POST' && pathname === '/api/telegram/bots') {
        return await handleTelegramRegister(req, res, session);
      }
      const telegramBotMatch = pathname.match(/^\/api\/telegram\/bots\/([^/]+)$/);
      if (telegramBotMatch && method === 'DELETE') {
        return await handleTelegramRemove(res, session, safeDecode(telegramBotMatch[1]));
      }
      const telegramProjectsMatch = pathname.match(/^\/api\/telegram\/bots\/([^/]+)\/projects$/);
      if (telegramProjectsMatch && method === 'PATCH') {
        return await handleTelegramProjects(req, res, session, safeDecode(telegramProjectsMatch[1]));
      }
      const telegramDecisionMatch = pathname.match(
        /^\/api\/telegram\/bots\/([^/]+)\/authorizations\/([^/]+)\/decision$/,
      );
      if (telegramDecisionMatch && method === 'POST') {
        return await handleTelegramAuthorizationDecision(
          req,
          res,
          session,
          safeDecode(telegramDecisionMatch[1]),
          safeDecode(telegramDecisionMatch[2]),
        );
      }
      if (method === 'POST' && pathname === '/api/routes') {
        return await handleRouteCreate(req, res);
      }
      if (method === 'POST' && pathname === '/api/edge-publication/reconcile') {
        return await handleEdgePublicationReconcile(res);
      }
      const routeUpstreamAuthMatch = pathname.match(/^\/api\/routes\/([^/]+)\/upstream-auth$/);
      if (routeUpstreamAuthMatch && method === 'PATCH') {
        return await handleRouteUpstreamAuthSet(
          req,
          res,
          session,
          safeDecode(routeUpstreamAuthMatch[1]),
        );
      }
      if (routeUpstreamAuthMatch && method === 'DELETE') {
        return await handleRouteUpstreamAuthRemove(
          res,
          session,
          safeDecode(routeUpstreamAuthMatch[1]),
        );
      }
      const routeMatch = pathname.match(/^\/api\/routes\/([^/]+)$/);
      if (routeMatch && method === 'PATCH') {
        return await handleRoutePatch(req, res, safeDecode(routeMatch[1]));
      }
      if (routeMatch && method === 'DELETE') {
        return await handleRouteDelete(res, safeDecode(routeMatch[1]));
      }
      if (method === 'POST' && pathname === '/api/servers/action') {
        return await handleServerAction(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/workers/action') {
        return await handleWorkerAction(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/servers/subdomain') {
        return await handleServerSubdomain(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/servers/logs') {
        return await handleServerLogs(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/ports/lease') {
        return await handlePortLease(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/ports/release') {
        return await handlePortRelease(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/ports/unassign') {
        return await handlePortUnassign(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/docker/action') {
        return await handleDockerAction(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/docker/subdomain') {
        return await handleDockerSubdomain(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/docker/logs') {
        return await handleDockerLogs(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/projects/action') {
        return await handleProjectAction(req, res, session);
      }
      if (method === 'GET' && pathname === '/api/lifecycle/list') {
        return await handleLifecycleList(res, session);
      }
      if (method === 'POST' && pathname === '/api/lifecycle/plan') {
        return await handleLifecyclePlan(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/lifecycle/apply') {
        return await handleLifecycleApply(req, res, session);
      }
      if (method === 'POST' && pathname === '/api/lifecycle/restore') {
        return await handleLifecycleRestore(req, res, session);
      }
      if (method === 'GET' && pathname === '/api/prefs') {
        return handlePrefsGet(res);
      }
      if (method === 'PATCH' && pathname === '/api/prefs') {
        return await handlePrefsPatch(req, res);
      }
      throw new ApiError(404, 'not found');
    } catch (err) {
      handleError(res, err);
    }
  }

  return { handle };
}
