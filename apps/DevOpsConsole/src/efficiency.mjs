import fs from 'node:fs';
import path from 'node:path';

const MAX_FILE_BYTES = 64 * 1024;
const MAX_ACCOUNTS = 64;
const MAX_REPOSITORIES = 512;
const ACCOUNT_RE = /^uid-[0-9]{1,10}$/;
const REPOSITORY_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const OPAQUE_RE = /^id_[0-9a-f]{32}$/;
const TOKEN_KEYS = ['input', 'cached_input', 'output', 'reasoning_output', 'tool', 'other'];
const PHASES = ['planning', 'implementation', 'testing', 'deployment', 'reporting', 'unattributed'];
const TOOL_CATEGORIES = ['shell', 'patch', 'mcp', 'web', 'agent', 'local', 'other'];

function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000_000;
}

function decimal(value) {
  return value === null || (typeof value === 'string' && /^(0|[1-9][0-9]{0,29})$/.test(value));
}

function knownCounter(value) {
  if (!exact(value, ['known_sum', 'known_task_count', 'task_count', 'coverage'])) return false;
  return decimal(value.known_sum)
    && count(value.known_task_count)
    && count(value.task_count)
    && value.known_task_count <= value.task_count
    && ['complete', 'partial', 'unknown'].includes(value.coverage)
    && ((value.known_sum === null) === (value.known_task_count === 0));
}

function countMap(value) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length <= 32
    && Object.entries(value).every(([key, item]) => /^[a-z][a-z0-9-]{0,31}$/.test(key) && count(item));
}

function validSummary(summary) {
  const keys = [
    'project_id', 'task_count', 'complete_task_count', 'outcomes', 'causes',
    'tokens', 'tokens_by_phase', 'request_to_delivery_ns',
    'execution_to_delivery_ns', 'automation_opportunities',
  ];
  if (!exact(summary, keys) || !OPAQUE_RE.test(summary.project_id)
    || !count(summary.task_count) || !count(summary.complete_task_count)
    || summary.complete_task_count > summary.task_count
    || !countMap(summary.outcomes) || !countMap(summary.causes)
    || !exact(summary.tokens, TOKEN_KEYS)
    || !TOKEN_KEYS.every((key) => knownCounter(summary.tokens[key]))
    || !exact(summary.tokens_by_phase, PHASES)
    || !knownCounter(summary.request_to_delivery_ns)
    || !knownCounter(summary.execution_to_delivery_ns)
    || !Array.isArray(summary.automation_opportunities)
    || summary.automation_opportunities.length > 32) return false;
  for (const phase of PHASES) {
    const value = summary.tokens_by_phase[phase];
    if (!exact(value, [...TOKEN_KEYS, 'usage_event_count'])
      || !TOKEN_KEYS.every((key) => knownCounter(value[key]))
      || !count(value.usage_event_count)) return false;
  }
  return summary.automation_opportunities.every((value) => (
    exact(value, [
      'kind', 'task_type', 'scope_size', 'current_method', 'occurrence_count',
      'input_tokens', 'tool_category_counts', 'basis', 'recommendation',
    ])
    && value.kind === 'deterministic-workflow-candidate'
    && ['task_type', 'scope_size', 'current_method'].every(
      (key) => typeof value[key] === 'string' && /^[a-z][a-z-]{0,31}$/.test(value[key]))
    && count(value.occurrence_count)
    && knownCounter(value.input_tokens)
    && exact(value.tool_category_counts, TOOL_CATEGORIES)
    && TOOL_CATEGORIES.every((key) => count(value.tool_category_counts[key]))
    && value.basis === 'at least three comparable non-automated terminal declarations'
    && value.recommendation === 'review the repeated sequence for a script, harness, verifier, or reusable tool boundary'
  ));
}

function validEnvelope(value, accountId, repositoryId) {
  return exact(value, ['account_id', 'recorded_at_utc', 'repository_id', 'schema_version', 'summary'])
    && value.schema_version === 1
    && value.account_id === accountId
    && value.repository_id === repositoryId
    && typeof value.recorded_at_utc === 'string'
    && Number.isFinite(Date.parse(value.recorded_at_utc))
    && validSummary(value.summary);
}

function listDirectories(root, maximum) {
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && !entry.isSymbolicLink())
    .slice(0, maximum);
}

function mergeCounter(items) {
  const known = items.filter((item) => item.known_sum !== null);
  const knownTaskCount = items.reduce((sum, item) => sum + item.known_task_count, 0);
  const taskCount = items.reduce((sum, item) => sum + item.task_count, 0);
  return {
    known_sum: known.length
      ? String(known.reduce((sum, item) => sum + BigInt(item.known_sum), 0n))
      : null,
    known_task_count: knownTaskCount,
    task_count: taskCount,
    coverage: taskCount > 0 && knownTaskCount === taskCount
      ? 'complete' : knownTaskCount > 0 ? 'partial' : 'unknown',
  };
}

function mergeRepository(repositoryId, accounts) {
  const summaries = accounts.map((account) => account.summary);
  const tokens = Object.fromEntries(TOKEN_KEYS.map((key) => [
    key, mergeCounter(summaries.map((summary) => summary.tokens[key])),
  ]));
  const tokensByPhase = {};
  for (const phase of PHASES) {
    tokensByPhase[phase] = Object.fromEntries(TOKEN_KEYS.map((key) => [
      key, mergeCounter(summaries.map((summary) => summary.tokens_by_phase[phase][key])),
    ]));
    tokensByPhase[phase].usage_event_count = summaries.reduce(
      (sum, summary) => sum + summary.tokens_by_phase[phase].usage_event_count, 0);
  }
  const mergedCounts = (key) => {
    const result = {};
    for (const summary of summaries) {
      for (const [name, value] of Object.entries(summary[key])) result[name] = (result[name] || 0) + value;
    }
    return Object.fromEntries(Object.entries(result).sort());
  };
  return {
    repository_id: repositoryId,
    task_count: summaries.reduce((sum, value) => sum + value.task_count, 0),
    complete_task_count: summaries.reduce((sum, value) => sum + value.complete_task_count, 0),
    outcomes: mergedCounts('outcomes'),
    causes: mergedCounts('causes'),
    tokens,
    tokens_by_phase: tokensByPhase,
    request_to_delivery_ns: mergeCounter(summaries.map((value) => value.request_to_delivery_ns)),
    execution_to_delivery_ns: mergeCounter(summaries.map((value) => value.execution_to_delivery_ns)),
    automation_opportunities: accounts.flatMap((account) => (
      account.summary.automation_opportunities.map((value) => ({ ...value, account_id: account.account_id }))
    )).slice(0, 32),
    accounts: accounts.map((value) => ({
      account_id: value.account_id,
      recorded_at_utc: value.recorded_at_utc,
      task_count: value.summary.task_count,
      complete_task_count: value.summary.complete_task_count,
      tokens: value.summary.tokens,
    })),
  };
}

export function createEfficiencyStore({ root, log = null }) {
  const directory = path.resolve(root);
  return {
    async list() {
      let metadata;
      try {
        metadata = fs.lstatSync(directory);
      } catch (error) {
        if (error?.code === 'ENOENT') return { schema_version: 1, available: false, repositories: [] };
        throw error;
      }
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        return { schema_version: 1, available: false, repositories: [] };
      }
      const grouped = new Map();
      let invalidCount = 0;
      for (const accountEntry of listDirectories(directory, MAX_ACCOUNTS)) {
        if (!ACCOUNT_RE.test(accountEntry.name)) { invalidCount += 1; continue; }
        const repositoryRoot = path.join(directory, accountEntry.name, 'repositories');
        let files;
        try {
          files = fs.readdirSync(repositoryRoot, { withFileTypes: true }).slice(0, MAX_REPOSITORIES);
        } catch { continue; }
        for (const entry of files) {
          const repositoryId = entry.name.endsWith('.json') ? entry.name.slice(0, -5) : '';
          if (!entry.isFile() || entry.isSymbolicLink() || !REPOSITORY_RE.test(repositoryId)) {
            invalidCount += 1; continue;
          }
          const filename = path.join(repositoryRoot, entry.name);
          try {
            const info = fs.lstatSync(filename);
            if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_FILE_BYTES) throw new Error('unsafe file');
            const value = JSON.parse(fs.readFileSync(filename, 'utf8'));
            if (!validEnvelope(value, accountEntry.name, repositoryId.toLowerCase())) throw new Error('invalid snapshot');
            const accounts = grouped.get(repositoryId.toLowerCase()) || [];
            accounts.push(value);
            grouped.set(repositoryId.toLowerCase(), accounts);
          } catch (error) {
            invalidCount += 1;
            log?.warn?.('ignored invalid efficiency projection', { error: String(error?.message || error) });
          }
        }
      }
      return {
        schema_version: 1,
        available: true,
        sampled_at_utc: new Date().toISOString(),
        invalid_projection_count: invalidCount,
        repositories: [...grouped.entries()].sort(([a], [b]) => a.localeCompare(b))
          .map(([repositoryId, accounts]) => mergeRepository(repositoryId, accounts)),
      };
    },
  };
}
