// Out-of-band open Coordinator bug registry.
//
// The normal Coordinator path is deliberately not involved: this store must
// remain readable and closable while authority, broker, API, or testd are the
// subject of the report. One bounded JSON file means open; closing physically
// removes every active file with the same fingerprint. There is no closed
// history or tombstone to synchronize between Console instances.

import { constants as fsConstants, promises as fsp } from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';

const SCHEMA_VERSION = 1;
const MAX_FILES = 2_048;
const MAX_FILE_BYTES = 16 * 1024;
const MAX_IMPORT_BUGS = 2_048;
const MAX_TEXT = 4_096;
const MAX_SUMMARY = 512;
const MAX_STEPS = 8;
const MAX_ARGV = 64;
const BUG_ID_RE = /^bug-[0-9a-f]{32}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const TRANSFER_KIND = 'devcoordinator-open-bugs';
const POTENTIAL_ASSIGNMENT_RE = /(?<![A-Za-z0-9_.-])(["']?)([A-Za-z_][A-Za-z0-9_.-]{0,127})\1(\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;]+)/gi;
const PRIVATE_PATH_RE = /(^|[\s"'=:])\/(?:home|root|var|tmp|opt|run|srv)(?:\/[^\s"'<>]*)?/g;

export class BugStoreError extends Error {
  constructor(status, message, options = undefined) {
    super(message, options);
    this.name = 'BugStoreError';
    this.status = status;
  }
}

function plainObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function boundedText(value, field, max = MAX_TEXT) {
  if (typeof value !== 'string') throw new Error(`${field} must be a string`);
  const text = value.trim();
  if (!text || text.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) {
    throw new Error(`${field} is invalid`);
  }
  return text;
}

function optionalText(value, field, max = MAX_TEXT) {
  if (value === undefined || value === null || value === '') return null;
  return boundedText(value, field, max);
}

function timestamp(value, field) {
  const text = boundedText(value, field, 64);
  if (!Number.isFinite(Date.parse(text))) throw new Error(`${field} must be a timestamp`);
  return new Date(text).toISOString();
}

function isSecretName(value) {
  const normalized = String(value).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
  const parts = normalized.split(/[._-]+/).filter(Boolean);
  if (!parts.length) return false;
  if (['token', 'password', 'passwd', 'authorization', 'credential', 'credentials', 'cookie']
    .includes(parts.at(-1))) return true;
  if (parts.includes('secret')) return true;
  if (['password', 'passwd', 'credential', 'credentials', 'cookie'].includes(parts[0])) return true;
  return parts.slice(0, -1).some((part, index) => (
    ['api', 'private', 'access'].includes(part) && parts[index + 1] === 'key'
  ));
}

function redactServerPaths(value, repositoryPath = null) {
  let text = String(value);
  if (repositoryPath && path.isAbsolute(repositoryPath)) {
    text = text.split(repositoryPath).join('$REPOSITORY');
  }
  return text
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/gi, '$1[redacted]@')
    .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [redacted]')
    .replace(
      POTENTIAL_ASSIGNMENT_RE,
      (match, quote, key, separator) => (
        isSecretName(key) ? `${quote}${key}${quote}${separator}[redacted]` : match
      ),
    )
    .replace(/\b\d{5,}:[A-Za-z0-9_-]{20,}\b/g, '[redacted bot token]')
    .replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,})\b/g, '[redacted credential]')
    .replace(PRIVATE_PATH_RE, (_match, prefix) => `${prefix}[server path]`);
}

function publicText(value, repositoryPath = null) {
  return redactServerPaths(value, repositoryPath);
}

function publicArgv(value, field, repositoryPath) {
  if (!Array.isArray(value) || value.length > MAX_ARGV) {
    throw new Error(`${field} must be a bounded array`);
  }
  const result = [];
  let redactNext = false;
  for (const [index, raw] of value.entries()) {
    let argument = boundedText(raw, `${field}[${index}]`, 1_024);
    if (redactNext) {
      argument = '[redacted]';
      redactNext = false;
    } else {
      const [option, ...assigned] = argument.split('=');
      const optionName = option.replace(/^-+/, '');
      if (isSecretName(optionName)) {
        if (assigned.length) argument = `${option}=[redacted]`;
        else redactNext = true;
      }
    }
    result.push(publicText(argument, repositoryPath));
  }
  return result;
}

function normalizeReporter(value, repositoryPath) {
  if (typeof value === 'string') return publicText(boundedText(value, 'reporter', 256), repositoryPath);
  if (!plainObject(value)) throw new Error('reporter must be a string or object');
  for (const field of ['display_name', 'name', 'agent', 'actor']) {
    if (typeof value[field] === 'string' && value[field].trim()) {
      return publicText(boundedText(value[field], `reporter.${field}`, 256), repositoryPath);
    }
  }
  throw new Error('reporter object has no display name');
}

function normalizeLocalFallback(value, repositoryPath) {
  if (value === undefined || value === null) return null;
  if (!plainObject(value)) throw new Error('local_fallback is invalid');
  const status = boundedText(value.status, 'local_fallback.status', 32);
  if (!['not_run', 'passed', 'failed', 'incomplete'].includes(status)) {
    throw new Error('local_fallback.status is invalid');
  }
  if (value.advisory !== true || value.coordinator_evidence !== false) {
    throw new Error('local_fallback evidence classification is invalid');
  }
  const commandArgv = publicArgv(
    value.command_argv ?? [],
    'local_fallback.command_argv',
    repositoryPath,
  );
  if (status === 'not_run' && commandArgv.length) {
    throw new Error('not_run local fallback cannot contain command_argv');
  }
  const summary = optionalText(value.summary, 'local_fallback.summary', 512);
  return {
    status,
    command_argv: commandArgv,
    summary: summary ? publicText(summary, repositoryPath) : null,
    advisory: true,
    coordinator_evidence: false,
  };
}

function normalizeCorrelations(value, repositoryPath) {
  if (value === undefined || value === null) return {};
  if (!plainObject(value)) throw new Error('correlations must be an object');
  const out = {};
  for (const field of ['call_id', 'operation_id', 'run_id', 'attempt_id']) {
    const text = optionalText(value[field], `correlations.${field}`, 256);
    if (text) out[field] = publicText(text, repositoryPath);
  }
  return out;
}

function normalizeOrigin(value) {
  if (value === undefined || value === null) return null;
  if (!plainObject(value)) throw new Error('origin must be an object');
  const kind = boundedText(value.kind, 'origin.kind', 16);
  if (!['local', 'remote'].includes(kind)) throw new Error('origin.kind is invalid');
  const serverId = boundedText(value.server_id, 'origin.server_id', 256);
  const bugId = boundedText(value.bug_id, 'origin.bug_id', 160);
  const fingerprint = boundedText(value.fingerprint, 'origin.fingerprint', 256);
  if (!BUG_ID_RE.test(bugId)) throw new Error('origin.bug_id is invalid');
  if (!SHA256_RE.test(fingerprint)) throw new Error('origin.fingerprint is invalid');
  return { kind, server_id: serverId, bug_id: bugId, fingerprint };
}

function normalizeRecord(value) {
  if (!plainObject(value)) throw new Error('report must be an object');
  if (value.schema_version !== SCHEMA_VERSION) throw new Error('schema_version is unsupported');
  const bugId = boundedText(value.bug_id, 'bug_id', 160);
  if (!BUG_ID_RE.test(bugId)) throw new Error('bug_id is invalid');
  const fingerprint = boundedText(value.fingerprint, 'fingerprint', 256);
  if (!SHA256_RE.test(fingerprint)) throw new Error('fingerprint is invalid');
  const repositoryPath = typeof value.repository === 'string' && path.isAbsolute(value.repository)
    ? value.repository.trim()
    : null;
  const steps = value.reproduction_steps;
  if (!Array.isArray(steps) || steps.length < 1 || steps.length > MAX_STEPS) {
    throw new Error('reproduction_steps must be a bounded non-empty array');
  }
  const commandArgv = publicArgv(value.command_argv ?? [], 'command_argv', repositoryPath);
  const occurrenceCount = value.occurrence_count;
  if (!Number.isSafeInteger(occurrenceCount) || occurrenceCount < 1) {
    throw new Error('occurrence_count must be a positive integer');
  }
  if (!Number.isSafeInteger(value.peer_uid) || value.peer_uid < 0) {
    throw new Error('peer_uid must be a non-negative integer');
  }
  const repository = optionalText(value.repository, 'repository', 1_024);
  const repositoryName = repository
    ? repository.replace(/[\\/]+$/, '').split(/[\\/]/).at(-1) || 'Repository'
    : null;
  return {
    schema_version: SCHEMA_VERSION,
    bug_id: bugId,
    fingerprint,
    component: publicText(boundedText(value.component, 'component', 256), repositoryPath),
    summary: publicText(boundedText(value.summary, 'summary', MAX_SUMMARY), repositoryPath),
    expected: publicText(boundedText(value.expected, 'expected'), repositoryPath),
    actual: publicText(boundedText(value.actual, 'actual'), repositoryPath),
    reproduction_steps: steps.map((step, index) => publicText(
      boundedText(step, `reproduction_steps[${index}]`), repositoryPath,
    )),
    reporter: normalizeReporter(value.reporter, repositoryPath),
    first_seen_at: timestamp(value.first_seen_at, 'first_seen_at'),
    last_seen_at: timestamp(value.last_seen_at, 'last_seen_at'),
    occurrence_count: occurrenceCount,
    surface: optionalText(value.surface, 'surface', 256)
      ? publicText(optionalText(value.surface, 'surface', 256), repositoryPath) : null,
    operation: optionalText(value.operation, 'operation', 256)
      ? publicText(optionalText(value.operation, 'operation', 256), repositoryPath) : null,
    classification: optionalText(value.classification, 'classification', 128)
      ? publicText(optionalText(value.classification, 'classification', 128), repositoryPath) : null,
    code: optionalText(value.code, 'code', 128)
      ? publicText(optionalText(value.code, 'code', 128), repositoryPath) : null,
    stage: optionalText(value.stage, 'stage', 128)
      ? publicText(optionalText(value.stage, 'stage', 128), repositoryPath) : null,
    command_argv: commandArgv,
    repository: repositoryName,
    peer_uid: value.peer_uid,
    release_digest: value.release_digest === undefined || value.release_digest === null
      ? null
      : (() => {
          const digest = boundedText(value.release_digest, 'release_digest', 64);
          if (!SHA256_RE.test(digest)) throw new Error('release_digest is invalid');
          return digest;
        })(),
    instance_id: optionalText(value.instance_id, 'instance_id', 256)
      ? publicText(optionalText(value.instance_id, 'instance_id', 256), repositoryPath) : null,
    correlations: normalizeCorrelations(value.correlations, repositoryPath),
    local_fallback: normalizeLocalFallback(value.local_fallback, repositoryPath),
    origin: normalizeOrigin(value.origin),
  };
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (!plainObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function storageRecord(record) {
  const stored = {
    schema_version: SCHEMA_VERSION,
    bug_id: record.bug_id,
    fingerprint: record.fingerprint,
    component: record.component,
    summary: record.summary,
    expected: record.expected,
    actual: record.actual,
    reproduction_steps: record.reproduction_steps,
    reporter: record.reporter,
    peer_uid: record.peer_uid,
    first_seen_at: record.first_seen_at,
    last_seen_at: record.last_seen_at,
    occurrence_count: record.occurrence_count,
  };
  for (const field of [
    'surface', 'operation', 'classification', 'code', 'stage', 'repository',
    'release_digest', 'instance_id', 'origin',
  ]) {
    if (record[field] !== null && record[field] !== undefined) stored[field] = record[field];
  }
  if (record.command_argv?.length) stored.command_argv = record.command_argv;
  if (Object.keys(record.correlations || {}).length) stored.correlations = record.correlations;
  if (record.local_fallback) stored.local_fallback = record.local_fallback;
  return stored;
}

function importedFingerprint(record) {
  const fields = {};
  for (const field of [
    'component', 'surface', 'operation', 'classification', 'code', 'stage',
    'summary', 'expected', 'actual', 'reproduction_steps', 'command_argv',
    'repository', 'origin',
  ]) {
    const value = record[field];
    if (value !== null && value !== undefined && (!Array.isArray(value) || value.length)) {
      fields[field] = value;
    }
  }
  return crypto.createHash('sha256').update(canonicalJson(fields)).digest('hex');
}

function mergeGroup(records) {
  const chronological = [...records].sort((a, b) => (
    Date.parse(a.record.last_seen_at) - Date.parse(b.record.last_seen_at)
    || a.record.bug_id.localeCompare(b.record.bug_id)
  ));
  const latest = chronological.at(-1).record;
  const firstSeen = Math.min(...records.map(({ record }) => Date.parse(record.first_seen_at)));
  const lastSeen = Math.max(...records.map(({ record }) => Date.parse(record.last_seen_at)));
  const occurrenceCount = records.reduce((sum, { record }) => sum + record.occurrence_count, 0);
  const merged = {
    ...latest,
    first_seen_at: new Date(firstSeen).toISOString(),
    last_seen_at: new Date(lastSeen).toISOString(),
    occurrence_count: occurrenceCount,
  };
  return { record: merged, sources: records.map(({ source }) => source) };
}

function publicCollection(groups, originServerId) {
  const bugs = groups.map((group) => {
    const record = group.record;
    return {
      ...record,
      origin: record.origin ?? {
        kind: 'local',
        server_id: originServerId,
        bug_id: record.bug_id,
        fingerprint: record.fingerprint,
      },
    };
  }).sort((a, b) => (
    Date.parse(b.last_seen_at) - Date.parse(a.last_seen_at)
    || a.bug_id.localeCompare(b.bug_id)
  ));
  const revision = crypto.createHash('sha256').update(JSON.stringify(bugs)).digest('hex');
  return {
    schema_version: SCHEMA_VERSION,
    revision,
    generated_at: new Date().toISOString(),
    bugs,
  };
}

export function createBugStore({ directory, log = null, originServerId = 'this-server' }) {
  if (!path.isAbsolute(String(directory || ''))) {
    throw new TypeError('bug directory must be an absolute path');
  }
  const localOrigin = boundedText(originServerId, 'originServerId', 256);
  const blog = typeof log?.child === 'function' ? log.child({ mod: 'bugs' }) : log;

  async function readFileSafely(file, source) {
    const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
    let handle;
    try {
      handle = await fsp.open(file, flags);
      const info = await handle.stat();
      if (!info.isFile() || info.size < 2 || info.size > MAX_FILE_BYTES) {
        throw new Error('report is not one bounded regular file');
      }
      const raw = await handle.readFile('utf8');
      const record = normalizeRecord(JSON.parse(raw));
      if (`${record.bug_id}.json` !== source) throw new Error('bug_id does not match the file name');
      return { record, source };
    } finally {
      await handle?.close();
    }
  }

  async function scan() {
    let entries;
    try {
      entries = await fsp.readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (error?.code === 'ENOENT') return [];
      throw new BugStoreError(503, 'Open Coordinator bugs are temporarily unavailable.', { cause: error });
    }
    const names = entries
      .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
      .map((entry) => entry.name)
      .sort();
    if (names.length > MAX_FILES) {
      throw new BugStoreError(503, 'Open Coordinator bugs are temporarily unavailable.');
    }
    const records = [];
    for (const [index, source] of names.entries()) {
      try {
        records.push(await readFileSafely(path.join(directory, source), source));
      } catch (error) {
        if (error?.code === 'ENOENT') continue;
        blog?.warn?.('isolated malformed open Coordinator bug report', {
          reportIndex: index,
          error: error?.message || String(error),
        });
      }
    }
    const byFingerprint = new Map();
    for (const entry of records) {
      const origin = entry.record.origin;
      const key = origin
        ? `remote:${origin.server_id}:${origin.bug_id}:${entry.record.fingerprint}`
        : `local:${entry.record.fingerprint}`;
      const group = byFingerprint.get(key) ?? [];
      group.push(entry);
      byFingerprint.set(key, group);
    }
    return [...byFingerprint.values()].map(mergeGroup);
  }

  async function listOpen() {
    return publicCollection(await scan(), localOrigin);
  }

  async function exportOpen() {
    const collection = await listOpen();
    return {
      schema_version: SCHEMA_VERSION,
      kind: TRANSFER_KIND,
      exporting_server: localOrigin,
      exported_at: new Date().toISOString(),
      bugs: collection.bugs,
    };
  }

  async function importOpen(bundle) {
    if (!plainObject(bundle) || bundle.schema_version !== SCHEMA_VERSION
        || bundle.kind !== TRANSFER_KIND || !Array.isArray(bundle.bugs)
        || bundle.bugs.length > MAX_IMPORT_BUGS) {
      throw new BugStoreError(400, 'The imported bug bundle is invalid.');
    }
    const exportingServer = boundedText(bundle.exporting_server, 'exporting_server', 256);
    timestamp(bundle.exported_at, 'exported_at');
    const prepared = [];
    try {
      for (const raw of bundle.bugs) {
        const normalized = normalizeRecord(raw);
        const source = normalized.origin ?? {
          kind: 'local',
          server_id: exportingServer,
          bug_id: normalized.bug_id,
          fingerprint: normalized.fingerprint,
        };
        const origin = {
          kind: 'remote',
          server_id: source.server_id,
          bug_id: source.bug_id,
          fingerprint: source.fingerprint,
        };
        const bugId = `bug-${crypto.createHash('sha256')
          .update(`${origin.server_id}\0${origin.bug_id}`).digest('hex').slice(0, 32)}`;
        const imported = { ...normalized, bug_id: bugId, origin };
        imported.fingerprint = importedFingerprint(imported);
        const stored = storageRecord(imported);
        const payload = `${canonicalJson(stored)}\n`;
        if (Buffer.byteLength(payload) > MAX_FILE_BYTES) {
          throw new Error('one imported bug exceeds its size limit');
        }
        prepared.push({ bugId, payload });
      }
    } catch (error) {
      throw new BugStoreError(400, 'The imported bug bundle contains an invalid report.', { cause: error });
    }
    await fsp.mkdir(directory, { recursive: true });
    const staged = [];
    const created = [];
    try {
      for (const item of prepared) {
        const temporary = path.join(directory, `.import-${crypto.randomUUID()}.tmp`);
        await fsp.writeFile(temporary, item.payload, { encoding: 'utf8', mode: 0o666, flag: 'wx' });
        staged.push({ ...item, temporary });
      }
      for (const item of staged) {
        const destination = path.join(directory, `${item.bugId}.json`);
        try {
          await fsp.link(item.temporary, destination);
          created.push(destination);
        } catch (error) {
          if (error?.code !== 'EEXIST') throw error;
        }
      }
    } catch (error) {
      await Promise.all(created.map((file) => fsp.unlink(file).catch(() => {})));
      throw new BugStoreError(503, 'The imported bugs could not be saved.', { cause: error });
    } finally {
      await Promise.all(staged.map((item) => (
        item.temporary ? fsp.unlink(item.temporary).catch(() => {}) : null
      )));
    }
    return {
      ...(await listOpen()),
      import_result: {
        received: prepared.length,
        imported: created.length,
        already_present: prepared.length - created.length,
      },
    };
  }

  async function close(bugId) {
    if (!BUG_ID_RE.test(String(bugId || ''))) throw new BugStoreError(404, 'Coordinator bug not found.');
    const groups = await scan();
    const group = groups.find(({ record }) => record.bug_id === bugId);
    if (group) {
      for (const source of group.sources) {
        try {
          await fsp.unlink(path.join(directory, source));
        } catch (error) {
          if (error?.code !== 'ENOENT') {
            throw new BugStoreError(503, 'The Coordinator bug could not be closed.', { cause: error });
          }
        }
      }
    }
    return listOpen();
  }

  return { listOpen, exportOpen, importOpen, close };
}
