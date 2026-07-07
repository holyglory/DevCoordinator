// Server-side UI preferences (currently: hidden inventory items), persisted in
// <stateDir>/ui-prefs.json so hiding follows the operator across devices.
// Hidden items are identified by stable keys: server identity keys
// ("<project>::<name>"), container names, and project usage_keys. The client
// auto-unhides an item the moment the coordinator reports it running again.

import fs from 'node:fs';
import { rename, writeFile } from 'node:fs/promises';

const LIST_NAMES = ['servers', 'docker', 'projects'];
const MAX_ENTRIES = 500;
const MAX_ENTRY_LENGTH = 300;

export class PrefsError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = 'PrefsError';
    this.status = status;
  }
}

function emptyPrefs() {
  return { version: 1, hidden: { servers: [], docker: [], projects: [] } };
}

function sanitizeList(value, name) {
  if (!Array.isArray(value)) throw new PrefsError(`hidden.${name} must be an array of strings`);
  if (value.length > MAX_ENTRIES) throw new PrefsError(`hidden.${name} exceeds ${MAX_ENTRIES} entries`);
  const out = [];
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== 'string' || !item.trim()) throw new PrefsError(`hidden.${name} entries must be non-empty strings`);
    if (item.length > MAX_ENTRY_LENGTH) throw new PrefsError(`hidden.${name} entries must stay under ${MAX_ENTRY_LENGTH} characters`);
    const trimmed = item.trim();
    if (seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

export function createPrefsStore({ file, log }) {
  const plog = typeof log?.child === 'function' ? log.child({ mod: 'prefs' }) : log;
  let prefs = null;
  let writing = Promise.resolve();

  function load() {
    if (prefs) return prefs;
    prefs = emptyPrefs();
    try {
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (raw && typeof raw === 'object' && raw.hidden && typeof raw.hidden === 'object') {
        for (const name of LIST_NAMES) {
          try {
            prefs.hidden[name] = sanitizeList(raw.hidden[name] ?? [], name);
          } catch {
            prefs.hidden[name] = [];
          }
        }
      }
    } catch (err) {
      if (err?.code !== 'ENOENT') {
        plog?.warn?.('ui prefs unreadable; starting fresh', { file, error: err?.message ?? String(err) });
      }
    }
    return prefs;
  }

  function persist() {
    const snapshot = JSON.stringify(load(), null, 2) + '\n';
    // Serialize writers; atomic tmp+rename so a crash never truncates prefs.
    // The returned promise REJECTS on failure so callers can refuse to claim
    // durability they do not have; the internal chain stays alive regardless.
    const op = writing.then(async () => {
      await writeFile(`${file}.tmp`, snapshot, 'utf8');
      await rename(`${file}.tmp`, file);
    });
    writing = op.catch((err) => {
      plog?.warn?.('ui prefs write failed', { file, error: err?.message ?? String(err) });
    });
    return op;
  }

  function get() {
    return load();
  }

  /**
   * Apply hide/unhide DELTAS against the authoritative stored lists. Deltas —
   * never whole-list replacement — so concurrent writers (two devices, or a
   * user hide racing the auto-unhide poll) can never clobber each other's
   * changes with a stale snapshot. Returns the merged prefs.
   */
  async function applyHiddenDelta({ hide, unhide } = {}) {
    const deltas = { hide, unhide };
    let sawAny = false;
    const current = load();
    // Validate everything before mutating anything.
    const parsed = { hide: {}, unhide: {} };
    for (const op of ['hide', 'unhide']) {
      const value = deltas[op];
      if (value === undefined) continue;
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new PrefsError(`${op} must be an object of lists`);
      }
      for (const name of Object.keys(value)) {
        if (!LIST_NAMES.includes(name)) {
          throw new PrefsError(`unknown list '${name}' — expected one of: ${LIST_NAMES.join(', ')}`);
        }
        parsed[op][name] = sanitizeList(value[name], name);
        sawAny = true;
      }
    }
    if (!sawAny) {
      throw new PrefsError(`nothing to do — provide hide and/or unhide with at least one of: ${LIST_NAMES.join(', ')}`);
    }
    const backup = Object.fromEntries(LIST_NAMES.map((name) => [name, [...current.hidden[name]]]));
    for (const name of LIST_NAMES) {
      const set = new Set(current.hidden[name]);
      for (const key of parsed.hide[name] ?? []) set.add(key);
      for (const key of parsed.unhide[name] ?? []) set.delete(key);
      if (set.size > MAX_ENTRIES) {
        Object.assign(current.hidden, backup);
        throw new PrefsError(`hidden.${name} would exceed ${MAX_ENTRIES} entries`);
      }
      current.hidden[name] = [...set];
    }
    try {
      await persist();
    } catch (err) {
      // Memory must not claim what disk refused: roll back and report.
      Object.assign(current.hidden, backup);
      throw new PrefsError(`preferences could not be saved: ${err?.message ?? err}`, 500);
    }
    return current;
  }

  return { get, applyHiddenDelta };
}
