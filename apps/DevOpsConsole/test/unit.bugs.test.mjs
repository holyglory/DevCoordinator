import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { BugStoreError, createBugStore } from '../src/bugs.mjs';

const BUG_A = `bug-${'a'.repeat(32)}`;
const BUG_B = `bug-${'b'.repeat(32)}`;
const BUG_C = `bug-${'c'.repeat(32)}`;
const BUG_D = `bug-${'d'.repeat(32)}`;
const BUG_E = `bug-${'e'.repeat(32)}`;
const FINGERPRINT_A = '1'.repeat(64);
const FINGERPRINT_B = '2'.repeat(64);

async function tempDir(t) {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-bugs-'));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  return directory;
}

function report(overrides = {}) {
  const bugId = overrides.bug_id || BUG_A;
  return {
    schema_version: 1,
    bug_id: bugId,
    fingerprint: overrides.fingerprint || FINGERPRINT_A,
    component: 'testd launch adapter',
    summary: 'Authority launch request times out before the test starts',
    expected: 'A runner starts within the caller-selected launch deadline.',
    actual: 'The request failed while reading /var/lib/devcoordinator/private.log with Bearer live-secret; {"access_token":"json-secret","token_count":12}; AWS_SECRET_ACCESS_KEY=aws-secret; tokens_processed=9.',
    reproduction_steps: [
      'Open the repository at /home/developer/GlobalFinance.',
      'Submit one immutable run and retain its operation identifier.',
    ],
    reporter: 'codex-root',
    peer_uid: 1000,
    first_seen_at: '2026-08-04T08:00:00.000Z',
    last_seen_at: '2026-08-04T08:05:00.000Z',
    occurrence_count: 2,
    repository: '/home/developer/GlobalFinance',
    classification: 'infrastructure_failure',
    code: 'request_timeout',
    stage: 'launch',
    command_argv: [
      'devcoordinator-test', 'submit', '--root-repo', '/home/developer/GlobalFinance',
      '--api-key', 'command-secret', '--password=assigned-secret',
    ],
    release_digest: '3'.repeat(64),
    instance_id: 'console-blue',
    correlations: {
      call_id: 'call-123',
      operation_id: 'operation-123',
      run_id: 'run-123',
    },
    local_fallback: {
      status: 'passed',
      command_argv: ['npm', 'test', '--token', 'fallback-secret'],
      summary: 'Local checks passed in /tmp/checkout; password=another-secret.',
      advisory: true,
      coordinator_evidence: false,
    },
    ...overrides,
  };
}

async function writeReport(directory, value) {
  await fsp.mkdir(directory, { recursive: true });
  const file = path.join(directory, `${value.bug_id}.json`);
  await fsp.writeFile(file, JSON.stringify(value), { mode: 0o666 });
  return file;
}

test('missing registry is an honest empty open collection', async (t) => {
  const root = await tempDir(t);
  const store = createBugStore({ directory: path.join(root, 'not-created') });

  const value = await store.listOpen();

  assert.equal(value.schema_version, 1);
  assert.deepEqual(value.bugs, []);
  assert.match(value.revision, /^[0-9a-f]{64}$/);
});

test('portable export and idempotent import preserve remote origin without merging local bugs', async (t) => {
  const root = await tempDir(t);
  const sourceDirectory = path.join(root, 'source');
  const destinationDirectory = path.join(root, 'destination');
  await writeReport(sourceDirectory, report());
  const source = createBugStore({ directory: sourceDirectory, originServerId: 'alpha.example.test' });
  const exported = await source.exportOpen();

  assert.equal(exported.kind, 'devcoordinator-open-bugs');
  assert.equal(exported.exporting_server, 'alpha.example.test');
  assert.deepEqual(exported.bugs[0].origin, {
    kind: 'local',
    server_id: 'alpha.example.test',
    bug_id: BUG_A,
    fingerprint: FINGERPRINT_A,
  });
  const serialized = JSON.stringify(exported);
  assert.doesNotMatch(serialized, /\/home\/|\/var\/|\/tmp\/|live-secret|json-secret|aws-secret|command-secret|assigned-secret|fallback-secret|another-secret/i);

  const destination = createBugStore({
    directory: destinationDirectory,
    originServerId: 'beta.example.test',
  });
  const first = await destination.importOpen(exported);
  assert.deepEqual(first.import_result, { received: 1, imported: 1, already_present: 0 });
  assert.equal(first.bugs.length, 1);
  assert.equal(first.bugs[0].origin.kind, 'remote');
  assert.equal(first.bugs[0].origin.server_id, 'alpha.example.test');
  assert.equal(first.bugs[0].origin.bug_id, BUG_A);
  assert.notEqual(first.bugs[0].bug_id, BUG_A);

  const repeated = await destination.importOpen(exported);
  assert.deepEqual(repeated.import_result, { received: 1, imported: 0, already_present: 1 });
  await writeReport(destinationDirectory, report());
  const withLocal = await destination.listOpen();
  assert.equal(withLocal.bugs.length, 2, 'a matching local observation remains distinct');
  assert.deepEqual(new Set(withLocal.bugs.map((bug) => bug.origin.kind)), new Set(['local', 'remote']));

  const reexported = await destination.exportOpen();
  const remote = reexported.bugs.find((bug) => bug.origin.kind === 'remote');
  assert.equal(remote.origin.server_id, 'alpha.example.test');
  assert.equal(remote.origin.bug_id, BUG_A);
});

test('one malformed imported report creates no partial open files', async (t) => {
  const root = await tempDir(t);
  const sourceDirectory = path.join(root, 'source');
  const destinationDirectory = path.join(root, 'destination');
  await writeReport(sourceDirectory, report());
  const source = createBugStore({ directory: sourceDirectory, originServerId: 'alpha.example.test' });
  const exported = await source.exportOpen();
  exported.bugs.push({ ...exported.bugs[0], bug_id: 'not-a-bug-id' });
  const destination = createBugStore({ directory: destinationDirectory, originServerId: 'beta.example.test' });

  await assert.rejects(destination.importOpen(exported), (error) => (
    error instanceof BugStoreError && error.status === 400
  ));
  await assert.rejects(fsp.stat(destinationDirectory), { code: 'ENOENT' });
});

test('valid reports are bounded, path-safe, deduplicated, and malformed files are isolated', async (t) => {
  const directory = await tempDir(t);
  const logs = [];
  const log = {
    child: () => log,
    warn: (message, fields) => logs.push({ message, fields }),
  };
  await writeReport(directory, report());
  await writeReport(directory, report({
    bug_id: BUG_B,
    first_seen_at: '2026-08-04T07:00:00.000Z',
    last_seen_at: '2026-08-04T08:15:00.000Z',
    occurrence_count: 3,
    summary: 'Authority launch request still times out',
  }));
  await writeReport(directory, report({
    bug_id: BUG_C,
    fingerprint: FINGERPRINT_B,
    component: 'broker',
    summary: 'Broker is unavailable',
    last_seen_at: '2026-08-04T06:00:00.000Z',
  }));
  await fsp.writeFile(path.join(directory, 'malformed.json'), '{ nope', 'utf8');
  await fsp.writeFile(path.join(directory, '.writer.tmp'), 'partial', 'utf8');
  await writeReport(directory, report({
    bug_id: BUG_D,
    fingerprint: '4'.repeat(64),
    reproduction_steps: Array.from({ length: 9 }, (_, index) => `Step ${index + 1}`),
  }));
  await fsp.writeFile(path.join(directory, `${BUG_E}.json`), 'x'.repeat(16 * 1024 + 1), 'utf8');

  const value = await createBugStore({ directory, log }).listOpen();

  assert.equal(value.bugs.length, 2);
  const merged = value.bugs.find((bug) => bug.fingerprint === FINGERPRINT_A);
  assert.equal(merged.bug_id, BUG_B);
  assert.equal(merged.occurrence_count, 5);
  assert.equal(merged.first_seen_at, '2026-08-04T07:00:00.000Z');
  assert.equal(merged.last_seen_at, '2026-08-04T08:15:00.000Z');
  assert.equal(merged.repository, 'GlobalFinance');
  assert.equal(merged.peer_uid, 1000);
  assert.equal(merged.release_digest, '3'.repeat(64));
  assert.equal(merged.instance_id, 'console-blue');
  assert.equal(merged.local_fallback.status, 'passed');
  assert.equal(merged.local_fallback.advisory, true);
  assert.equal(merged.local_fallback.coordinator_evidence, false);
  assert.deepEqual(merged.origin, {
    kind: 'local',
    server_id: 'this-server',
    bug_id: BUG_B,
    fingerprint: FINGERPRINT_A,
  });
  assert.deepEqual(merged.command_argv.slice(-3), ['--api-key', '[redacted]', '--password=[redacted]']);
  assert.deepEqual(merged.local_fallback.command_argv.slice(-2), ['--token', '[redacted]']);
  assert.match(merged.local_fallback.summary, /\[server path\]/);
  assert.match(merged.reproduction_steps[0], /\$REPOSITORY/);
  assert.doesNotMatch(JSON.stringify(value), /\/home\/|\/var\/|\/tmp\/|live-secret|json-secret|aws-secret|command-secret|assigned-secret|fallback-secret|another-secret/);
  assert.match(merged.actual, /token_count/);
  assert.match(merged.actual, /tokens_processed=9/);
  assert.equal(logs.length, 3);
  assert.equal(logs[0].message, 'isolated malformed open Coordinator bug report');
  assert.doesNotMatch(JSON.stringify(logs), /malformed\.json|private\.log/);
});

test('close removes the complete active fingerprint group and every store observes it', async (t) => {
  const directory = await tempDir(t);
  const first = await writeReport(directory, report());
  const duplicate = await writeReport(directory, report({
    bug_id: BUG_B,
    last_seen_at: '2026-08-04T08:15:00.000Z',
  }));
  await writeReport(directory, report({
    bug_id: BUG_C,
    fingerprint: FINGERPRINT_B,
    summary: 'Another open bug',
  }));
  const storeA = createBugStore({ directory });
  const storeB = createBugStore({ directory });

  const before = await storeA.listOpen();
  const canonical = before.bugs.find((bug) => bug.fingerprint === FINGERPRINT_A);
  const [closed, raced] = await Promise.all([
    storeA.close(canonical.bug_id),
    storeB.close(canonical.bug_id),
  ]);

  assert.equal(closed.bugs.some((bug) => bug.fingerprint === canonical.fingerprint), false);
  assert.equal(raced.bugs.some((bug) => bug.fingerprint === canonical.fingerprint), false);
  assert.equal((await storeB.listOpen()).bugs.length, 1);
  await assert.rejects(fsp.stat(first), { code: 'ENOENT' });
  await assert.rejects(fsp.stat(duplicate), { code: 'ENOENT' });
  assert.equal((await fsp.readdir(directory)).some((name) => /closed|tombstone/i.test(name)), false);

  const again = await storeA.close(canonical.bug_id);
  assert.equal(again.bugs.length, 1, 'closing an already-removed report stays idempotent');
});

test('an unavailable registry fails locally instead of masquerading as an empty list', async (t) => {
  const root = await tempDir(t);
  const notDirectory = path.join(root, 'not-a-directory');
  await fsp.writeFile(notDirectory, 'occupied', 'utf8');
  const store = createBugStore({ directory: notDirectory });

  await assert.rejects(
    store.listOpen(),
    (error) => error instanceof BugStoreError
      && error.status === 503
      && error.message === 'Open Coordinator bugs are temporarily unavailable.',
  );
});
