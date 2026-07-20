import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { createProcessLifecycle, runCleanupSteps } from '../src/process-lifecycle.mjs';

class FakeProcess extends EventEmitter {
  constructor() {
    super();
    this.pid = 4242;
    this.stderrLines = [];
    this.stderr = { write: (line) => this.stderrLines.push(line) };
  }
}

function createHarness({ cleanup = async () => [], nowValues = [1_000, 1_025] } = {}) {
  const processTarget = new FakeProcess();
  const records = [];
  const exits = [];
  const timers = [];
  let nowIndex = 0;
  const log = Object.fromEntries(
    ['info', 'warn', 'error'].map((level) => [
      level,
      (message, fields = {}) => records.push({ level, message, fields }),
    ]),
  );
  const lifecycle = createProcessLifecycle({
    log,
    cleanup,
    processTarget,
    shutdownTimeoutMs: 250,
    now: () => nowValues[Math.min(nowIndex++, nowValues.length - 1)],
    setTimeoutFn(callback, delay) {
      const timer = {
        callback,
        delay,
        cleared: false,
        unreferenced: false,
        unref() { this.unreferenced = true; },
      };
      timers.push(timer);
      return timer;
    },
    clearTimeoutFn(timer) { timer.cleared = true; },
    exit(code) { exits.push(code); },
  });
  return { lifecycle, processTarget, records, exits, timers };
}

test('signal shutdown logs a ready marker and bounded successful completion before exit zero', async () => {
  let cleanupCalls = 0;
  const harness = createHarness({
    cleanup: async () => {
      cleanupCalls += 1;
      return [];
    },
  });
  assert.equal(harness.lifecycle.install(), true);
  assert.equal(harness.lifecycle.install(), false);
  assert.equal(harness.lifecycle.state, 'starting');
  assert.equal(harness.lifecycle.markReady({ version: '1.7.1', httpsPort: 443 }), true);
  assert.equal(harness.lifecycle.markReady({ version: 'duplicate' }), false);
  assert.equal(harness.lifecycle.state, 'ready');

  harness.processTarget.emit('SIGTERM');
  const result = await harness.lifecycle.waitForShutdown();

  assert.equal(cleanupCalls, 1);
  assert.deepEqual(harness.exits, [0]);
  assert.equal(result.exitCode, 0);
  assert.equal(result.forced, false);
  assert.equal(harness.timers.length, 1);
  assert.equal(harness.timers[0].delay, 250);
  assert.equal(harness.timers[0].unreferenced, false, 'the fatal deadline must keep the process alive');
  assert.equal(harness.timers[0].cleared, true);
  assert.deepEqual(
    harness.records.map(({ level, message }) => [level, message]),
    [
      ['info', 'devops-console ready'],
      ['info', 'shutdown started'],
      ['info', 'shutdown complete'],
    ],
  );
  assert.deepEqual(harness.records[0].fields, { version: '1.7.1', httpsPort: 443, pid: 4242 });
  assert.deepEqual(harness.records[2].fields, {
    trigger: 'signal',
    signal: 'SIGTERM',
    exitCode: 0,
    durationMs: 25,
    cleanupFailures: 0,
    pid: 4242,
  });
  assert.equal(harness.lifecycle.dispose(), true);
  assert.equal(harness.lifecycle.dispose(), false);
});

for (const [event, trigger, failure] of [
  ['unhandledRejection', 'unhandledRejection', new Error('asynchronous failure')],
  ['uncaughtException', 'uncaughtException', new TypeError('synchronous failure')],
]) {
  test(`${event} is fatal, is logged with a stack, cleans up, and exits nonzero`, async () => {
    let cleaned = false;
    const harness = createHarness({ cleanup: async () => { cleaned = true; return []; } });
    harness.lifecycle.install();

    harness.processTarget.emit(event, failure);
    const result = await harness.lifecycle.waitForShutdown();

    assert.equal(cleaned, true);
    assert.deepEqual(harness.exits, [1]);
    assert.equal(result.exitCode, 1);
    const fatal = harness.records.find((record) => record.message === 'fatal process event');
    assert.equal(fatal.level, 'error');
    assert.equal(fatal.fields.trigger, trigger);
    assert.match(fatal.fields.error, new RegExp(failure.message));
    assert.match(fatal.fields.error, /unit\.process-lifecycle\.test\.mjs/);
    const completed = harness.records.find((record) => record.message === 'shutdown complete');
    assert.equal(completed.level, 'error');
    assert.equal(completed.fields.exitCode, 1);
  });
}

test('top-level fatal uses the same bounded nonzero cleanup path', async () => {
  const harness = createHarness();
  harness.lifecycle.install();
  const result = await harness.lifecycle.fatal('top-level-failure', new Error('startup broke'));
  assert.equal(result.exitCode, 1);
  assert.deepEqual(harness.exits, [1]);
  assert.equal(harness.records[0].message, 'fatal process event');
  assert.equal(harness.records[0].fields.trigger, 'top-level-failure');
});

test('cleanup runs every step, retains every failure, and makes signal shutdown nonzero', async () => {
  const order = [];
  const failures = await runCleanupSteps([
    { name: 'first', run: async () => { order.push('first'); throw new Error('first failed'); } },
    { name: 'second', run: () => { order.push('second'); } },
    { name: 'third', run: () => { order.push('third'); throw new TypeError('third failed'); } },
  ]);
  assert.deepEqual(order, ['first', 'second', 'third']);
  assert.equal(failures.length, 2);
  assert.equal(failures[0].step, 'first');
  assert.equal(failures[1].step, 'third');

  const harness = createHarness({ cleanup: async () => failures });
  const result = await harness.lifecycle.shutdown('SIGTERM');
  assert.deepEqual(harness.exits, [1]);
  assert.equal(result.exitCode, 1);
  assert.deepEqual(result.cleanupFailures.map(({ step }) => step), ['first', 'third']);
  const cleanupLogs = harness.records.filter((record) => record.message === 'shutdown cleanup failed');
  assert.deepEqual(cleanupLogs.map((record) => record.fields.step), ['first', 'third']);
  assert.match(cleanupLogs[0].fields.error, /first failed/);
  const completed = harness.records.find((record) => record.message === 'shutdown complete');
  assert.equal(completed.fields.cleanupFailures, 2);
  assert.equal(completed.fields.exitCode, 1);
});

test('a second signal forces immediate nonzero exit while cleanup is still pending', async () => {
  let finishCleanup;
  const pendingCleanup = new Promise((resolve) => { finishCleanup = resolve; });
  const harness = createHarness({ cleanup: () => pendingCleanup });
  harness.lifecycle.install();

  harness.processTarget.emit('SIGTERM');
  assert.deepEqual(harness.exits, []);
  harness.processTarget.emit('SIGINT');
  assert.deepEqual(harness.exits, [1]);
  const forced = harness.records.find((record) => record.message === 'shutdown forced');
  assert.deepEqual(
    { reason: forced.fields.reason, trigger: forced.fields.trigger, signal: forced.fields.signal },
    { reason: 'second-trigger', trigger: 'signal', signal: 'SIGINT' },
  );

  finishCleanup([]);
  const result = await harness.lifecycle.waitForShutdown();
  assert.equal(result.forced, true);
  assert.equal(result.forcedReason, 'second-trigger');
  assert.equal(
    harness.records.some((record) => record.message === 'shutdown complete'),
    false,
    'a forced exit must not later claim graceful completion',
  );
  assert.deepEqual(harness.exits, [1], 'completion after a forced exit must not request another exit');
});

test('the shutdown deadline forces nonzero exit when cleanup never settles', async () => {
  const harness = createHarness({ cleanup: () => new Promise(() => {}) });
  harness.lifecycle.install();
  harness.processTarget.emit('SIGTERM');
  assert.equal(harness.timers.length, 1);

  harness.timers[0].callback();
  const result = await harness.lifecycle.waitForShutdown();

  assert.deepEqual(harness.exits, [1]);
  assert.equal(result.forced, true);
  assert.equal(result.exitCode, 1);
  const forced = harness.records.find((record) => record.message === 'shutdown forced');
  assert.equal(forced.fields.reason, 'deadline');
  assert.equal(forced.fields.firstTrigger, 'signal');
});

test('production entrypoint installs lifecycle handling before async boot and marks ready after registration', async () => {
  const source = await readFile(new URL('../bin/devops-console.mjs', import.meta.url), 'utf8');
  const install = source.indexOf('lifecycle.install();');
  const firstAsyncBoot = source.indexOf('await createCertManager(', install);
  const registration = source.indexOf('await completeProductionRegistration(', install);
  const ready = source.indexOf('lifecycle.markReady(', registration);
  assert.ok(install >= 0 && firstAsyncBoot > install, 'lifecycle handlers must precede async resource boot');
  assert.ok(registration > firstAsyncBoot && ready > registration, 'ready marker must follow registration');
  assert.doesNotMatch(source, /process\.on\(['"](?:uncaughtException|unhandledRejection|SIGTERM|SIGINT)/);
  assert.match(source, /directRunLifecycle\.fatal\('top-level-failure', err\)/);
});
