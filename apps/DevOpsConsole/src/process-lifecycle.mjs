import process from 'node:process';

const DEFAULT_SHUTDOWN_TIMEOUT_MS = 15_000;

function safeString(value) {
  try {
    return String(value);
  } catch {
    return '<unprintable value>';
  }
}

function errorDetail(error) {
  if (error instanceof Error) {
    let rendered;
    try {
      rendered = error.stack || error.message || safeString(error);
    } catch {
      rendered = '<unprintable Error>';
    }
    return {
      type: error.name || 'Error',
      error: rendered,
    };
  }
  return {
    type: typeof error,
    error: safeString(error),
  };
}

function normalizeCleanupFailures(value) {
  if (!Array.isArray(value)) return [];
  return value.map((failure, index) => {
    if (failure && typeof failure === 'object') {
      return {
        step: String(failure.step || `cleanup-${index + 1}`),
        ...errorDetail(failure.error ?? failure.detail ?? failure),
      };
    }
    return {
      step: `cleanup-${index + 1}`,
      ...errorDetail(failure),
    };
  });
}

/**
 * Run every cleanup step in order and retain every failure. Cleanup is a
 * best-effort boundary: one broken closer must not prevent later resources
 * from releasing their listeners, timers, or file handles.
 */
export async function runCleanupSteps(steps) {
  const failures = [];
  for (const step of steps) {
    if (!step || typeof step.run !== 'function') continue;
    try {
      await step.run();
    } catch (error) {
      failures.push({ step: String(step.name || 'cleanup'), error });
    }
  }
  return failures;
}

/**
 * Own process-level fatal and shutdown behavior for the production daemon.
 * Dependencies are injectable so the same state machine can be exercised
 * deterministically without signals or process termination in unit tests.
 */
export function createProcessLifecycle({
  log,
  cleanup = async () => [],
  processTarget = process,
  shutdownTimeoutMs = DEFAULT_SHUTDOWN_TIMEOUT_MS,
  now = () => Date.now(),
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  exit = (code) => processTarget.exit(code),
} = {}) {
  if (!log || typeof log.info !== 'function' || typeof log.warn !== 'function' || typeof log.error !== 'function') {
    throw new TypeError('process lifecycle requires info, warn, and error logger methods');
  }
  if (typeof cleanup !== 'function') throw new TypeError('process lifecycle cleanup must be a function');
  if (!Number.isFinite(shutdownTimeoutMs) || shutdownTimeoutMs <= 0) {
    throw new TypeError('process lifecycle shutdown timeout must be positive');
  }

  let installed = false;
  let ready = false;
  let shutdownPromise = null;
  let exitRequested = false;
  let forcedExit = null;
  let firstTrigger = null;

  const safeLog = (level, message, fields) => {
    try {
      log[level](message, fields);
    } catch (error) {
      // A logger failure must never prevent a fatal process from terminating.
      try {
        processTarget.stderr?.write?.(
          `${new Date().toISOString()} ERROR lifecycle logger failed error=${JSON.stringify(safeString(error))}\n`,
        );
      } catch {
        // No further reliable output boundary remains.
      }
    }
  };

  const requestExit = (code) => {
    if (exitRequested) return;
    exitRequested = true;
    exit(code);
  };

  const forceExit = ({ reason, trigger, signal }) => {
    if (exitRequested) return;
    forcedExit = { reason, trigger, signal };
    safeLog('error', 'shutdown forced', {
      reason,
      trigger,
      signal,
      firstTrigger,
      exitCode: 1,
      pid: processTarget.pid,
    });
    requestExit(1);
  };

  const performShutdown = async ({ trigger, signal, error, requestedExitCode }) => {
    firstTrigger = trigger;
    const startedAt = now();
    if (error !== undefined) {
      safeLog('error', 'fatal process event', {
        trigger,
        ...errorDetail(error),
        pid: processTarget.pid,
      });
    }
    safeLog(requestedExitCode === 0 ? 'info' : 'error', 'shutdown started', {
      trigger,
      signal,
      requestedExitCode,
      timeoutMs: shutdownTimeoutMs,
      pid: processTarget.pid,
    });

    let deadlineTimer;
    const deadline = new Promise((resolve) => {
      deadlineTimer = setTimeoutFn(() => {
        forceExit({ reason: 'deadline', trigger, signal });
        resolve({ timedOut: true, failures: [] });
      }, shutdownTimeoutMs);
    });

    const cleaned = Promise.resolve()
      .then(() => cleanup())
      .then((failures) => ({ timedOut: false, failures: normalizeCleanupFailures(failures) }))
      .catch((cleanupError) => ({
        timedOut: false,
        failures: [{ step: 'cleanup', ...errorDetail(cleanupError) }],
      }));

    const outcome = await Promise.race([cleaned, deadline]);
    if (outcome.timedOut) {
      return {
        trigger,
        signal,
        exitCode: 1,
        forced: true,
        cleanupFailures: [],
      };
    }
    clearTimeoutFn(deadlineTimer);
    if (forcedExit) {
      return {
        trigger,
        signal,
        exitCode: 1,
        forced: true,
        forcedReason: forcedExit.reason,
        cleanupFailures: outcome.failures,
      };
    }

    for (const failure of outcome.failures) {
      safeLog('error', 'shutdown cleanup failed', failure);
    }
    const exitCode = requestedExitCode === 0 && outcome.failures.length === 0 ? 0 : 1;
    const durationMs = Math.max(0, now() - startedAt);
    safeLog(exitCode === 0 ? 'info' : 'error', 'shutdown complete', {
      trigger,
      signal,
      exitCode,
      durationMs,
      cleanupFailures: outcome.failures.length,
      pid: processTarget.pid,
    });
    requestExit(exitCode);
    return {
      trigger,
      signal,
      exitCode,
      forced: false,
      cleanupFailures: outcome.failures,
    };
  };

  const requestShutdown = ({ trigger, signal, error, requestedExitCode }) => {
    if (shutdownPromise) {
      forceExit({ reason: 'second-trigger', trigger, signal });
      return shutdownPromise;
    }
    shutdownPromise = performShutdown({ trigger, signal, error, requestedExitCode });
    return shutdownPromise;
  };

  const handlers = {
    SIGTERM: () => void requestShutdown({ trigger: 'signal', signal: 'SIGTERM', requestedExitCode: 0 }),
    SIGINT: () => void requestShutdown({ trigger: 'signal', signal: 'SIGINT', requestedExitCode: 0 }),
    uncaughtException: (error) => void requestShutdown({
      trigger: 'uncaughtException',
      error,
      requestedExitCode: 1,
    }),
    unhandledRejection: (reason) => void requestShutdown({
      trigger: 'unhandledRejection',
      error: reason,
      requestedExitCode: 1,
    }),
  };

  return {
    install() {
      if (installed) return false;
      installed = true;
      for (const [event, handler] of Object.entries(handlers)) processTarget.on(event, handler);
      return true;
    },

    dispose() {
      if (!installed) return false;
      for (const [event, handler] of Object.entries(handlers)) processTarget.off(event, handler);
      installed = false;
      return true;
    },

    markReady(fields = {}) {
      if (ready || shutdownPromise) return false;
      ready = true;
      safeLog('info', 'devops-console ready', { ...fields, pid: processTarget.pid });
      return true;
    },

    shutdown(signal = 'SIGTERM') {
      return requestShutdown({ trigger: 'signal', signal, requestedExitCode: 0 });
    },

    fatal(trigger, error) {
      return requestShutdown({ trigger, error, requestedExitCode: 1 });
    },

    waitForShutdown() {
      return shutdownPromise;
    },

    get state() {
      if (shutdownPromise) return 'shutting-down';
      if (ready) return 'ready';
      return installed ? 'starting' : 'new';
    },
  };
}
