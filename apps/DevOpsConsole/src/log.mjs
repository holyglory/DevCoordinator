// Line-oriented logger: `2026-07-05T12:00:00.000Z INFO msg key=val key2="v 2"`.
// Never pass secrets, cookie values, tokens, or Authorization headers as fields.

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

// Values matching this stay unquoted; everything else is JSON-quoted so the
// line stays parseable even with spaces/quotes in the value.
const BARE_VALUE_RE = /^[A-Za-z0-9_.,:;/@#+~^()<>?!*&%$|=[\]{}-]+$/;

function formatValue(value) {
  let v = value;
  if (v instanceof Error) v = v.message;
  else if (typeof v === 'object' && v !== null) {
    try {
      v = JSON.stringify(v);
    } catch {
      v = String(v);
    }
  }
  const s = String(v);
  if (s !== '' && BARE_VALUE_RE.test(s)) return s;
  return JSON.stringify(s);
}

function makeLogger(threshold, bindings) {
  const emit = (levelName, levelNum, msg, fields) => {
    if (levelNum < threshold) return;
    let line = `${new Date().toISOString()} ${levelName.toUpperCase()} ${String(msg)}`;
    const merged = fields ? { ...bindings, ...fields } : bindings;
    for (const [key, value] of Object.entries(merged)) {
      if (value === undefined) continue;
      line += ` ${key}=${formatValue(value)}`;
    }
    const stream = levelNum >= LEVELS.warn ? process.stderr : process.stdout;
    stream.write(line + '\n');
  };

  return {
    debug: (msg, fields) => emit('debug', LEVELS.debug, msg, fields),
    info: (msg, fields) => emit('info', LEVELS.info, msg, fields),
    warn: (msg, fields) => emit('warn', LEVELS.warn, msg, fields),
    error: (msg, fields) => emit('error', LEVELS.error, msg, fields),
    child: (childBindings = {}) => makeLogger(threshold, { ...bindings, ...childBindings }),
  };
}

export function createLogger(level) {
  const threshold = LEVELS[level] ?? LEVELS.info;
  return makeLogger(threshold, {});
}
