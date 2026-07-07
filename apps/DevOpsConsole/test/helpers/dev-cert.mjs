// Self-signed *.vr.ae test certificate, generated on demand so a fresh clone
// (CI) can run the suite without committed key material. certs/dev/ stays
// gitignored; generation is idempotent and safe under node --test's parallel
// test processes (mkdir lock + atomic renames of a matched cert/key pair).

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIR = path.join(APP_ROOT, 'certs', 'dev');

export const DEV_CERT = path.join(DIR, 'wildcard.vr.ae.crt');
export const DEV_KEY = path.join(DIR, 'wildcard.vr.ae.key');

export function ensureDevCert() {
  if (fs.existsSync(DEV_CERT) && fs.existsSync(DEV_KEY)) return { cert: DEV_CERT, key: DEV_KEY };
  fs.mkdirSync(DIR, { recursive: true });
  const lock = path.join(DIR, '.generating');
  const deadline = Date.now() + 30_000;
  for (;;) {
    if (fs.existsSync(DEV_CERT) && fs.existsSync(DEV_KEY)) return { cert: DEV_CERT, key: DEV_KEY };
    try {
      fs.mkdirSync(lock);
      break;
    } catch {
      if (Date.now() > deadline) throw new Error('timed out waiting for another process to generate the dev cert');
      execFileSync('sleep', ['0.1']);
    }
  }
  try {
    if (!fs.existsSync(DEV_CERT) || !fs.existsSync(DEV_KEY)) {
      const tmpCert = `${DEV_CERT}.tmp`;
      const tmpKey = `${DEV_KEY}.tmp`;
      execFileSync('openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', tmpKey, '-out', tmpCert, '-days', '365',
        '-subj', '/CN=*.vr.ae',
        '-addext', 'subjectAltName=DNS:vr.ae,DNS:*.vr.ae',
      ], { stdio: 'pipe' });
      fs.renameSync(tmpKey, DEV_KEY);
      fs.renameSync(tmpCert, DEV_CERT);
    }
  } finally {
    fs.rmdirSync(lock);
  }
  return { cert: DEV_CERT, key: DEV_KEY };
}
