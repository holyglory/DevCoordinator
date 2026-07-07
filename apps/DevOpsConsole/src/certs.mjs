// TLS certificate manager: loads the wildcard cert/key, exposes a
// tls.SecureContext for the SNICallback, hot-reloads on file change (polled;
// certbot renewals replace the files in place) and on demand (SIGHUP is wired
// in bin/). A failed reload keeps serving the previous context.

import fs from 'node:fs';
import { readFile } from 'node:fs/promises';
import tls from 'node:tls';
import crypto from 'node:crypto';

const WATCH_INTERVAL_MS = 30_000;

export async function createCertManager({ certFile, keyFile, log }) {
  let context = null;
  let credentials = null; // current PEMs — the TLS server's default (non-SNI) context
  let info = null;
  let inflightReload = null;
  let closed = false;
  const swapListeners = new Set();

  async function load() {
    const [certPem, keyPem] = await Promise.all([readFile(certFile), readFile(keyFile)]);
    // Throws on bad PEM or key/cert mismatch — caller decides what to do.
    const nextContext = tls.createSecureContext({ cert: certPem, key: keyPem });
    const x509 = new crypto.X509Certificate(certPem);
    let selfSigned;
    try {
      selfSigned = x509.checkIssued(x509);
    } catch {
      selfSigned = x509.issuer === x509.subject;
    }
    context = nextContext;
    credentials = { cert: certPem, key: keyPem };
    info = {
      loadedAt: new Date().toISOString(),
      notAfter: new Date(x509.validTo).toISOString(),
      subject: x509.subject,
      issuer: x509.issuer,
      selfSigned,
    };
    for (const listener of swapListeners) {
      try {
        listener();
      } catch (err) {
        log.warn('cert swap listener failed', { error: err?.message || String(err) });
      }
    }
  }

  // Initial load is fatal on failure (config already checked readability, but
  // the PEM contents themselves are validated here).
  await load();
  log.info('tls certificate loaded', { subject: info.subject, notAfter: info.notAfter, selfSigned: info.selfSigned });

  // Never throws: a broken half-written renewal must not take the edge down.
  function reload() {
    if (inflightReload) return inflightReload;
    inflightReload = load()
      .then(() => {
        log.info('tls certificate reloaded', { subject: info.subject, notAfter: info.notAfter });
      })
      .catch((err) => {
        log.error('tls certificate reload failed; keeping previous context', { error: err.message });
      })
      .finally(() => {
        inflightReload = null;
      });
    return inflightReload;
  }

  const onFileChange = (curr, prev) => {
    if (closed) return;
    // fs.watchFile fires on any stat change; only react to real content changes.
    if (curr.mtimeMs === prev.mtimeMs && curr.size === prev.size && curr.ino === prev.ino) return;
    log.info('tls files changed on disk; reloading certificate');
    reload();
  };

  for (const file of [certFile, keyFile]) {
    const watcher = fs.watchFile(file, { interval: WATCH_INTERVAL_MS }, onFileChange);
    // Polling must not keep the process alive after close().
    watcher.unref();
  }

  return {
    getSecureContext: () => context,
    // Current PEMs for the server's DEFAULT context. SNICallback only fires
    // when the client sends SNI; IP-address clients (curl to 127.0.0.1,
    // loopback health probes) get the default context, which must hold a
    // valid cert or their handshake fails outright.
    getCredentials: () => ({ ...credentials }),
    // Notify listeners after every successful (re)load so servers can refresh
    // their default context via setSecureContext(). Returns an unsubscribe fn.
    onSwap: (fn) => {
      swapListeners.add(fn);
      return () => swapListeners.delete(fn);
    },
    reload,
    info: () => ({ ...info }),
    close: () => {
      closed = true;
      fs.unwatchFile(certFile, onFileChange);
      fs.unwatchFile(keyFile, onFileChange);
    },
  };
}
