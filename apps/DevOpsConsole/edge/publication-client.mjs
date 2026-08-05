// Bounded local Console -> stable-edge publication transport.
//
// The Console never writes the edge state directory.  It proposes a complete
// generation through the local Unix socket and acknowledges the
// corresponding user mutation only after the edge has validated, atomically
// persisted, and activated that exact generation.

import net from 'node:net';
import path from 'node:path';

import { validateEnvelope, validatePublication } from './publication.mjs';

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 5_000;

export class EdgePublicationClientError extends Error {
  constructor(message, { code = 'edge_publication_unavailable' } = {}) {
    super(message);
    this.name = 'EdgePublicationClientError';
    this.code = code;
  }
}

function validatedOptions({ socketPath, releaseRoot, timeoutMs }) {
  if (typeof socketPath !== 'string' || !path.isAbsolute(socketPath) || /[\0\r\n]/.test(socketPath)) {
    throw new TypeError('edge publication socket must be one absolute path');
  }
  if (typeof releaseRoot !== 'string' || !path.isAbsolute(releaseRoot)) {
    throw new TypeError('edge release root must be one absolute path');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    throw new TypeError('edge publication timeout must be 100-30000ms');
  }
  return { socketPath, releaseRoot, timeoutMs };
}

function exchange(options, request) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: options.socketPath });
    let body = '';
    let settled = false;
    const complete = (operation) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      operation();
    };
    const fail = (error) => complete(() => {
      socket.destroy();
      reject(error instanceof EdgePublicationClientError
        ? error
        : new EdgePublicationClientError(error?.message || String(error)));
    });
    const timer = setTimeout(() => fail(new EdgePublicationClientError('edge publication request timed out')), options.timeoutMs);
    timer.unref?.();
    socket.setEncoding('utf8');
    socket.once('connect', () => {
      socket.end(`${JSON.stringify(request)}\n`);
    });
    socket.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > MAX_RESPONSE_BYTES) {
        fail(new EdgePublicationClientError('edge publication response exceeded its byte bound'));
      }
    });
    socket.once('error', fail);
    socket.once('end', () => complete(() => {
      let response;
      try {
        response = JSON.parse(body);
      } catch {
        reject(new EdgePublicationClientError('edge publication response was invalid JSON'));
        return;
      }
      if (!response || response.ok !== true) {
        reject(new EdgePublicationClientError(
          typeof response?.error === 'string' ? response.error : 'edge rejected the publication request',
          { code: 'edge_publication_rejected' },
        ));
        return;
      }
      resolve(response);
    }));
  });
}

export function createEdgePublicationClient({
  socketPath = '/run/devcoordinator-edge-publication/publish.sock',
  releaseRoot = '/opt/devcoordinator/releases',
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const options = validatedOptions({ socketPath, releaseRoot, timeoutMs });

  async function describe() {
    const response = await exchange(options, {
      schema_version: 1,
      operation: 'describe',
    });
    const envelope = validateEnvelope(response.envelope, { releaseRoot: options.releaseRoot });
    return structuredClone(envelope);
  }

  async function adopt(publicationInput, { expectedPayloadSha256 } = {}) {
    if (typeof expectedPayloadSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(expectedPayloadSha256)) {
      throw new TypeError('edge publication CAS token must be one SHA-256 digest');
    }
    const publication = validatePublication(publicationInput, { releaseRoot: options.releaseRoot });
    const response = await exchange(options, {
      schema_version: 1,
      operation: 'adopt',
      expected_payload_sha256: expectedPayloadSha256,
      publication,
    });
    if (
      !Number.isSafeInteger(response.generation)
      || response.generation !== publication.generation
      || typeof response.payload_sha256 !== 'string'
      || !/^[a-f0-9]{64}$/.test(response.payload_sha256)
    ) throw new EdgePublicationClientError('edge adoption acknowledgement is invalid');
    return response;
  }

  return { describe, adopt };
}
