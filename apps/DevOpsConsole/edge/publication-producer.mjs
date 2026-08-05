// Complete-snapshot producer for Console route/access mutations.
//
// The producer always starts from the edge's authenticated active envelope,
// resolves every route as one coherent inventory view, preserves a retained
// upstream while its runtime is temporarily unobservable, and submits exactly
// generation + 1 under the active payload CAS token.

import {
  canonicalJson,
  isUnavailableRouteUpstream,
  unavailableRouteUpstream,
  validatePublication,
} from './publication.mjs';

export class EdgePublicationProducerError extends Error {
  constructor(message, { code = 'edge_publication_failed', cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'EdgePublicationProducerError';
    this.code = code;
  }
}

function routeProtocol(route, prior, domain) {
  const scheme = route.upstreamScheme ?? prior?.scheme ?? 'http';
  if (!['http', 'https'].includes(scheme)) {
    throw new EdgePublicationProducerError(`route '${route.slug}' has an invalid upstream protocol`);
  }
  return scheme === 'http'
    ? { scheme: 'http', tls_server_name: null, tls_verify: true }
    : {
        scheme: 'https',
        tls_server_name: route.upstreamServerName ?? prior?.tls_server_name ?? `${route.slug}.${domain}`,
        tls_verify: route.upstreamTlsVerify ?? prior?.tls_verify ?? true,
      };
}

function sameProtocol(upstream, protocol) {
  return upstream?.scheme === protocol.scheme
    && upstream?.tls_server_name === protocol.tls_server_name
    && upstream?.tls_verify === protocol.tls_verify;
}

function routeUpstream(route, resolved, retained, domain) {
  const prior = retained?.instance_id === route.instanceId ? retained.upstream : null;
  const protocol = routeProtocol(route, prior, domain);
  if (!Number.isInteger(resolved?.port)) {
    if (prior && !isUnavailableRouteUpstream(prior) && sameProtocol(prior, protocol)) {
      return structuredClone(prior);
    }
    return unavailableRouteUpstream(protocol, `routes.${route.slug}.upstream`);
  }
  return { host: '127.0.0.1', port: resolved.port, ...protocol };
}

function stablePayload(publication) {
  const copy = structuredClone(publication);
  delete copy.generation;
  delete copy.published_at;
  return canonicalJson(copy);
}

export function createEdgePublicationProducer({
  client,
  config,
  coordinator,
  routeStore,
  upstreamAuthStore,
  accessStore,
  log,
} = {}) {
  if (!client?.describe || !client?.adopt) throw new TypeError('edge publication producer requires a client');
  if (!routeStore?.list || !routeStore?.resolve) throw new TypeError('edge publication producer requires a route store');
  if (!accessStore?.list) throw new TypeError('edge publication producer requires an access store');
  let chain = Promise.resolve();

  function serialize(operation) {
    const queued = chain.then(operation);
    // One failed local mutation or edge proposal must not poison the
    // serialization lane.  The original caller still observes the failure.
    chain = queued.then(() => undefined, () => undefined);
    return queued;
  }

  async function build(current) {
    if (current.maintenance.active) {
      throw new EdgePublicationProducerError(
        'control-plane maintenance is active; retry this mutation shortly',
        { code: 'edge_publication_maintenance' },
      );
    }
    let inventory = null;
    try {
      inventory = await coordinator.inventory({ maxAgeMs: 0 });
    } catch (error) {
      // Per-route retained targets make a transient observer/API failure safe.
      // A brand-new unresolved route is published in the explicit unavailable
      // state below, so it cannot be mistaken for a dialable target.
      log?.warn?.('edge publication inventory unavailable; using retained targets where exact identities match', {
        error: error?.message || String(error),
      });
    }
    const routes = {};
    for (const route of routeStore.list()) {
      let resolved;
      try {
        resolved = await routeStore.resolve(route.slug, coordinator, inventory);
      } catch (error) {
        resolved = { port: null, reason: error?.message || String(error) };
      }
      const retained = current.routes[route.slug];
      routes[route.slug] = {
        auth: route.auth,
        instance_id: route.instanceId,
        title: route.title || null,
        upstream: routeUpstream(route, resolved, retained, config.domain),
        upstream_authorization: route.auth === 'public'
          ? null
          : upstreamAuthStore?.authorizationFor(route.slug) ?? null,
      };
    }
    const owners = [];
    const grants = {};
    for (const identity of accessStore.list()) {
      if (identity.owner) owners.push(identity.email);
      else {
        grants[identity.email] = identity.grants
          .filter((grant) => grant === 'console' || grant.startsWith('route:'))
          .sort();
      }
    }
    return validatePublication({
      ...structuredClone(current),
      generation: current.generation + 1,
      published_at: new Date().toISOString(),
      routes,
      access: { owners: owners.sort(), grants },
    }, { releaseRoot: config.releaseRoot ?? '/opt/devcoordinator/releases' });
  }

  async function reconcileNow({ reason = 'state-change' } = {}) {
    // A release switch or authority maintenance transition can advance the
    // edge between describe and adopt.  Re-read once and rebuild from that
    // exact last-known-good generation instead of overwriting it or asking the
    // user to replay an already-persisted Console mutation.
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      const envelope = await client.describe();
      const candidate = await build(envelope.publication);
      if (stablePayload(candidate) === stablePayload(envelope.publication)) {
        return {
          ok: true,
          changed: false,
          generation: envelope.publication.generation,
          payload_sha256: envelope.payload_sha256,
        };
      }
      try {
        const adopted = await client.adopt(candidate, {
          expectedPayloadSha256: envelope.payload_sha256,
        });
        log?.info?.('edge publication reconciled', {
          reason,
          generation: adopted.generation,
          routes: Object.keys(candidate.routes).length,
        });
        return { ...adopted, changed: true };
      } catch (error) {
        if (attempt < 2 && error?.code === 'edge_publication_rejected') continue;
        throw error;
      }
    }
    throw new EdgePublicationProducerError('edge publication could not converge');
  }

  function reconcile(options) {
    return serialize(async () => {
      try {
        return await reconcileNow(options);
      } catch (error) {
        if (error instanceof EdgePublicationProducerError) throw error;
        throw new EdgePublicationProducerError(
          'the stable edge did not activate the saved Console state',
          { code: error?.code || 'edge_publication_failed', cause: error },
        );
      }
    });
  }

  // Route/access handlers use this boundary for the *complete* local
  // mutation.  It prevents another request from publishing an intermediate
  // rename/removal state and returns to the handler only after the exact
  // resulting snapshot is active at the stable edge.  Local persistence is
  // intentionally completed first; if the edge is temporarily unavailable,
  // the durable Console state is retained for a publication-only retry while
  // the edge continues serving its last-known-good snapshot.
  function mutate(operation, { reason = 'state-change' } = {}) {
    if (typeof operation !== 'function') {
      throw new TypeError('edge publication mutation requires one operation');
    }
    return serialize(async () => {
      const result = await operation();
      let publication;
      try {
        publication = await reconcileNow({ reason });
      } catch (error) {
        if (error instanceof EdgePublicationProducerError) throw error;
        throw new EdgePublicationProducerError(
          'the stable edge did not activate the saved Console state',
          { code: error?.code || 'edge_publication_failed', cause: error },
        );
      }
      return { result, publication };
    });
  }

  return { reconcile, mutate };
}
