/* DevOps Console control panel.
 * Vanilla JS, no dependencies. Talks only to same-origin /api/*.
 * Hash-routed pages (#/projects, #/tests, #/efficiency, #/bugs, #/servers, #/routes, #/docker, #/ports,
 * #/performance, #/access, #/invites, #/telegram)
 * share one sticky status bar. Polls GET /api/overview every 6s and
 * GET /api/metrics/history every 10s (both paused while the tab is hidden),
 * and refetches immediately after every mutation. All user data goes through
 * textContent — never innerHTML; charts are built with createElementNS. */
(() => {
  'use strict';

  const POLL_MS = 6000;
  const METRICS_POLL_MS = 10_000;
  const TESTS_POLL_MS = 5000;
  const METRICS_LIMIT_SPARK = 90; // row sparkline window (~15 min at 10s sampling)
  const METRICS_LIMIT_FULL = 360; // performance-page window (~1 h at 10s)
  const RESOURCE_PAGE_SIZE = 75;  // bound selectable DOM for host-wide inventories
  const RESERVED_SLUGS = new Set(['console', 'www', 'api', 'auth', 'static', 'healthz']);
  const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

  // ---------------------------------------------------------------- state

  const state = {
    overview: null,      // last successful GET /api/overview payload
    session: null,       // GET /api/session payload
    stale: false,        // last poll failed but older data is shown
    lastFetch: 0,
    metrics: null,       // last GET /api/metrics/history payload
    metricsMap: new Map(), // entity key ('srv:<id>'|'dock:<name>'|'proj:<key>') -> entity
    metricsAt: 0,
    prefs: null,         // GET /api/prefs payload ({ hidden: { servers, docker, projects } })
    access: null,        // owner-only GET /api/access payload ({ users, resources })
    invites: null,       // owner-only GET /api/access/requests payload
    telegram: null,      // GET /api/telegram payload for bots manageable by this account
    bugs: null,          // independent open-only Coordinator bug registry
    bugsError: null,     // local retained/cold error; never promoted to the global banner
    bugsErrorContext: null, // refresh or close, for truthful retained-state copy
    bugsLoading: false,
    bugsClosing: new Set(),
    bugsTransferBusy: false,
    efficiency: null,    // independent optional delivery-efficiency projection
    efficiencyError: null,
    efficiencyLoading: false,
    archives: null,      // owner-only GET /api/lifecycle/list ({ archives })
    testsRepositories: null, // lightweight configured repository catalog
    testsProject: null,
    testsLoading: false,
    testsRenderSignature: null,
    testsError: null,
    testsRuns: null,
    testsRunsLoading: false,
    testsRunsError: null,
    testsRunEvidence: new Map(),
    testsPlan: null,
    testsPlanOperationId: null,
    testsRunTargetSetup: null,
    testsRunTargetLoading: false,
    testsRunTargetError: null,
    testsRunTargetRequest: 0,
    testsRunSourceCatalog: null,
    testsRunSourceLoading: false,
    testsRunSourceError: null,
    testsRunSourceRequest: 0,
    testsRunSourceSelections: new Map(),
  };

  const ui = {
    expanded: new Set(),   // server ids with open detail panels
    dockerOpen: new Set(), // container names with open log panels
    logs: new Map(),       // 'srv:<id>' | 'dock:<name>' -> {loading,text,error,at}
    busy: new Set(),       // action keys currently in flight
    reveal: new Set(),     // pages currently showing their hidden items
    treeExpanded: new Set(), // repository-family IDs explicitly expanded on the Projects page
    temporaryScopesExpanded: new Set(), // one nested temporary repo disclosure at a time
    projectScopePages: new Map(), // bounded member page per disclosed root/temporary repo scope
    serverGroupsExpanded: new Set(), // transient Servers-page project disclosure (at most one)
    dockerGroupsExpanded: new Set(), // transient Docker-page project disclosure (at most one)
    resourcePages: { projects: 0, servers: 0, docker: 0 }, // zero-based page per large collection
    lifecycleViews: { projects: 'active', servers: 'active', docker: 'active' },
    archiveGroupsExpanded: { projects: new Set(), servers: new Set(), docker: new Set() },
    performanceProjectKey: null, // stable segment key selected in the Performance legend
    performanceProjectRecord: null, // retained detail while a fresh sample is incomplete
    performanceReturnFocus: null, // exact legend button when it survives a refresh
    performanceReturnFocusMetric: null, // fallback legend when the button is rebuilt
    // Native <details> are rebuilt as inventory observations refresh. Retain
    // their user-selected state outside the DOM so an opaque host-resource ID
    // changing during a fresh observation cannot close evidence being read.
    sectionDisclosures: new Map(),
    lifecycleDialog: null, // { action, target, stage, plan, returnFocusKey }
    lifecycleFocus: null,  // target revealed after a successful archive/restore/purge
    bugFocusAfterClose: null, // logical row to focus after an exact report disappears
    bugTransferReturnFocus: null,
    efficiencyRepositoryId: null,
    efficiencyReturnFocus: null,
    version: 0,            // bumped on any ui-state change to invalidate sigs
  };
  const bump = () => { ui.version += 1; };

  const sigs = Object.create(null);

  // ---------------------------------------------------------------- DOM helpers

  const $ = (sel, root = document) => root.querySelector(sel);

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else if (v === true) el.setAttribute(k, '');
        else el.setAttribute(k, String(v));
      }
    }
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  // Static icon markup only — constant strings, never user data.
  const ICONS = {
    chevron: '<svg viewBox="0 0 16 16" width="14" height="14"><path d="M6 4l4 4-4 4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    copy: '<svg viewBox="0 0 16 16" width="14" height="14"><rect x="5.5" y="5.5" width="8" height="8" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M10.5 3.5h-6a1 1 0 0 0-1 1v6" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>',
    check: '<svg viewBox="0 0 16 16" width="14" height="14"><path d="M3 8.5l3.2 3L13 5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    trash: '<svg viewBox="0 0 16 16" width="14" height="14"><path d="M3 4.5h10M6.4 4.5V3.4a1 1 0 0 1 1-1h1.2a1 1 0 0 1 1 1v1.1M5 4.5l.6 8.1a1 1 0 0 0 1 .9h2.8a1 1 0 0 0 1-.9l.6-8.1" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    warn: '<svg viewBox="0 0 16 16" width="15" height="15"><path d="M8 2.2 14.6 13.4H1.4Z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/><path d="M8 6.4v3.1" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/><circle cx="8" cy="11.6" r=".9" fill="currentColor"/></svg>',
    refresh: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M13 8a5 5 0 1 1-1.4-3.5M13 2.6v2.7h-2.7" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    x: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
    play: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M5.5 3.5v9l7-4.5z" fill="currentColor"/></svg>',
    stop: '<svg viewBox="0 0 16 16" width="13" height="13"><rect x="4.5" y="4.5" width="7" height="7" rx="1" fill="currentColor"/></svg>',
    link: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M6.5 9.5l3-3M7 4.5l1-1a2.1 2.1 0 0 1 3 3l-1 1M9 11.5l-1 1a2.1 2.1 0 0 1-3-3l1-1" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    edit: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M11.2 3.3l1.5 1.5-7 7-2 .5.5-2z" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/></svg>',
    plus: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M8 3.5v9M3.5 8h9" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
    clock: '<svg viewBox="0 0 16 16" width="13" height="13"><circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M8 4.8v3.5l2.4 1.4" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    eyeoff: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M2 8s2.2-3.8 6-3.8S14 8 14 8s-2.2 3.8-6 3.8S2 8 2 8Z" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="8" cy="8" r="1.7" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M3 13 13 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>',
    eye: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M2 8s2.2-3.8 6-3.8S14 8 14 8s-2.2 3.8-6 3.8S2 8 2 8Z" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="8" cy="8" r="1.7" fill="none" stroke="currentColor" stroke-width="1.3"/></svg>',
    archive: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M2.5 4.5h11v8.2a.8.8 0 0 1-.8.8H3.3a.8.8 0 0 1-.8-.8Z" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M2 2.5h12v2H2zM6 7.5h4" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>',
    server: '<svg viewBox="0 0 16 16" width="16" height="16"><rect x="2.5" y="2.5" width="11" height="4.5" rx="1" fill="none" stroke="currentColor" stroke-width="1.3"/><rect x="2.5" y="9" width="11" height="4.5" rx="1" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="5" cy="4.75" r=".75" fill="currentColor"/><circle cx="5" cy="11.25" r=".75" fill="currentColor"/><path d="M8 4.75h3M8 11.25h3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>',
    worker: '<svg viewBox="0 0 16 16" width="16" height="16"><circle cx="8" cy="8" r="2.25" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M8 2.2v1.4M8 12.4v1.4M2.2 8h1.4M12.4 8h1.4M3.9 3.9l1 1M11.1 11.1l1 1M12.1 3.9l-1 1M4.9 11.1l-1 1" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>',
    container: '<svg viewBox="0 0 16 16" width="16" height="16"><path d="m8 2.2 5 2.7v6.2L8 13.8l-5-2.7V4.9Z" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/><path d="m3.3 5 4.7 2.6L12.7 5M8 7.6v5.8" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/></svg>',
    database: '<svg viewBox="0 0 16 16" width="16" height="16"><ellipse cx="8" cy="3.8" rx="5" ry="2.1" fill="none" stroke="currentColor" stroke-width="1.25"/><path d="M3 3.8v4.1C3 9.1 5.2 10 8 10s5-.9 5-2.1V3.8M3 7.9V12c0 1.2 2.2 2.1 5 2.1s5-.9 5-2.1V7.9" fill="none" stroke="currentColor" stroke-width="1.25"/></svg>',
    temporary: '<svg viewBox="0 0 16 16" width="16" height="16"><path d="M2.7 4.3h4l1.2 1.4h5.4v7.1a1 1 0 0 1-1 1H3.7a1 1 0 0 1-1-1Z" fill="none" stroke="currentColor" stroke-width="1.25" stroke-linejoin="round"/><circle cx="11.2" cy="5" r="3" fill="var(--bg, #111820)" stroke="currentColor" stroke-width="1.2"/><path d="M11.2 3.4v1.8l1.1.7" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  };

  function icon(name) {
    const span = document.createElement('span');
    span.className = `icon i-${name}`;
    span.setAttribute('aria-hidden', 'true');
    span.innerHTML = ICONS[name] || '';
    return span;
  }

  // ---------------------------------------------------------------- formatting

  const sfx = (n) => (n === 1 ? '' : 's');

  function projectTail(p) {
    if (!p) return '—';
    const parts = String(p).split('/').filter(Boolean);
    return parts[parts.length - 1] || p;
  }

  function fmtBytes(n) {
    if (!Number.isFinite(n) || n <= 0) return '0 B';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
  }

  function fmtClock(ms) {
    return new Date(ms).toLocaleTimeString([], { hour12: false });
  }

  function fmtSeconds(value) {
    const seconds = Number(value);
    if (!Number.isFinite(seconds)) return '—';
    if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
    if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 2 : 1)} s`;
    const minutes = Math.floor(seconds / 60);
    return `${minutes}m ${Math.round(seconds % 60)}s`;
  }

  function fmtIntegerString(value) {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) return 'Unknown';
    try { return BigInt(value).toLocaleString(); } catch { return 'Unknown'; }
  }

  // Accepts an ISO string, epoch-ms number, or epoch-seconds float.
  function fmtWhen(value) {
    if (value === null || value === undefined || value === '') return '—';
    let t;
    if (typeof value === 'number') t = value > 1e12 ? value : value * 1000;
    else t = Date.parse(value);
    if (Number.isNaN(t)) return String(value);
    return `${new Date(t).toLocaleString()} (${timeAgo(t)})`;
  }

  function timeAgo(ms) {
    const d = Math.max(0, Date.now() - ms);
    if (d < 60_000) return `${Math.floor(d / 1000)}s ago`;
    if (d < 3_600_000) return `${Math.floor(d / 60_000)}m ago`;
    if (d < 86_400_000) return `${Math.floor(d / 3_600_000)}h ago`;
    return `${Math.floor(d / 86_400_000)}d ago`;
  }

  function countdownText(epochSec) {
    const diff = epochSec - Date.now() / 1000;
    if (diff <= 0) return 'expired';
    const s = Math.floor(diff % 60);
    const m = Math.floor((diff / 60) % 60);
    const hs = Math.floor((diff / 3600) % 24);
    const d = Math.floor(diff / 86400);
    if (diff < 600) return `${m}m ${s}s`;
    if (diff < 86400) return `${hs}h ${m}m`;
    return `${d}d ${hs}h`;
  }

  // ---------------------------------------------------------------- API client

  class ApiError extends Error {
    constructor(message, status, data = null) {
      super(message);
      this.status = status;
      this.data = data;
      const evidence = data?.evidence && typeof data.evidence === 'object'
        ? data.evidence
        : null;
      this.code = typeof data?.code === 'string'
        ? data.code
        : typeof evidence?.code === 'string' ? evidence.code : null;
      this.classification = typeof data?.classification === 'string'
        ? data.classification
        : typeof evidence?.classification === 'string' ? evidence.classification
        : null;
      const retryAfter = Number(
        data?.retryAfterSeconds
        ?? data?.retry_after_seconds
        ?? evidence?.retryAfterSeconds
        ?? evidence?.retry_after_seconds,
      );
      this.retryAfterSeconds = Number.isFinite(retryAfter)
        ? retryAfter
        : null;
    }
  }

  async function api(path, { method = 'GET', body } = {}) {
    let res;
    try {
      res = await fetch(path, {
        method,
        credentials: 'same-origin',
        headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (err) {
      throw new ApiError(`Network error: ${err.message}`, 0);
    }
    if (res.status === 401) {
      // Session expired — the server will bounce us through login.
      location.reload();
      throw new ApiError('Session expired — reloading', 401);
    }
    let data = null;
    try { data = await res.json(); } catch { /* non-JSON error body */ }
    if (!res.ok) {
      const msg = data && typeof data.error === 'string' && data.error
        ? data.error
        : `HTTP ${res.status} ${res.statusText}`;
      throw new ApiError(msg, res.status, data);
    }
    return data;
  }

  // ---------------------------------------------------------------- error banner

  let bannerKey = null;

  function isMaintenanceError(value) {
    return value?.classification === 'maintenance' || value?.code === 'maintenance_in_progress';
  }

  function isEdgePublicationError(value) {
    return value?.classification === 'edge_publication'
      || (typeof value?.code === 'string' && value.code.startsWith('edge_publication_'));
  }

  function renderLocalPublicationError(element, value, { onActivated } = {}) {
    const message = value?.message ?? String(value);
    const retry = h('button', { class: 'btn small', type: 'button' }, 'Activate now');
    retry.addEventListener('click', async () => {
      retry.disabled = true;
      retry.textContent = 'Activating…';
      try {
        await api('/api/edge-publication/reconcile', { method: 'POST' });
        element.remove();
        announce('Public routes updated');
        await onActivated?.();
      } catch (error) {
        retry.disabled = false;
        retry.textContent = 'Try again';
        const copy = element.querySelector('.local-publication-copy');
        if (copy) copy.textContent = error?.message ?? String(error);
      }
    });
    element.classList.add('local-publication-error');
    element.setAttribute('role', 'alert');
    element.replaceChildren(
      h('span', { class: 'local-publication-copy' }, message),
      retry,
    );
    element.hidden = false;
  }

  function showSectionPublicationError(bodyId, value, onActivated) {
    const body = document.getElementById(bodyId);
    if (!body) return;
    body.querySelector('.local-publication-error')?.remove();
    const local = h('div', { class: 'form-error local-publication-error' });
    body.prepend(local);
    renderLocalPublicationError(local, value, { onActivated });
  }

  function showBanner(value, retry, key = 'action') {
    const maintenance = isMaintenanceError(value);
    if (maintenance || isEdgePublicationError(value)) {
      // Planned maintenance and background refreshes are not decisions the
      // user can act on globally. Publication failures belong beside the
      // route/access control that caused them; the edge keeps serving its
      // last-known-good snapshot.
      if (maintenance) clearBanner('maintenance');
      return;
    }
    const message = value?.message ?? String(value);
    bannerKey = key;
    $('#banner-slot').replaceChildren(
      h('div', {
        class: 'banner',
        role: 'alert',
      },
        icon('warn'),
        h('span', { class: 'banner-msg' }, String(message)),
        retry ? h('button', {
          class: 'btn small', type: 'button',
          onclick: () => { clearBanner(); retry(); },
        }, 'Retry') : null,
        h('button', {
          class: 'iconbtn', type: 'button',
          'aria-label': 'Dismiss error', title: 'Dismiss',
          onclick: () => clearBanner(),
        }, icon('x'))),
    );
  }

  function clearBanner(onlyKey) {
    if (onlyKey && bannerKey !== onlyKey) return;
    bannerKey = null;
    $('#banner-slot').replaceChildren();
  }

  function announce(msg) {
    const live = $('#live');
    live.textContent = msg;
    setTimeout(() => { if (live.textContent === msg) live.textContent = ''; }, 1800);
  }

  // ---------------------------------------------------------------- popover

  const popEl = $('#popover');
  const popover = {
    key: null,
    anchor: null,
    pending: false,
    toggle(key, anchor, build) {
      if (this.key === key) { this.close(); return; }
      this.close(); // may trigger a deferred re-render that replaces the anchor
      let a = anchor;
      if (!a.isConnected && a.dataset?.fk) {
        a = document.querySelector(`[data-fk="${CSS.escape(a.dataset.fk)}"]`) || a;
      }
      popEl.replaceChildren(build());
      popEl.hidden = false;
      this.key = key;
      this.anchor = a;
      a.setAttribute('aria-expanded', 'true');
      this.position();
      popEl.focus({ preventScroll: true });
    },
    position() {
      if (!this.anchor?.isConnected) return;
      const r = this.anchor.getBoundingClientRect();
      const w = popEl.offsetWidth;
      const hgt = popEl.offsetHeight;
      let left = Math.min(Math.max(12, r.left), window.innerWidth - w - 12);
      let top = r.bottom + 8;
      if (top + hgt > window.innerHeight - 12) top = Math.max(12, r.top - hgt - 8);
      popEl.style.left = `${Math.round(left)}px`;
      popEl.style.top = `${Math.round(top)}px`;
    },
    close() {
      if (this.key === null) return;
      const anchor = this.anchor;
      const fk = anchor?.dataset?.fk;
      this.key = null;
      this.anchor = null;
      popEl.hidden = true;
      popEl.replaceChildren();
      if (anchor?.isConnected) {
        anchor.setAttribute('aria-expanded', 'false');
        anchor.focus({ preventScroll: true });
      } else if (fk) {
        const again = document.querySelector(`[data-fk="${CSS.escape(fk)}"]`);
        if (again) { again.setAttribute('aria-expanded', 'false'); again.focus({ preventScroll: true }); }
      }
      if (this.pending) { this.pending = false; renderAll(); }
    },
  };

  document.addEventListener('pointerdown', (e) => {
    if (popover.key === null) return;
    if (popEl.contains(e.target)) return;
    if (popover.anchor && (e.target === popover.anchor || popover.anchor.contains(e.target))) return;
    popover.close();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') popover.close();
  });
  window.addEventListener('resize', () => popover.close());
  document.addEventListener('scroll', (e) => {
    if (popover.key !== null && !popEl.contains(e.target)) popover.close();
  }, true);

  // Resource-kind icons replace repetitive text badges in the Projects tree.
  // Their explanation remains available without spending permanent row width:
  // hover/focus is transient, while click/touch pins the same tooltip.
  const PROJECT_RESOURCE_KINDS = Object.freeze({
    server: Object.freeze({
      icon: 'server', css: 'k-srv', label: 'Server',
      hint: 'A host process registered to this repository.',
    }),
    worker: Object.freeze({
      icon: 'worker', css: 'k-worker', label: 'Worker',
      hint: 'A supervised host process that the Coordinator can keep alive.',
    }),
    container: Object.freeze({
      icon: 'container', css: 'k-dock', label: 'Container',
      hint: 'A Docker container attributed to this repository.',
    }),
    database: Object.freeze({
      icon: 'database', css: 'k-db', label: 'Database',
      hint: 'A database service running in an attributed Docker container.',
    }),
    temporary: Object.freeze({
      icon: 'temporary', css: 'k-temp', label: 'Temporary repository',
      hint: 'An isolated repository scope with its own expiry and cleanup policy.',
    }),
  });

  const resourceKindTooltipEl = $('#resource-kind-tooltip');
  let activeResourceKindTooltipKey = null;
  let pinnedResourceKindTooltipKey = null;
  let resourceKindTooltipFrame = null;

  function resourceKindTooltipTarget(key) {
    if (!key) return null;
    return document.querySelector(`[data-fk="${CSS.escape(key)}"]`);
  }

  function positionResourceKindTooltip(target) {
    if (!target?.isConnected || resourceKindTooltipEl.hidden) return;
    // Keep the measurement position inside the viewport. Browser automation
    // (and assistive focus changes) can observe geometry between style/layout
    // updates; briefly placing the tooltip at 0,0 made an otherwise correctly
    // clamped hint appear flush with the viewport edge on narrow screens.
    const margin = 8;
    resourceKindTooltipEl.style.visibility = 'hidden';
    resourceKindTooltipEl.style.left = `${margin}px`;
    resourceKindTooltipEl.style.top = `${margin}px`;
    const targetRect = target.getBoundingClientRect();
    const tooltipRect = resourceKindTooltipEl.getBoundingClientRect();
    const gap = 7;
    const maxLeft = Math.max(margin, window.innerWidth - tooltipRect.width - margin);
    const left = Math.min(
      maxLeft,
      Math.max(margin, targetRect.left + (targetRect.width / 2) - (tooltipRect.width / 2)),
    );
    let top = targetRect.top - tooltipRect.height - gap;
    if (top < margin) top = targetRect.bottom + gap;
    const maxTop = Math.max(margin, window.innerHeight - tooltipRect.height - margin);
    top = Math.min(maxTop, Math.max(margin, top));
    resourceKindTooltipEl.style.left = `${Math.round(left)}px`;
    resourceKindTooltipEl.style.top = `${Math.round(top)}px`;
    resourceKindTooltipEl.style.visibility = '';
  }

  function showResourceKindTooltip(target) {
    if (!target?.isConnected) return;
    const key = target.dataset.fk;
    if (!key || (pinnedResourceKindTooltipKey && pinnedResourceKindTooltipKey !== key)) return;
    activeResourceKindTooltipKey = key;
    target.setAttribute('aria-pressed', String(pinnedResourceKindTooltipKey === key));
    resourceKindTooltipEl.replaceChildren(
      h('strong', { class: 'resource-kind-tooltip-label' }, target.dataset.kindLabel || ''),
      h('span', { class: 'resource-kind-tooltip-copy' }, target.dataset.kindHint || ''),
    );
    resourceKindTooltipEl.hidden = false;
    positionResourceKindTooltip(target);
  }

  function hideResourceKindTooltip(key = null, force = false) {
    if (key && activeResourceKindTooltipKey !== key) return;
    if (!force && pinnedResourceKindTooltipKey) return;
    if (force && pinnedResourceKindTooltipKey) {
      resourceKindTooltipTarget(pinnedResourceKindTooltipKey)?.setAttribute('aria-pressed', 'false');
      pinnedResourceKindTooltipKey = null;
    }
    activeResourceKindTooltipKey = null;
    resourceKindTooltipEl.hidden = true;
  }

  function togglePinnedResourceKindTooltip(target) {
    const key = target.dataset.fk;
    if (pinnedResourceKindTooltipKey === key) {
      target.setAttribute('aria-pressed', 'false');
      pinnedResourceKindTooltipKey = null;
      hideResourceKindTooltip(null, true);
      return;
    }
    resourceKindTooltipTarget(pinnedResourceKindTooltipKey)?.setAttribute('aria-pressed', 'false');
    pinnedResourceKindTooltipKey = key;
    target.setAttribute('aria-pressed', 'true');
    showResourceKindTooltip(target);
  }

  function refreshResourceKindTooltip() {
    const key = pinnedResourceKindTooltipKey || activeResourceKindTooltipKey;
    if (!key) return;
    const target = resourceKindTooltipTarget(key);
    if (!target) {
      hideResourceKindTooltip(null, true);
      return;
    }
    showResourceKindTooltip(target);
  }

  function scheduleResourceKindTooltipRefresh() {
    if (resourceKindTooltipFrame !== null) return;
    resourceKindTooltipFrame = window.requestAnimationFrame(() => {
      resourceKindTooltipFrame = null;
      refreshResourceKindTooltip();
    });
  }

  function projectResourceKindTrigger(kind, stableKey) {
    const meta = PROJECT_RESOURCE_KINDS[kind];
    const fk = `tree-kind:${kind}:${String(stableKey ?? '')}`;
    const trigger = h('button', {
      class: `resource-kind-trigger kind-icon-button ${meta.css}`,
      type: 'button',
      'data-fk': fk,
      'data-resource-kind': kind,
      'data-kind-label': meta.label,
      'data-kind-hint': meta.hint,
      'aria-label': `${meta.label}: ${meta.hint}`,
      'aria-describedby': 'resource-kind-tooltip',
      'aria-pressed': String(pinnedResourceKindTooltipKey === fk),
      onclick: (event) => {
        event.stopPropagation();
        togglePinnedResourceKindTooltip(trigger);
      },
      onpointerenter: () => showResourceKindTooltip(trigger),
      onpointerleave: () => {
        if (document.activeElement !== trigger) hideResourceKindTooltip(fk);
      },
      onfocus: () => showResourceKindTooltip(trigger),
      onblur: () => {
        if (!trigger.matches(':hover')) hideResourceKindTooltip(fk);
      },
    }, icon(meta.icon), h('span', { class: 'visually-hidden' }, meta.label));
    return trigger;
  }

  document.addEventListener('pointerdown', (event) => {
    if (!pinnedResourceKindTooltipKey) return;
    const target = resourceKindTooltipTarget(pinnedResourceKindTooltipKey);
    if (target?.contains(event.target) || resourceKindTooltipEl.contains(event.target)) return;
    hideResourceKindTooltip(null, true);
  }, true);
  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape' || !activeResourceKindTooltipKey) return;
    event.preventDefault();
    hideResourceKindTooltip(null, true);
  });
  window.addEventListener('resize', scheduleResourceKindTooltipRefresh);
  document.addEventListener('scroll', scheduleResourceKindTooltipRefresh, true);

  function popHead(title) {
    return h('div', { class: 'pop-head' },
      h('span', { class: 'pop-title' }, title),
      h('button', {
        class: 'iconbtn', type: 'button', 'aria-label': 'Close details', title: 'Close',
        onclick: () => popover.close(),
      }, icon('x')));
  }

  function kv(label, value, { mono = false } = {}) {
    return h('div', { class: 'kv' },
      h('span', { class: 'k' }, label),
      h('span', { class: `v${mono ? ' mono' : ''}` }, value ?? '—'));
  }

  // ---------------------------------------------------------------- pages & nav

  const PAGES = [
    { id: 'projects', title: 'Projects' },
    { id: 'tests', title: 'Tests' },
    { id: 'efficiency', title: 'Efficiency' },
    { id: 'bugs', title: 'Bugs' },
    { id: 'servers', title: 'Servers' },
    { id: 'routes', title: 'Routes' },
    { id: 'docker', title: 'Docker' },
    { id: 'ports', title: 'Port leases' },
    { id: 'performance', title: 'Performance' },
    { id: 'access', title: 'Access' },
    { id: 'invites', title: 'Invites' },
    { id: 'telegram', title: 'Telegram' },
  ];

  function currentPage() {
    const m = /^#\/([a-z-]+)/.exec(location.hash || '');
    const id = m ? m[1] : '';
    if (!PAGES.some((p) => p.id === id)) return 'projects';
    if (id === 'efficiency' && state.efficiency?.available === false) return 'projects';
    if ((id === 'access' || id === 'invites') && state.session?.accessAdmin !== true) return 'projects';
    return id;
  }

  const navOpen = () => $('#site-nav').classList.contains('open');

  function setNavOpen(open) {
    $('#site-nav').classList.toggle('open', open);
    const btn = $('#nav-toggle');
    btn.setAttribute('aria-expanded', String(open));
    btn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  }

  function applyPage() {
    const page = currentPage();
    if (page === 'bugs') {
      clearBanner('maintenance');
      clearBanner('overview');
    }
    if (page !== 'tests' && $('#test-detail-dialog')?.open) closeTestDetail();
    if (page !== 'efficiency' && $('#efficiency-detail-dialog')?.open) {
      closeEfficiencyDetail({ restoreFocus: false });
    }
    if (page !== 'bugs') {
      closeBugTransfer('export', { restoreFocus: false });
      closeBugTransfer('import', { restoreFocus: false });
    }
    if (page !== 'performance' && $('#perf-project-dialog')?.open) {
      closePerformanceProject({ restoreFocus: false });
    }
    for (const sec of document.querySelectorAll('#main [data-page]')) {
      sec.hidden = sec.dataset.page !== page;
    }
    for (const a of document.querySelectorAll('#site-nav a')) {
      if (a.dataset.nav === page) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    document.title = `${PAGES.find((p) => p.id === page).title} — DevOps Console`;
    setNavOpen(false);
    popover.close();
    // Hash navigation changes which dynamic body is allowed to stay mounted.
    // Rebuild immediately from the latest overview instead of waiting for the
    // next six-second poll.
    if (state.overview || page === 'bugs' || page === 'efficiency') renderAll(true);
    // The performance page charts use a longer history window than sparklines.
    if (page === 'performance') refreshMetrics();
    if (page === 'tests') {
      loadTests({ force: true });
    }
    if (page === 'bugs') loadBugs();
    if (page === 'efficiency') loadEfficiency();
    if (page === 'access' && state.session?.accessAdmin === true) loadAccess();
    if (page === 'invites' && state.session?.accessAdmin === true) loadInvites();
    if (page === 'telegram' && state.session?.email) loadTelegram();
  }

  function wireNav() {
    $('#nav-toggle').addEventListener('click', () => setNavOpen(!navOpen()));
    $('#tests-run').addEventListener('click', () => openTestRunDialog());
    $('#bugs-refresh').addEventListener('click', () => loadBugs({ force: true }));
    $('#efficiency-refresh').addEventListener('click', () => loadEfficiency({ force: true }));
    $('#efficiency-detail-close').append(icon('x'));
    $('#efficiency-detail-close').addEventListener('click', () => closeEfficiencyDetail());
    $('#efficiency-detail-dialog').addEventListener('cancel', (event) => {
      event.preventDefault();
      closeEfficiencyDetail();
    });
    $('#bugs-export').addEventListener('click', openBugExport);
    $('#bugs-import').addEventListener('click', openBugImport);
    $('#bugs-export-close').append(icon('x'));
    $('#bugs-export-close').addEventListener('click', () => closeBugTransfer('export'));
    $('#bugs-export-cancel').addEventListener('click', () => closeBugTransfer('export'));
    $('#bugs-export-copy').addEventListener('click', copyBugExport);
    $('#bugs-export-dialog').addEventListener('cancel', (event) => {
      event.preventDefault();
      closeBugTransfer('export');
    });
    $('#bugs-import-close').append(icon('x'));
    $('#bugs-import-close').addEventListener('click', () => closeBugTransfer('import'));
    $('#bugs-import-cancel').addEventListener('click', () => closeBugTransfer('import'));
    $('#bugs-import-form').addEventListener('submit', (event) => {
      event.preventDefault();
      importBugs();
    });
    $('#bugs-import-dialog').addEventListener('cancel', (event) => {
      event.preventDefault();
      closeBugTransfer('import');
    });
    $('#test-detail-close').append(icon('x'));
    $('#test-detail-close').addEventListener('click', closeTestDetail);
    $('#test-detail-dialog').addEventListener('cancel', (event) => {
      event.preventDefault();
      closeTestDetail();
    });
    $('#perf-project-dialog-close').append(icon('x'));
    $('#perf-project-dialog-close').addEventListener('click', () => closePerformanceProject());
    $('#perf-project-dialog').addEventListener('cancel', (event) => {
      event.preventDefault();
      closePerformanceProject();
    });
    window.addEventListener('resize', positionTestDetail, { passive: true });
    testDetailNarrowViewport.addEventListener('change', syncTestDetailSurface);
    window.addEventListener('keydown', (event) => {
      const dialog = $('#test-detail-dialog');
      if (event.key !== 'Escape' || !dialog.open || dialog.matches(':modal')) return;
      event.preventDefault();
      closeTestDetail();
    });
    $('#test-detail-run').addEventListener('click', () => openTestRunDialog(state.testsProject));
    $('#test-run-close').append(icon('x'));
    $('#test-run-close').addEventListener('click', closeTestRunDialog);
    $('#test-run-cancel').addEventListener('click', closeTestRunDialog);
    $('#test-run-dialog').addEventListener('cancel', (event) => {
      event.preventDefault();
      closeTestRunDialog();
    });
    $('#test-run-preview-button').addEventListener('click', previewTestRun);
    $('#test-run-project').addEventListener('change', () => {
      resetTestRunPreview();
      const repoId = $('#test-run-project').value;
      state.testsRunTargetSetup = null;
      state.testsRunTargetError = null;
      state.testsRunSourceCatalog = null;
      state.testsRunSourceError = null;
      loadTestRunTargets(repoId);
      loadTestRunSources(repoId);
    });
    $('#test-run-source').addEventListener('change', () => {
      const source = selectedTestRunSource();
      if (source) state.testsRunSourceSelections.set($('#test-run-project').value, sourceKey(source.selector));
      resetTestRunPreview();
    });
    $('#test-run-intent').addEventListener('change', () => {
      resetTestRunPreview();
      updateTestRunTargetField();
      if ($('#test-run-intent').value === 'manual') {
        loadTestRunTargets($('#test-run-project').value);
      }
    });
    $('#test-run-form').addEventListener('submit', (event) => {
      event.preventDefault();
      submitTestRun();
    });
    window.addEventListener('hashchange', applyPage);
    document.addEventListener('pointerdown', (e) => {
      if (!navOpen()) return;
      if (e.target.closest('#site-nav') || e.target.closest('#nav-toggle')) return;
      setNavOpen(false);
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && navOpen()) setNavOpen(false);
    });
  }

  // ---------------------------------------------------------------- open Coordinator bugs

  function efficiencyAvailable() {
    return state.efficiency?.available === true;
  }

  function syncEfficiencyVisibility() {
    const available = efficiencyAvailable();
    $('#nav-efficiency').hidden = !available;
    if (!available && /^#\/efficiency(?:$|[/?])/.test(location.hash || '')) {
      location.hash = '#/projects';
    }
  }

  async function loadEfficiency({ force = false } = {}) {
    if (state.efficiencyLoading && !force) return;
    state.efficiencyLoading = true;
    if (currentPage() === 'efficiency') renderEfficiency(true);
    try {
      const payload = await api('/api/efficiency');
      if (!payload || payload.schema_version !== 1 || typeof payload.available !== 'boolean'
        || !Array.isArray(payload.repositories)) {
        throw new ApiError('Efficiency response is invalid', 502);
      }
      state.efficiency = payload;
      state.efficiencyError = null;
      syncEfficiencyVisibility();
      if (currentPage() === 'efficiency') renderEfficiency(true);
    } catch (error) {
      state.efficiencyError = error;
      if (!state.efficiency) syncEfficiencyVisibility();
      if (currentPage() === 'efficiency') renderEfficiency(true);
    } finally {
      state.efficiencyLoading = false;
      if (currentPage() === 'efficiency') renderEfficiency(true);
    }
  }

  function efficiencyKnown(counter) {
    return counter?.known_sum === null || counter?.known_sum === undefined
      ? 'Unknown' : fmtIntegerString(counter.known_sum);
  }

  function efficiencyCoverage(counter) {
    if (!counter || counter.coverage === 'unknown') return 'No measured tasks';
    return `${counter.known_task_count} of ${counter.task_count} tasks measured`;
  }

  function efficiencyPhaseCoverage(repository) {
    const phases = repository?.tokens_by_phase || {};
    const total = Object.values(phases).reduce(
      (sum, phase) => sum + (Number(phase?.usage_event_count) || 0), 0);
    const unattributed = Number(phases.unattributed?.usage_event_count) || 0;
    if (total === 0) return 'Unknown';
    const attributed = Math.max(0, total - unattributed);
    return `${Math.round((attributed / total) * 100)}% (${attributed}/${total})`;
  }

  function efficiencyRepository(repository) {
    return state.efficiency?.repositories?.find(
      (item) => item.repository_id === repository.repository_id) || repository;
  }

  function buildEfficiencyRepositories() {
    if (state.efficiencyLoading && !state.efficiency) {
      return [h('div', { class: 'skel', 'aria-hidden': 'true' }), h('div', { class: 'skel', 'aria-hidden': 'true' })];
    }
    if (state.efficiencyError && !state.efficiency) {
      return [emptyState(`Efficiency statistics are unavailable: ${state.efficiencyError.message}`)];
    }
    const repositories = state.efficiency?.repositories || [];
    if (!repositories.length) return [emptyState('No recorded repository tasks yet.')];
    const rows = [h('div', { class: 'grid-head efficiency-grid', 'aria-hidden': 'true' },
      h('span', null, 'Repository'), h('span', null, 'Tasks'), h('span', null, 'Accounts'),
      h('span', null, 'Input'), h('span', null, 'Output'), h('span', null, 'Phase attribution'))];
    for (const repository of repositories) {
      const name = repository.display_name || 'Repository unavailable';
      const button = h('button', {
        class: 'row efficiency-grid efficiency-row', type: 'button',
        'aria-label': `View efficiency details for ${name}`,
        onclick: (event) => openEfficiencyDetail(repository.repository_id, event.currentTarget),
      },
      h('span', { class: 'cell efficiency-name', 'data-label': 'Repository' }, name),
      h('span', { class: 'cell', 'data-label': 'Tasks' }, String(repository.task_count)),
      h('span', { class: 'cell', 'data-label': 'Accounts' }, String(repository.accounts?.length || 0)),
      h('span', { class: 'cell', 'data-label': 'Input' }, efficiencyKnown(repository.tokens?.input)),
      h('span', { class: 'cell', 'data-label': 'Output' }, efficiencyKnown(repository.tokens?.output)),
      h('span', { class: 'cell', 'data-label': 'Phase attribution' }, efficiencyPhaseCoverage(repository)));
      rows.push(h('div', { class: 'item' }, button));
    }
    return rows;
  }

  function renderEfficiency(force = false) {
    setSection('efficiency-body', sig(state.efficiency, state.efficiencyError?.message, state.efficiencyLoading),
      buildEfficiencyRepositories, force);
    const count = efficiencyAvailable() ? state.efficiency.repositories.length : null;
    setCount('efficiency-count', count);
    setNavCount('efficiency', count);
    if ($('#efficiency-detail-dialog')?.open) renderEfficiencyDetail();
  }

  function openEfficiencyDetail(repositoryId, trigger) {
    ui.efficiencyRepositoryId = repositoryId;
    ui.efficiencyReturnFocus = trigger;
    renderEfficiencyDetail();
    $('#efficiency-detail-dialog').showModal();
  }

  function closeEfficiencyDetail({ restoreFocus = true } = {}) {
    const dialog = $('#efficiency-detail-dialog');
    if (dialog.open) dialog.close();
    const target = ui.efficiencyReturnFocus;
    ui.efficiencyRepositoryId = null;
    ui.efficiencyReturnFocus = null;
    if (restoreFocus && target?.isConnected) target.focus({ preventScroll: true });
  }

  function efficiencyTokenRows(tokens) {
    const labels = {
      input: 'Input', cached_input: 'Cached input', output: 'Output',
      reasoning_output: 'Reasoning output', tool: 'Tool', other: 'Other',
    };
    return Object.entries(labels).map(([key, label]) => h('div', { class: 'efficiency-detail-row' },
      h('span', null, label), h('strong', null, efficiencyKnown(tokens?.[key])),
      h('span', { class: 'meta-passive' }, efficiencyCoverage(tokens?.[key]))));
  }

  function renderEfficiencyDetail() {
    const repository = state.efficiency?.repositories?.find(
      (item) => item.repository_id === ui.efficiencyRepositoryId);
    if (!repository) {
      closeEfficiencyDetail({ restoreFocus: false });
      return;
    }
    $('#efficiency-detail-h').textContent = repository.display_name || 'Repository efficiency';
    const body = $('#efficiency-detail-body');
    const phaseLabels = {
      planning: 'Planning', implementation: 'Implementation', testing: 'Testing',
      deployment: 'Deployment', reporting: 'Reporting', unattributed: 'Unattributed',
    };
    const phaseRows = Object.entries(phaseLabels).map(([key, label]) => {
      const phase = repository.tokens_by_phase?.[key];
      return h('div', { class: 'efficiency-phase-row' }, h('strong', null, label),
        h('span', null, efficiencyKnown(phase?.input)),
        h('span', null, efficiencyKnown(phase?.output)),
        h('span', null, String(phase?.usage_event_count || 0)));
    });
    const accounts = (repository.accounts || []).map((account, index) => h('div', { class: 'efficiency-account-row' },
      h('strong', null, `Account ${index + 1}`),
      h('span', null, `${account.task_count} task${account.task_count === 1 ? '' : 's'}`),
      h('span', null, `Input ${efficiencyKnown(account.tokens?.input)}`),
      h('span', null, `Output ${efficiencyKnown(account.tokens?.output)}`)));
    const opportunities = (repository.automation_opportunities || []).map((item) => h('li', null,
      h('strong', null, `${item.task_type} · ${item.scope_size} · ${item.current_method}`),
      h('span', null, `${item.occurrence_count} comparable tasks. ${item.recommendation}.`)));
    body.replaceChildren(
      h('div', { class: 'efficiency-summary' },
        kv('Tasks', String(repository.task_count)),
        kv('Completed', String(repository.complete_task_count)),
        kv('Accounts', String(repository.accounts?.length || 0)),
        kv('Phase attribution', efficiencyPhaseCoverage(repository))),
      h('section', { class: 'efficiency-detail-section' }, h('h3', null, 'Provider token categories'),
        ...efficiencyTokenRows(repository.tokens)),
      h('section', { class: 'efficiency-detail-section' }, h('h3', null, 'Tokens by phase'),
        h('div', { class: 'efficiency-phase-head', 'aria-hidden': 'true' },
          h('span', null, 'Phase'), h('span', null, 'Input'), h('span', null, 'Output'), h('span', null, 'Events')),
        ...phaseRows),
      h('section', { class: 'efficiency-detail-section' }, h('h3', null, 'Accounts'),
        ...(accounts.length ? accounts : [emptyState('No account projections.')])),
      h('section', { class: 'efficiency-detail-section' }, h('h3', null, 'Automation candidates'),
        opportunities.length ? h('ul', { class: 'efficiency-opportunities' }, ...opportunities)
          : emptyState('No repeated deterministic-workflow candidate has reached the evidence threshold.')));
  }

  function validBugsPayload(payload) {
    if (!payload || payload.schema_version !== 1 || !Array.isArray(payload.bugs)) return false;
    return payload.bugs.every((bug) => (
      bug && typeof bug === 'object' && !Array.isArray(bug)
      && typeof bug.bug_id === 'string' && bug.bug_id.length > 0
      && typeof bug.fingerprint === 'string' && bug.fingerprint.length > 0
      && typeof bug.component === 'string' && bug.component.length > 0
      && typeof bug.summary === 'string' && bug.summary.length > 0
      && typeof bug.expected === 'string' && bug.expected.length > 0
      && typeof bug.actual === 'string' && bug.actual.length > 0
      && Array.isArray(bug.reproduction_steps) && bug.reproduction_steps.length > 0
      && bug.reproduction_steps.length <= 8
      && bug.reproduction_steps.every((step) => typeof step === 'string' && step.length > 0)
      && Array.isArray(bug.command_argv) && bug.command_argv.length <= 64
      && bug.command_argv.every((argument) => typeof argument === 'string' && argument.length > 0)
      && Number.isInteger(bug.occurrence_count) && bug.occurrence_count > 0
      && Number.isInteger(bug.peer_uid) && bug.peer_uid >= 0
      && Number.isFinite(Date.parse(bug.first_seen_at))
      && Number.isFinite(Date.parse(bug.last_seen_at))
      && bug.origin && typeof bug.origin === 'object' && !Array.isArray(bug.origin)
      && ['local', 'remote'].includes(bug.origin.kind)
      && typeof bug.origin.server_id === 'string' && bug.origin.server_id.length > 0
      && typeof bug.origin.bug_id === 'string' && bug.origin.bug_id.length > 0
      && typeof bug.origin.fingerprint === 'string' && bug.origin.fingerprint.length > 0
      && (bug.local_fallback == null || (
        typeof bug.local_fallback === 'object' && !Array.isArray(bug.local_fallback)
        && ['not_run', 'passed', 'failed', 'incomplete'].includes(bug.local_fallback.status)
        && Array.isArray(bug.local_fallback.command_argv)
        && bug.local_fallback.command_argv.length <= 64
        && bug.local_fallback.command_argv.every((argument) => (
          typeof argument === 'string' && argument.length > 0
        ))
        && bug.local_fallback.advisory === true
        && bug.local_fallback.coordinator_evidence === false
      ))
    ));
  }

  function bugCommand(argv) {
    return (argv || []).map((argument) => {
      const value = String(argument);
      return /^[A-Za-z0-9_./:@%+=,-]+$/.test(value)
        ? value
        : `'${value.replaceAll("'", "'\\''")}'`;
    }).join(' ');
  }

  function bugFact(label, value, { mono = false } = {}) {
    if (value === null || value === undefined || value === '') return null;
    return h('div', { class: 'bug-fact' },
      h('dt', null, label),
      h('dd', { class: mono ? 'mono' : null }, String(value)));
  }

  function bugCorrelationFacts(bug) {
    const correlations = bug.correlations || {};
    return [
      bugFact('Coordinator release', bug.release_digest, { mono: true }),
      bugFact('Coordinator instance', bug.instance_id, { mono: true }),
      bugFact('Call', correlations.call_id, { mono: true }),
      bugFact('Operation', correlations.operation_id, { mono: true }),
      bugFact('Run', correlations.run_id, { mono: true }),
      bugFact('Attempt', correlations.attempt_id, { mono: true }),
    ].filter(Boolean);
  }

  function bugArgvBlock(title, argv, description = null) {
    if (!Array.isArray(argv) || !argv.length) return null;
    return h('section', { class: 'bug-command-section' },
      h('h4', null, title),
      description ? h('p', { class: 'bug-command-context' }, description) : null,
      h('pre', { class: 'bug-command' },
        h('code', null, bugCommand(argv))),
      h('details', { class: 'bug-argv-disclosure' },
        h('summary', null, `${argv.length} structured argument${sfx(argv.length)}`),
        h('ol', { class: 'bug-argv-list', 'aria-label': `${title} argument boundaries` },
          argv.map((argument, index) => h('li', null,
            h('span', { 'aria-hidden': 'true' }, `${index + 1}`),
            h('code', null, argument))))));
  }

  function bugFallbackBlock(fallback) {
    if (!fallback) return null;
    const status = fallback.status.replaceAll('_', ' ');
    return h('section', { class: 'bug-local-fallback' },
      h('div', { class: 'bug-local-fallback-head' },
        h('h4', null, 'Local fallback'),
        h('span', { class: `bug-fallback-status is-${fallback.status}` }, status)),
      h('p', { class: 'bug-advisory-label' },
        'Advisory local check only — this is not governed Coordinator evidence.'),
      fallback.summary ? h('p', null, fallback.summary) : null,
      bugArgvBlock('Local command', fallback.command_argv));
  }

  function buildBugCard(bug) {
    const busy = state.bugsClosing.has(bug.bug_id);
    const closeButton = state.session?.accessAdmin === true
      ? h('button', {
          class: `btn small danger${busy ? ' is-busy' : ''}`,
          type: 'button',
          disabled: busy,
          'data-fk': `bug-close:${bug.bug_id}`,
          'aria-label': `Close Coordinator bug: ${bug.summary}`,
          onclick: () => closeBug(bug),
        }, busy ? 'Closing…' : 'Close')
      : null;
    const metadata = [
      bugFact('Origin server', bug.origin.server_id, { mono: true }),
      bug.origin.kind === 'remote' ? bugFact('Origin bug', bug.origin.bug_id, { mono: true }) : null,
      bugFact('Surface', bug.surface),
      bugFact('Stage', bug.stage),
      bugFact('Classification', bug.classification),
      bugFact('Code', bug.code, { mono: true }),
      bugFact('Operation', bug.operation),
      bugFact('Repository', bug.repository),
      bugFact('Reported by', bug.reporter),
      bugFact('Reporter account', `UID ${bug.peer_uid}`),
    ].filter(Boolean);
    const correlations = bugCorrelationFacts(bug);
    const details = h('details', {
      class: 'bug-details',
      'data-section-disclosure': `bug:${bug.bug_id}`,
      'data-section-disclosure-match': `bug-fingerprint:${bug.fingerprint}`,
    },
    h('summary', {
      'data-fk': `bug-details:${bug.bug_id}`,
      'data-section-disclosure-match': `bug-fingerprint:${bug.fingerprint}`,
    }, 'Expected, actual and reproduction'),
    h('div', { class: 'bug-details-body' },
      h('div', { class: 'bug-behavior' },
        h('section', null, h('h4', null, 'Expected'), h('p', null, bug.expected)),
        h('section', null, h('h4', null, 'Actual'), h('p', null, bug.actual))),
      h('section', { class: 'bug-reproduction' },
        h('h4', null, 'Reproduce'),
        h('ol', null, bug.reproduction_steps.map((step) => h('li', null, step)))),
      bugArgvBlock('Coordinator command', bug.command_argv,
        'Run with these exact argument boundaries.'),
      bugFallbackBlock(bug.local_fallback),
      metadata.length || correlations.length
        ? h('dl', { class: 'bug-facts' }, metadata, correlations) : null));
    return h('article', {
      class: 'bug-card',
      'data-bug-id': bug.bug_id,
      'data-fk': `bug:${bug.bug_id}`,
      tabindex: '-1',
    },
    h('div', { class: 'bug-card-head' },
      h('div', { class: 'bug-card-copy' },
        h('p', { class: `bug-origin${bug.origin.kind === 'remote' ? ' is-remote' : ''}` },
          bug.origin.kind === 'remote'
            ? `Imported from ${bug.origin.server_id}`
            : `This server · ${bug.origin.server_id}`),
        h('p', { class: 'bug-component' }, bug.component),
        h('h3', null, bug.summary),
        h('p', { class: 'bug-occurrence' },
          `${bug.occurrence_count} occurrence${sfx(bug.occurrence_count)} · last seen ${timeAgo(Date.parse(bug.last_seen_at))}`,
          bug.occurrence_count > 1 ? ` · first seen ${timeAgo(Date.parse(bug.first_seen_at))}` : '')),
      closeButton),
    details);
  }

  function buildBugs() {
    if (!state.bugs) {
      if (!state.bugsError) return [h('div', { class: 'skel', 'aria-hidden': 'true' })];
      return [h('div', { class: 'bugs-local-error', role: 'alert' },
        h('div', null,
          h('h3', null, 'Open bugs could not be loaded'),
          h('p', null, state.bugsError)),
        h('button', { class: 'btn', type: 'button', onclick: () => loadBugs({ force: true }) },
          icon('refresh'), 'Try again'))];
    }
    if (!state.bugs.bugs.length) {
      return [h('div', { class: 'bugs-empty' },
        h('p', null, 'No open Coordinator bugs.'),
        h('span', null, 'New agent reports appear here automatically.'))];
    }
    return [h('div', { class: 'bug-list' }, state.bugs.bugs.map(buildBugCard))];
  }

  function renderBugs(force = false) {
    const count = state.bugs?.bugs?.length ?? null;
    setCount('bugs-count', count);
    setNavCount('bugs', count > 0 ? count : null);
    $('#bugs-import').hidden = state.session?.accessAdmin !== true;
    const retained = $('#bugs-retained');
    if (state.bugsError && state.bugs) {
      retained.hidden = false;
      retained.textContent = state.bugsErrorContext === 'close'
        ? `${state.bugsError} The retained open collection is unchanged.`
        : `Latest refresh failed — showing ${count} retained open report${sfx(count)}. ${state.bugsError}`;
    } else {
      retained.hidden = true;
      retained.textContent = '';
    }
    if (currentPage() === 'bugs') {
      setSection('bugs-body', sig(
        state.bugs?.revision ?? null,
        state.bugsError,
        state.session?.accessAdmin === true,
        [...state.bugsClosing].sort(),
      ), buildBugs, force);
    }
    if (ui.bugFocusAfterClose) {
      const key = ui.bugFocusAfterClose;
      ui.bugFocusAfterClose = null;
      queueMicrotask(() => (
        document.querySelector(`[data-fk="${CSS.escape(`bug:${key}`)}"]`)
        || $('#bugs-refresh')
      )?.focus({ preventScroll: true }));
    }
  }

  async function loadBugs({ force = false } = {}) {
    if (state.bugsLoading) return;
    if (!force && state.bugs && currentPage() !== 'bugs') {
      setNavCount('bugs', state.bugs.bugs.length || null);
    }
    state.bugsLoading = true;
    try {
      const payload = await api('/api/bugs');
      if (!validBugsPayload(payload)) throw new ApiError('The open-bug registry returned malformed data.', 502);
      state.bugs = payload;
      state.bugsError = null;
      state.bugsErrorContext = null;
      renderBugs();
    } catch (error) {
      if (error.status === 401) return;
      state.bugsError = error.message || 'Open Coordinator bugs are temporarily unavailable.';
      state.bugsErrorContext = 'refresh';
      renderBugs();
    } finally {
      state.bugsLoading = false;
    }
  }

  function bugTransferError(kind, message = null) {
    const error = $(`#bugs-${kind}-error`);
    error.hidden = !message;
    error.textContent = message || '';
  }

  function closeBugTransfer(kind, { restoreFocus = true } = {}) {
    const dialog = $(`#bugs-${kind}-dialog`);
    if (dialog.open) dialog.close();
    bugTransferError(kind);
    if (restoreFocus) {
      const focus = ui.bugTransferReturnFocus;
      ui.bugTransferReturnFocus = null;
      focus?.focus?.({ preventScroll: true });
    }
  }

  async function openBugExport(event) {
    const dialog = $('#bugs-export-dialog');
    ui.bugTransferReturnFocus = event?.currentTarget || $('#bugs-export');
    bugTransferError('export');
    $('#bugs-export-json').value = 'Preparing export…';
    $('#bugs-export-copy').disabled = true;
    dialog.showModal();
    try {
      const payload = await api('/api/bugs/export');
      if (!payload || payload.schema_version !== 1
          || payload.kind !== 'devcoordinator-open-bugs' || !Array.isArray(payload.bugs)) {
        throw new ApiError('The bug export returned malformed data.', 502);
      }
      $('#bugs-export-json').value = JSON.stringify(payload, null, 2);
      $('#bugs-export-copy').disabled = false;
      $('#bugs-export-json').focus();
      $('#bugs-export-json').select();
    } catch (error) {
      $('#bugs-export-json').value = '';
      bugTransferError('export', error.message || 'Open bugs could not be exported.');
    }
  }

  async function copyBugExport(event) {
    const text = $('#bugs-export-json').value;
    if (!text) return;
    await copyText(text, event?.currentTarget);
    $('#bugs-export-json').focus();
    $('#bugs-export-json').select();
  }

  function openBugImport(event) {
    if (state.session?.accessAdmin !== true) return;
    ui.bugTransferReturnFocus = event?.currentTarget || $('#bugs-import');
    bugTransferError('import');
    $('#bugs-import-json').value = '';
    $('#bugs-import-submit').disabled = false;
    $('#bugs-import-submit').textContent = 'Import';
    $('#bugs-import-dialog').showModal();
    $('#bugs-import-json').focus();
  }

  async function importBugs() {
    if (state.bugsTransferBusy) return;
    let bundle;
    try {
      bundle = JSON.parse($('#bugs-import-json').value);
    } catch {
      bugTransferError('import', 'Paste one valid JSON export bundle.');
      $('#bugs-import-json').focus();
      return;
    }
    state.bugsTransferBusy = true;
    const submit = $('#bugs-import-submit');
    submit.disabled = true;
    submit.textContent = 'Importing…';
    bugTransferError('import');
    try {
      const payload = await api('/api/bugs/import', { method: 'POST', body: bundle });
      if (!validBugsPayload(payload)) throw new ApiError('The imported bug collection is malformed.', 502);
      state.bugs = payload;
      state.bugsError = null;
      state.bugsErrorContext = null;
      const imported = payload.import_result?.imported ?? 0;
      const present = payload.import_result?.already_present ?? 0;
      closeBugTransfer('import');
      renderBugs(true);
      announce(`Imported ${imported} open bug${sfx(imported)}${present ? `; ${present} already present` : ''}`);
    } catch (error) {
      bugTransferError('import', error.message || 'Open bugs could not be imported.');
    } finally {
      state.bugsTransferBusy = false;
      submit.disabled = false;
      submit.textContent = 'Import';
    }
  }

  async function closeBug(bug) {
    if (state.bugsClosing.has(bug.bug_id)) return;
    const label = `${bug.component}: ${bug.summary}`;
    if (!window.confirm(
      `Close “${label}”?\n\nThe open report will be removed from every Console instance. No closed history is kept.`,
    )) return;
    const current = state.bugs?.bugs || [];
    const index = current.findIndex((candidate) => candidate.bug_id === bug.bug_id);
    const next = current[index + 1] || current[index - 1] || null;
    state.bugsClosing.add(bug.bug_id);
    renderBugs(true);
    try {
      const payload = await api(`/api/bugs/${encodeURIComponent(bug.bug_id)}`, { method: 'DELETE' });
      if (!validBugsPayload(payload)) throw new ApiError('The open-bug registry returned malformed data.', 502);
      state.bugs = payload;
      state.bugsError = null;
      state.bugsErrorContext = null;
      ui.bugFocusAfterClose = next?.bug_id || '__refresh__';
      $('#live').textContent = `Closed Coordinator bug: ${label}`;
    } catch (error) {
      if (error.status !== 401) {
        state.bugsError = `Could not close “${label}”. ${error.message}`;
        state.bugsErrorContext = 'close';
      }
    } finally {
      state.bugsClosing.delete(bug.bug_id);
      renderBugs(true);
    }
  }

  // ---------------------------------------------------------------- access policy

  let accessFetching = false;
  let accessRoutesSig = '';

  function syncAccessVisibility() {
    const admin = state.session?.accessAdmin === true;
    $('#nav-access').hidden = !admin;
    $('#nav-invites').hidden = !admin;
    $('#nav-telegram').hidden = !state.session?.email;
    $('#access-add').hidden = !admin;
    if (!admin) {
      state.access = null;
      state.invites = null;
    }
    syncLifecycleVisibility();
    applyPage();
  }

  function currentAccessRoutesSig() {
    return JSON.stringify((state.overview?.routes || []).map((route) => [
      route.slug, route.auth, route.kind, route.title, route.project, route.serverName,
      route.containerName, route.containerPort, route.port,
    ]));
  }

  async function loadAccess({ force = false } = {}) {
    if (state.session?.accessAdmin !== true || accessFetching) return;
    if (!force && state.access) {
      renderAccess();
      return;
    }
    accessFetching = true;
    try {
      state.access = await api('/api/access');
      accessRoutesSig = currentAccessRoutesSig();
      clearBanner('access');
      renderAccess();
    } catch (err) {
      if (err.status === 401) return;
      if (currentPage() === 'access') {
        $('#access-body').replaceChildren(
          h('p', { class: 'empty err' }, 'Could not load the access list. Use Retry above.'));
        showBanner(err, () => loadAccess({ force: true }), 'access');
      }
    } finally {
      accessFetching = false;
    }
  }

  function accessResourceControl(resource, { checked, disabled = false, email = '' } = {}) {
    const input = h('input', {
      type: 'checkbox',
      checked: checked ? true : null,
      disabled: disabled ? true : null,
      name: email ? null : 'grants',
      value: resource.id,
      'data-fk': email ? `access:${email}:${resource.id}` : null,
      'aria-label': `${checked ? 'Remove' : 'Grant'} access to ${resource.host}`,
    });
    if (email) {
      input.addEventListener('change', () => changeAccessGrant(email, resource, input));
    }
    const publicBadge = resource.auth === 'public'
      ? h('span', { class: 'access-public-badge' }, 'Public')
      : null;
    const detail = resource.auth === 'public'
      ? `${resource.target} · Public now; this grant applies if the domain becomes private.`
      : resource.target;
    return h('label', { class: 'access-resource' },
      input,
      h('span', { class: 'access-resource-main' },
        h('span', { class: 'access-resource-title' },
          h('span', { class: 'access-resource-host' }, resource.host), publicBadge),
        h('span', { class: 'access-resource-detail' }, detail)));
  }

  function buildAccess() {
    const policy = state.access;
    if (!policy) return [
      h('div', { class: 'skel', 'aria-hidden': 'true' }),
      h('div', { class: 'skel', 'aria-hidden': 'true' }),
    ];
    const out = [];
    const invited = policy.users.filter((user) => !user.owner);
    for (const user of policy.users) {
      const header = h('div', { class: 'access-user-head' },
        h('span', { class: 'access-email' }, user.email),
        user.owner ? h('span', { class: 'access-owner-badge' }, 'Owner') : null,
        user.owner ? null : h('button', {
          class: 'iconbtn danger access-remove', type: 'button',
          'data-fk': `access-remove:${user.email}`,
          'aria-label': `Remove ${user.email} and revoke all access`,
          title: 'Remove user',
          onclick: () => removeAccessUser(user.email),
        }, icon('trash')));
      const content = user.owner
        ? h('p', { class: 'access-owner-note' },
            'Full access to the Console and every assigned domain. Owners are changed only in the private ALLOWED_EMAILS configuration.')
        : h('div', { class: 'access-resource-list' },
            ...policy.resources.map((resource) => accessResourceControl(resource, {
              checked: user.grants.includes(resource.id),
              email: user.email,
            })));
      out.push(h('article', {
        class: 'item access-user',
        'data-access-user': user.email,
        tabindex: '-1',
      }, header, content));
    }
    if (invited.length === 0) {
      out.push(h('p', { class: 'empty access-empty' },
        'No invited users yet. Add a Google account when someone needs a private domain.'));
    }
    return out;
  }

  function renderAccess() {
    if (state.session?.accessAdmin !== true || currentPage() !== 'access') return;
    setSection('access-body', sig(state.access), buildAccess, true);
    const count = state.access?.users?.length;
    setCount('access-count', count);
    setNavCount('access', count);
  }

  async function changeAccessGrant(email, resource, input, desired = input.checked) {
    const allowed = desired;
    input.checked = allowed;
    input.disabled = true;
    try {
      state.access = await api(`/api/access/users/${encodeURIComponent(email)}`, {
        method: 'PATCH',
        body: { resource: resource.id, allowed },
      });
      announce(`${resource.host} ${allowed ? 'granted to' : 'removed from'} ${email}`);
      renderAccess();
    } catch (err) {
      if (isEdgePublicationError(err)) {
        await loadAccess({ force: true });
        showSectionPublicationError('access-body', err, () => loadAccess({ force: true }));
      } else {
        input.checked = !allowed;
        input.disabled = false;
        if (err.status !== 401) {
          showBanner(err, () => changeAccessGrant(email, resource, input, allowed));
        }
      }
    }
  }

  async function removeAccessUser(email) {
    if (!window.confirm(`Remove ${email}?\n\nEvery Console and private-domain grant is revoked immediately, including existing signed-in sessions.`)) return;
    try {
      state.access = await api(`/api/access/users/${encodeURIComponent(email)}`, { method: 'DELETE' });
      announce(`${email} removed`);
      renderAccess();
      $('#access-add').focus({ preventScroll: true });
    } catch (err) {
      if (isEdgePublicationError(err)) {
        await loadAccess({ force: true });
        showSectionPublicationError('access-body', err, () => loadAccess({ force: true }));
      } else if (err.status !== 401) showBanner(err, () => removeAccessUser(email));
    }
  }

  function openAccessDialog() {
    if (!state.access) return loadAccess({ force: true });
    const form = $('#access-form');
    form.reset();
    $('#access-form-error').hidden = true;
    $('#access-resource-picker').replaceChildren(
      ...state.access.resources.map((resource) => accessResourceControl(resource, { checked: false })));
    const dialog = $('#access-dialog');
    dialog.showModal();
    queueMicrotask(() => $('#access-email').focus());
  }

  function closeAccessDialog() {
    const dialog = $('#access-dialog');
    if (dialog.open) dialog.close();
  }

  function wireAccessDialog() {
    $('#access-add').addEventListener('click', openAccessDialog);
    $('#access-dialog-close').append(icon('x'));
    $('#access-dialog-close').addEventListener('click', closeAccessDialog);
    $('#access-cancel').addEventListener('click', closeAccessDialog);
    $('#access-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const emailInput = $('#access-email');
      const error = $('#access-form-error');
      if (!emailInput.reportValidity()) return;
      const grants = [...document.querySelectorAll('#access-resource-picker input[name="grants"]:checked')]
        .map((input) => input.value);
      const submit = $('#access-submit');
      submit.disabled = true;
      submit.textContent = 'Adding…';
      error.hidden = true;
      try {
        state.access = await api('/api/access/users', {
          method: 'POST', body: { email: emailInput.value, grants },
        });
        const normalized = emailInput.value.trim().toLowerCase();
        closeAccessDialog();
        renderAccess();
        announce(`${normalized} added`);
        const row = document.querySelector(`[data-access-user="${CSS.escape(normalized)}"]`);
        row?.scrollIntoView({ block: 'nearest' });
        row?.focus({ preventScroll: true });
      } catch (err) {
        if (isEdgePublicationError(err)) {
          renderLocalPublicationError(error, err, {
            onActivated: async () => {
              closeAccessDialog();
              await loadAccess({ force: true });
            },
          });
        } else {
          error.textContent = err.message;
          error.hidden = false;
        }
      } finally {
        submit.disabled = false;
        submit.textContent = 'Add user';
      }
    });
  }

  // ---------------------------------------------------------------- incoming Google access requests

  let invitesFetching = false;

  function inviteRows() {
    if (Array.isArray(state.invites)) return state.invites;
    return Array.isArray(state.invites?.requests) ? state.invites.requests : [];
  }

  function requestStatus(request) {
    return String(request?.status || 'pending').toLowerCase();
  }

  function queueStatusBadge(status) {
    const normalized = String(status || 'pending').toLowerCase();
    return h('span', { class: `queue-status ${normalized}` }, normalized.replaceAll('_', ' '));
  }

  function requestDisplay(request) {
    const resource = request.resource || request.grant || '';
    const fallbackHost = resource === 'console'
      ? state.overview?.console?.host || 'DevOps Console'
      : resource.startsWith('route:')
        ? `${resource.slice('route:'.length)}.${state.overview?.console?.domain || ''}`
        : resource || 'Requested destination';
    return {
      host: request.host || request.resourceHost || fallbackHost,
      title: request.title || (resource === 'console' ? 'DevOps Console' : 'Private domain'),
      target: request.target || request.resourceTarget || resource,
      requestedAt: request.requestedAt || request.requested_at,
      resolvedAt: request.resolvedAt || request.resolved_at,
      resolvedBy: request.resolvedBy || request.resolved_by,
      resource,
    };
  }

  function inviteRequestRow(request, { terminal = false } = {}) {
    const view = requestDisplay(request);
    const status = requestStatus(request);
    const id = String(request.id || request.requestId || request.request_id || '');
    const busyKey = `invite:${id}`;
    const busy = ui.busy.has(busyKey);
    const actions = terminal ? null : h('div', { class: 'queue-actions' },
      h('button', {
        class: 'btn small', type: 'button', 'data-fk': `${busyKey}:approve`,
        disabled: busy || undefined,
        onclick: () => decideInvite(request, 'approve'),
      }, busy ? 'Working…' : 'Approve'),
      h('button', {
        class: 'btn small danger', type: 'button', 'data-fk': `${busyKey}:deny`,
        disabled: busy || undefined,
        onclick: () => decideInvite(request, 'deny'),
      }, 'Deny'));
    return h('article', { class: 'item queue-row', 'data-invite-id': id, tabindex: '-1' },
      h('div', { class: 'queue-row-head' },
        h('div', { class: 'queue-row-main' },
          h('div', { class: 'queue-title' },
            h('strong', { class: 'access-email' }, request.email || 'Verified Google account'),
            queueStatusBadge(status)),
          h('p', { class: 'queue-meta' }, `${view.title} · ${view.host}`),
          h('p', { class: 'queue-meta' }, view.target || 'Exact requested destination'),
          h('p', { class: 'queue-meta' }, terminal
            ? `Requested ${fmtWhen(view.requestedAt)} · resolved ${fmtWhen(view.resolvedAt)}${view.resolvedBy ? ` by ${view.resolvedBy}` : ''}`
            : `Requested ${fmtWhen(view.requestedAt)}`)),
        actions),
      !terminal && view.resource === 'console'
        ? h('p', { class: 'queue-warning' },
            'Approving Console access grants full server, Docker, route and port control. It does not grant access administration.')
        : null);
  }

  function buildInvites() {
    if (!state.invites) return [
      h('div', { class: 'skel', 'aria-hidden': 'true' }),
      h('div', { class: 'skel', 'aria-hidden': 'true' }),
    ];
    const rows = inviteRows();
    const pending = rows.filter((row) => requestStatus(row) === 'pending');
    const resolved = rows.filter((row) => requestStatus(row) !== 'pending').slice(0, RESOURCE_PAGE_SIZE);
    const out = [h('p', { class: 'queue-summary' },
      pending.length
        ? `${pending.length} verified request${sfx(pending.length)} waiting for a decision.`
        : 'No access requests are waiting.')];
    if (pending.length) out.push(...pending.slice(0, RESOURCE_PAGE_SIZE).map((row) => inviteRequestRow(row)));
    else out.push(h('p', { class: 'empty' },
      'When a verified Google account requests this Console or a private domain, it appears here.'));
    if (resolved.length) {
      out.push(h('details', { class: 'queue-history' },
        h('summary', null, `Recent decisions (${resolved.length})`),
        ...resolved.map((row) => inviteRequestRow(row, { terminal: true }))));
    }
    return out;
  }

  function renderInvites() {
    if (state.session?.accessAdmin !== true) return;
    const pending = inviteRows().filter((row) => requestStatus(row) === 'pending').length;
    setNavCount('invites', pending);
    if (currentPage() !== 'invites') return;
    setSection('invites-body', sig(state.invites), buildInvites, true);
    setCount('invites-count', pending);
  }

  async function loadInvites({ force = false } = {}) {
    if (state.session?.accessAdmin !== true || invitesFetching) return;
    if (!force && state.invites) return renderInvites();
    invitesFetching = true;
    $('#invites-refresh').disabled = true;
    try {
      state.invites = await api('/api/access/requests?status=all');
      clearBanner('invites');
      renderInvites();
    } catch (err) {
      if (err.status !== 401) {
        if (currentPage() === 'invites') {
          $('#invites-body').replaceChildren(
            h('p', { class: 'empty err' }, 'Could not load incoming invites.'));
          showBanner(err, () => loadInvites({ force: true }), 'invites');
        }
      }
    } finally {
      invitesFetching = false;
      $('#invites-refresh').disabled = false;
    }
  }

  async function decideInvite(request, decision) {
    const id = String(request.id || request.requestId || request.request_id || '');
    if (!id || !['approve', 'deny'].includes(decision)) return;
    const busyKey = `invite:${id}`;
    if (ui.busy.has(busyKey)) return;
    ui.busy.add(busyKey);
    bump();
    renderInvites();
    try {
      const result = await api(`/api/access/requests/${encodeURIComponent(id)}/decision`, {
        method: 'POST', body: { decision },
      });
      if (result?.access) state.access = result.access;
      await loadInvites({ force: true });
      announce(`Access request ${decision === 'approve' ? 'approved' : 'denied'}`);
      if (decision === 'approve' && !result?.access) loadAccess({ force: true });
    } catch (err) {
      if (isEdgePublicationError(err)) {
        await loadInvites({ force: true });
        showSectionPublicationError('invites-body', err, () => loadInvites({ force: true }));
      } else if (err.status !== 401) {
        // A successful background refresh may clear only the collection-load
        // error.  Keep this action conflict visible until the operator retries
        // or dismisses it instead of racing it against the refresh poll.
        showBanner(
          err,
          () => decideInvite(request, decision),
          `invite-action:${id}`,
        );
      }
    } finally {
      ui.busy.delete(busyKey);
      bump();
      renderInvites();
    }
  }

  // ---------------------------------------------------------------- Telegram bots + per-bot authorization

  let telegramFetching = false;

  const telegramBots = () => Array.isArray(state.telegram?.bots) ? state.telegram.bots : [];
  const telegramProjects = () => Array.isArray(state.telegram?.projects) ? state.telegram.projects : [];
  const telegramBotId = (bot) => String(bot.id || bot.botId || bot.bot_id || '');
  const telegramAssignments = (bot) => new Set(
    (bot.projectIds || bot.project_ids || bot.projects || []).map(String),
  );
  const telegramAuthorizations = (bot) => (
    Array.isArray(bot.authorizations) ? bot.authorizations
      : Array.isArray(bot.authorizationQueue) ? bot.authorizationQueue
        : []
  );

  function telegramAuthorizationId(row) {
    return String(row.id || row.authorizationId || row.authorization_id || row.telegramUserId || row.user_id || '');
  }

  function telegramPerson(row) {
    const name = [row.firstName || row.first_name, row.lastName || row.last_name].filter(Boolean).join(' ');
    const username = row.username ? `@${String(row.username).replace(/^@/, '')}` : '';
    return {
      name: name || username || `Telegram user ${row.telegramUserId || row.user_id || row.chatId || row.chat_id || ''}`,
      detail: [username, row.telegramUserId || row.user_id ? `user ${row.telegramUserId || row.user_id}` : '',
        row.requestedAt || row.requested_at ? `requested ${fmtWhen(row.requestedAt || row.requested_at)}` : '']
        .filter(Boolean).join(' · '),
    };
  }

  function telegramAuthRow(bot, row, { terminal = false } = {}) {
    const botId = telegramBotId(bot);
    const authId = telegramAuthorizationId(row);
    const person = telegramPerson(row);
    const status = String(row.status || 'pending').toLowerCase();
    const busyKey = `telegram-auth:${botId}:${authId}`;
    const busy = ui.busy.has(busyKey);
    return h('div', { class: 'telegram-auth' },
      h('div', { class: 'telegram-auth-main' },
        h('strong', null, person.name),
        h('span', null, person.detail || 'Private Telegram chat')),
      queueStatusBadge(status),
      terminal ? null : h('div', { class: 'queue-actions' },
        h('button', {
          class: 'btn small', type: 'button', 'data-fk': `${busyKey}:approve`,
          disabled: busy || undefined,
          onclick: () => decideTelegramAuthorization(bot, row, 'approve'),
        }, busy ? 'Working…' : 'Approve'),
        h('button', {
          class: 'btn small danger', type: 'button', 'data-fk': `${busyKey}:deny`,
          disabled: busy || undefined,
          onclick: () => decideTelegramAuthorization(bot, row, 'deny'),
        }, 'Deny')));
  }

  function telegramProjectControl(bot, project) {
    const botId = telegramBotId(bot);
    const projectId = String(project.id || project.repoId || project.repo_id || '');
    const assigned = telegramAssignments(bot).has(projectId);
    const busyKey = `telegram-projects:${botId}`;
    const input = h('input', {
      type: 'checkbox', checked: assigned || undefined,
      disabled: ui.busy.has(busyKey) || undefined,
      'data-project-id': projectId,
      'aria-label': `${assigned ? 'Stop' : 'Start'} notifications for ${project.name || project.displayName || projectId}`,
    });
    input.addEventListener('change', () => changeTelegramProject(bot, projectId, input.checked));
    return h('label', { class: 'telegram-project' }, input,
      h('span', null,
        h('strong', null, project.name || project.displayName || project.display_name || projectId),
        h('span', null, project.path || project.canonicalRoot || project.canonical_root || projectId)));
  }

  function telegramBotCard(bot) {
    const botId = telegramBotId(bot);
    const username = String(bot.username || '').replace(/^@/, '');
    const owner = bot.ownerEmail || bot.owner_email;
    const enabled = bot.enabled !== false;
    const pollingError = bot.lastError || bot.last_error || bot.polling?.lastError;
    const auth = telegramAuthorizations(bot);
    const pending = auth.filter((row) => String(row.status || 'pending').toLowerCase() === 'pending');
    const resolved = auth.filter((row) => String(row.status || '').toLowerCase() !== 'pending').slice(0, 20);
    const assignments = telegramAssignments(bot);
    const missingProjects = [...assignments].filter(
      (id) => !telegramProjects().some((project) => String(project.id || project.repoId || project.repo_id) === id),
    );
    return h('article', { class: 'item telegram-bot', 'data-telegram-bot': botId, tabindex: '-1' },
      h('div', { class: 'telegram-bot-head' },
        h('div', { class: 'telegram-bot-main' },
          h('div', { class: 'telegram-bot-title' },
            h('strong', null, bot.label || (username ? `@${username}` : 'Telegram bot')),
            queueStatusBadge(enabled ? 'active' : 'paused')),
          h('p', { class: 'telegram-bot-meta' },
            username
              ? h('a', { href: `https://t.me/${username}`, target: '_blank', rel: 'noreferrer' }, `@${username}`)
              : 'Telegram identity unavailable',
            owner ? ` · owned by ${owner}` : '',
            ` · ${assignments.size} assigned project${sfx(assignments.size)}`),
          pollingError ? h('p', { class: 'telegram-bot-meta telegram-error' }, String(pollingError)) : null),
        h('div', { class: 'telegram-bot-actions' },
          h('button', {
            class: 'btn small danger', type: 'button', 'data-fk': `telegram-remove:${botId}`,
            onclick: () => removeTelegramBot(bot),
          }, icon('trash'), 'Remove'))),
      h('section', { class: 'telegram-section' },
        h('h3', null, 'Assigned projects'),
        telegramProjects().length
          ? h('div', { class: 'telegram-project-list' },
              ...telegramProjects().map((project) => telegramProjectControl(bot, project)))
          : h('p', { class: 'queue-meta' }, 'No active coordinator projects are available.'),
        missingProjects.length
          ? h('p', { class: 'queue-warning' },
              `${missingProjects.length} assignment${sfx(missingProjects.length)} no longer matches an active project and receives no events.`)
          : null),
      h('section', { class: 'telegram-section' },
        h('h3', null, `Bot authorization queue${pending.length ? ` (${pending.length})` : ''}`),
        pending.length
          ? h('div', { class: 'telegram-auth-list' }, ...pending.map((row) => telegramAuthRow(bot, row)))
          : h('p', { class: 'queue-meta' },
              username ? `No one is waiting. Ask the user to open @${username} and send /start.` : 'No one is waiting.'),
        resolved.length
          ? h('details', { class: 'queue-history' },
              h('summary', null, `Recent decisions (${resolved.length})`),
              h('div', { class: 'telegram-auth-list' },
                ...resolved.map((row) => telegramAuthRow(bot, row, { terminal: true }))))
          : null));
  }

  function buildTelegram() {
    if (!state.telegram) return [
      h('div', { class: 'skel', 'aria-hidden': 'true' }),
      h('div', { class: 'skel', 'aria-hidden': 'true' }),
    ];
    const bots = telegramBots();
    if (!bots.length) return [h('div', { class: 'empty telegram-empty' },
      h('p', null, 'No Telegram bots are registered for this account.'),
      h('button', { class: 'btn primary', type: 'button', onclick: openTelegramDialog }, 'Register bot'))];
    return bots.map(telegramBotCard);
  }

  let pendingRegisteredTelegramFocus = null;

  function telegramBotRow(botId) {
    return botId ? document.querySelector(
      `[data-telegram-bot="${CSS.escape(String(botId))}"]`,
    ) : null;
  }

  function restorePendingRegisteredTelegramFocus() {
    const pending = pendingRegisteredTelegramFocus;
    if (!pending || currentPage() !== 'telegram' || $('#telegram-dialog').open) return;
    const active = document.activeElement;
    const mayRestore = active === document.body
      || active === $('#telegram-add')
      || $('#telegram-dialog').contains(active)
      || active?.dataset?.telegramBot === pending.botId;
    if (!mayRestore) return;
    if (pendingRegisteredTelegramFocus !== pending) return;
    const row = telegramBotRow(pending.botId);
    if (!row) return;
    // The success journey renders the new card before calling this helper.
    // Focus it synchronously so a waiting browser client cannot observe the
    // card in the brief interval before a zero-delay timer fires.  Retaining
    // the pending marker still lets a subsequent polling render restore focus
    // if it replaces the card while the confirmation context is active.
    row.scrollIntoView({ block: 'nearest' });
    row.focus({ preventScroll: true });
  }

  function requestRegisteredTelegramFocus(botId) {
    const normalizedBotId = String(botId || '');
    if (!normalizedBotId) return;
    const pending = { botId: normalizedBotId };
    pendingRegisteredTelegramFocus = pending;
    restorePendingRegisteredTelegramFocus();
    queueMicrotask(() => {
      if (pendingRegisteredTelegramFocus === pending) {
        restorePendingRegisteredTelegramFocus();
      }
    });
    requestAnimationFrame(() => {
      if (pendingRegisteredTelegramFocus === pending) {
        restorePendingRegisteredTelegramFocus();
      }
    });
    setTimeout(() => {
      if (pendingRegisteredTelegramFocus === pending) pendingRegisteredTelegramFocus = null;
    }, 5_000);
  }

  function renderTelegram() {
    if (!state.session?.email) return;
    setNavCount('telegram', state.telegram ? telegramBots().length : null);
    if (currentPage() !== 'telegram') return;
    setSection('telegram-body', sig(state.telegram), buildTelegram, true);
    setCount('telegram-count', state.telegram ? telegramBots().length : null);
    restorePendingRegisteredTelegramFocus();
  }

  async function loadTelegram({ force = false } = {}) {
    if (!state.session?.email || telegramFetching) return;
    if (!force && state.telegram) return renderTelegram();
    telegramFetching = true;
    try {
      state.telegram = await api('/api/telegram');
      clearBanner('telegram');
      renderTelegram();
    } catch (err) {
      if (err.status !== 401) {
        if (currentPage() === 'telegram') {
          $('#telegram-body').replaceChildren(h('p', { class: 'empty err' }, 'Could not load Telegram bots.'));
          showBanner(err, () => loadTelegram({ force: true }), 'telegram');
        }
      }
    } finally {
      telegramFetching = false;
    }
  }

  async function changeTelegramProject(bot, projectId, allowed) {
    const botId = telegramBotId(bot);
    const busyKey = `telegram-projects:${botId}`;
    if (ui.busy.has(busyKey)) return;
    const selected = telegramAssignments(bot);
    if (allowed) selected.add(projectId); else selected.delete(projectId);
    ui.busy.add(busyKey);
    bump();
    renderTelegram();
    try {
      state.telegram = await api(`/api/telegram/bots/${encodeURIComponent(botId)}/projects`, {
        method: 'PATCH', body: { projectIds: [...selected] },
      });
      announce('Telegram project assignments updated');
    } catch (err) {
      if (err.status !== 401) showBanner(err, () => changeTelegramProject(bot, projectId, allowed), 'telegram');
    } finally {
      ui.busy.delete(busyKey);
      bump();
      renderTelegram();
    }
  }

  async function decideTelegramAuthorization(bot, row, decision) {
    const botId = telegramBotId(bot);
    const authId = telegramAuthorizationId(row);
    const busyKey = `telegram-auth:${botId}:${authId}`;
    if (!botId || !authId || ui.busy.has(busyKey)) return;
    ui.busy.add(busyKey);
    bump();
    renderTelegram();
    try {
      state.telegram = await api(
        `/api/telegram/bots/${encodeURIComponent(botId)}/authorizations/${encodeURIComponent(authId)}/decision`,
        { method: 'POST', body: { decision } },
      );
      announce(`Telegram user ${decision === 'approve' ? 'approved' : 'denied'}`);
    } catch (err) {
      if (err.status !== 401) showBanner(
        err, () => decideTelegramAuthorization(bot, row, decision), 'telegram',
      );
    } finally {
      ui.busy.delete(busyKey);
      bump();
      renderTelegram();
    }
  }

  async function removeTelegramBot(bot) {
    const botId = telegramBotId(bot);
    const label = bot.label || (bot.username ? `@${String(bot.username).replace(/^@/, '')}` : 'this bot');
    if (!window.confirm(
      `Remove ${label}?\n\nIts token, project assignments, authorization queue and pending notifications will be deleted from this Console.`,
    )) return;
    try {
      state.telegram = await api(`/api/telegram/bots/${encodeURIComponent(botId)}`, { method: 'DELETE' });
      announce(`${label} removed`);
      renderTelegram();
      $('#telegram-add').focus({ preventScroll: true });
    } catch (err) {
      if (err.status !== 401) showBanner(err, () => removeTelegramBot(bot), 'telegram');
    }
  }

  function openTelegramDialog() {
    const form = $('#telegram-form');
    form.reset();
    $('#telegram-form-error').hidden = true;
    $('#telegram-takeover-wrap').hidden = true;
    $('#telegram-dialog').showModal();
    queueMicrotask(() => $('#telegram-label').focus());
  }

  function closeTelegramDialog() {
    const dialog = $('#telegram-dialog');
    if (dialog.open) dialog.close();
    $('#telegram-token').value = '';
  }

  function wireTelegramDialog() {
    $('#telegram-add').addEventListener('click', openTelegramDialog);
    $('#telegram-dialog-close').append(icon('x'));
    $('#telegram-dialog-close').addEventListener('click', closeTelegramDialog);
    $('#telegram-cancel').addEventListener('click', closeTelegramDialog);
    $('#telegram-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const token = $('#telegram-token');
      const label = $('#telegram-label');
      const takeover = $('#telegram-takeover');
      const error = $('#telegram-form-error');
      if (!token.reportValidity()) return;
      const submit = $('#telegram-submit');
      submit.disabled = true;
      submit.textContent = 'Registering…';
      error.hidden = true;
      try {
        state.telegram = await api('/api/telegram/bots', {
          method: 'POST',
          body: { token: token.value, label: label.value, takeOver: takeover.checked },
        });
        const registeredId = String(state.telegram?.registeredBotId || '');
        const registered = telegramBots().find((bot) => telegramBotId(bot) === registeredId)
          || telegramBots()[telegramBots().length - 1];
        renderTelegram();
        requestRegisteredTelegramFocus(telegramBotId(registered));
        closeTelegramDialog();
        restorePendingRegisteredTelegramFocus();
        announce('Telegram bot registered');
      } catch (err) {
        const webhookActive = err.code === 'telegram_webhook_active'
          || (err.status === 409 && /webhook/i.test(err.message));
        if (webhookActive) {
          $('#telegram-takeover-wrap').hidden = false;
          error.textContent = 'This bot already sends updates to another webhook. Check the takeover box only if this Console should replace it.';
          error.hidden = false;
          takeover.focus();
        } else {
          error.textContent = err.message;
          error.hidden = false;
        }
      } finally {
        submit.disabled = false;
        submit.textContent = 'Register bot';
      }
    });
  }

  // ---------------------------------------------------------------- durable lifecycle archive / restore / remove

  let archivesFetching = false;
  let archivesFetchPromise = null;
  let archivesRequestedGeneration = 0;
  let archivesCompletedGeneration = 0;
  let archivesCurrent = false;
  let lifecycleRefreshInFlight = false;

  function lifecycleAvailable() {
    return state.session?.accessAdmin === true && state.session?.lifecycleAvailable === true;
  }

  function syncLifecycleVisibility() {
    const admin = state.session?.accessAdmin === true;
    const available = lifecycleAvailable();
    for (const filter of document.querySelectorAll('[data-lifecycle-filter]')) {
      filter.hidden = !admin;
      for (const button of filter.querySelectorAll('[data-lifecycle-view="archived"]')) {
        button.disabled = !available;
        button.title = available
          ? 'Show archived resources'
          : 'Archive management is not activated on this Console';
        button.setAttribute('aria-disabled', String(!available));
      }
    }
    if (!available) {
      state.archives = null;
      archivesCurrent = false;
      for (const page of ['projects', 'servers', 'docker']) ui.lifecycleViews[page] = 'active';
      const dialog = $('#lifecycle-dialog');
      if (dialog?.open) dialog.close();
    }
    syncLifecycleFilters();
  }

  function archivesForPage(page) {
    const rows = state.archives || [];
    if (page === 'projects') return rows.filter((row) => row?.target_kind === 'project');
    if (page === 'servers') return rows.filter((row) => row?.target_kind === 'server');
    if (page === 'docker') return rows.filter((row) => row?.target_kind === 'container');
    return [];
  }

  function syncLifecycleFilters() {
    for (const page of ['projects', 'servers', 'docker']) {
      const filter = document.querySelector(`[data-lifecycle-filter="${page}"]`);
      if (!filter) continue;
      const view = ui.lifecycleViews[page];
      for (const button of filter.querySelectorAll('[data-lifecycle-view]')) {
        const selected = button.dataset.lifecycleView === view;
        button.classList.toggle('is-selected', selected);
        button.setAttribute('aria-pressed', String(selected));
      }
      // Until the owner-only archive endpoint answers, omit the badge instead
      // of presenting an invented zero as durable host state.
      setCount(`${page}-archived-count`, archivesCurrent && Array.isArray(state.archives)
        ? archivesForPage(page).length : null);
    }
  }

  async function loadArchives({ force = false } = {}) {
    if (!lifecycleAvailable()) return;
    if (!force && state.archives && archivesCurrent) {
      syncLifecycleFilters();
      return;
    }
    const requestedGeneration = ++archivesRequestedGeneration;
    while (archivesCompletedGeneration < requestedGeneration) {
      if (!archivesFetchPromise) {
        const fetchGeneration = archivesRequestedGeneration;
        archivesFetching = true;
        archivesFetchPromise = (async () => {
          try {
            const result = await api('/api/lifecycle/list');
            if (!Array.isArray(result?.archives)) throw new ApiError('Archive list is malformed', 502);
            state.archives = result.archives;
            archivesCurrent = true;
            clearBanner('lifecycle');
            bump();
            syncLifecycleFilters();
            renderAll(true);
          } catch (err) {
            archivesCurrent = false;
            syncLifecycleFilters();
            renderAll(true);
            if (err.status !== 401 && ['projects', 'servers', 'docker'].some(
              (page) => currentPage() === page && ui.lifecycleViews[page] === 'archived',
            )) {
              showBanner(err, () => loadArchives({ force: true }), 'lifecycle');
            }
          } finally {
            archivesCompletedGeneration = Math.max(
              archivesCompletedGeneration, fetchGeneration,
            );
          }
        })();
      }
      const pending = archivesFetchPromise;
      await pending;
      if (archivesFetchPromise === pending) {
        archivesFetchPromise = null;
        archivesFetching = false;
      }
    }
  }

  function setLifecycleView(page, view) {
    if (state.session?.accessAdmin !== true || !['active', 'archived'].includes(view)) return;
    if (view === 'archived' && !lifecycleAvailable()) return;
    ui.lifecycleViews[page] = view;
    ui.resourcePages[page] = 0;
    ui.archiveGroupsExpanded[page].clear();
    bump();
    syncLifecycleFilters();
    if (view === 'archived') loadArchives();
    renderAll(true);
    queueMicrotask(() => {
      document.querySelector(
        `[data-lifecycle-filter="${page}"] [data-lifecycle-view="${view}"]`,
      )?.focus({ preventScroll: true });
    });
  }

  function lifecycleTarget(kind, id, displayName, page, extras = {}) {
    if (!id) return null;
    return {
      target_kind: kind,
      target_id: String(id),
      display_name: displayName || lifecycleKindLabel(kind),
      page,
      ...extras,
    };
  }

  function lifecycleIdentityMatches(target, kind, id) {
    return !!target
      && target.target_kind === kind
      && String(target.target_id) === String(id);
  }

  function lifecycleKindLabel(kind) {
    if (kind === 'project') return 'Project';
    if (kind === 'server') return 'Server';
    if (kind === 'container') return 'Docker container';
    if (kind === 'worktree') return 'Git worktree';
    return 'Coordinator resource';
  }

  function archiveButton(target, { compact = false } = {}) {
    if (!lifecycleAvailable() || !target) return compact ? ghostIconSlot() : null;
    const inventoryProblem = inventoryMutationProblemOf(state.overview, target);
    const blocked = !!inventoryProblem;
    return h('button', {
      class: compact ? 'iconbtn' : 'btn small', type: 'button',
      'data-fk': `archive:${target.target_kind}:${target.target_id}`,
      disabled: blocked || undefined,
      'aria-label': blocked
        ? `Archive ${target.display_name} unavailable — repository ownership needs attention`
        : `Archive ${target.display_name}`,
      title: blocked
        ? 'Archive is disabled only for this affected resource until its exact ownership problem is resolved'
        : 'Archive — stop and fence this resource while retaining its data and history',
      onclick: (event) => openLifecycleDialog('archive', target, event.currentTarget),
    }, icon('archive'), compact ? null : 'Archive');
  }

  function workerRemoveButton(server, { compact = false } = {}) {
    if (state.session?.accessAdmin !== true || !server?.supervision) {
      return compact ? ghostIconSlot() : null;
    }
    const inventoryProblem = inventoryMutationProblemOf(state.overview, {
      target_kind: 'server', target_id: server.id,
    });
    return h('button', {
      class: compact ? 'iconbtn' : 'btn small', type: 'button',
      'data-fk': `worker-remove:${server.id}`,
      disabled: !!inventoryProblem || undefined,
      'aria-label': inventoryProblem
        ? `Remove worker ${server.name || server.id} unavailable — repository ownership needs attention`
        : `Remove worker ${server.name || server.id}`,
      title: inventoryProblem
        ? 'Removal is disabled only for this affected worker until its exact ownership problem is resolved'
        : 'Remove worker — first stop, archive and hide it; permanent deletion is a separate reviewed step',
      onclick: (event) => openWorkerRemovalDialog(server, event.currentTarget),
    }, icon('trash'), compact ? null : 'Remove worker');
  }

  function lifecycleList(value) {
    if (!Array.isArray(value)) return [];
    return value.map((item) => {
      if (typeof item === 'string') return item;
      if (!item || typeof item !== 'object') return String(item);
      return item.description || item.message || item.effect || item.name || item.path || item.code
        || JSON.stringify(item);
    });
  }

  function lifecyclePlanSection(title, values, blocked = false) {
    const items = lifecycleList(values);
    return h('section', { class: `lifecycle-plan-section${blocked ? ' is-blocked' : ''}` },
      h('h3', null, title),
      items.length
        ? h('ul', null, items.map((item) => h('li', null, item)))
        : h('p', { class: 'meta-passive' }, 'None'));
  }

  function renderLifecycleDialog() {
    const model = ui.lifecycleDialog;
    if (!model) return;
    const { action, target, stage, plan } = model;
    const isWorkerRemove = action === 'worker-remove';
    const plannedAction = isWorkerRemove ? String(plan?.action || '') : action;
    const workerPermanentStage = isWorkerRemove && (
      model.archivedInThisJourney || ['purge', 'forget'].includes(plannedAction)
    );
    const isArchive = action === 'archive' || (isWorkerRemove && !workerPermanentStage);
    const isPurge = action === 'purge' || workerPermanentStage;
    const isRestore = action === 'restore';
    const busy = stage === 'planning' || stage === 'applying';
    const title = isWorkerRemove
      ? (isPurge ? 'Permanently remove worker' : 'Remove worker')
      : isArchive ? 'Archive resource' : isPurge ? 'Remove permanently' : 'Restore resource';
    const summary = isWorkerRemove && isPurge
      ? 'This worker is already stopped, archived and hidden. Permanent removal deletes its active definition and projections. Its no-resurrection tombstone, audit history, crash traces and log links remain.'
      : isWorkerRemove
        ? 'Removal first stops this worker, disables automatic restart, archives its coordinator record and hides it from active views. Permanent deletion is offered only after that succeeds.'
        : isArchive
      ? 'Archiving stops and fences this exact coordinator resource. Its data and history are retained and it remains discoverable here.'
      : isPurge
        ? 'Permanent removal is available only after archival. Review the coordinator plan and type its exact confirmation phrase.'
        : 'Restoring clears the exact lifecycle fence. It does not start the resource.';
    $('#lifecycle-dialog-h').textContent = title;
    $('#lifecycle-dialog-summary').textContent = summary;
    $('#lifecycle-target').replaceChildren(
      h('strong', null, target.display_name),
      h('span', { class: 'meta-passive' },
        `${isWorkerRemove ? 'Supervised worker' : lifecycleKindLabel(target.target_kind)} managed by the server-wide coordinator`));
    const reason = $('#lifecycle-reason');
    reason.disabled = busy || stage === 'planned';

    const planHost = $('#lifecycle-plan');
    if (stage === 'planning') {
      planHost.replaceChildren(h('p', { class: 'inline-note' }, 'Refreshing host evidence and preparing an exact plan…'));
    } else if (stage === 'applying') {
      planHost.replaceChildren(h('p', { class: 'inline-note' }, isRestore
        ? 'Restoring the lifecycle fence…'
        : 'Applying the exact reviewed plan…'));
    } else if (plan) {
      planHost.replaceChildren(...[
        isWorkerRemove && model.archivedInThisJourney
          ? h('p', { class: 'worker-archived-note', role: 'status' },
              'Worker archived successfully. It is stopped, automatic restart is disabled, and it is hidden from active views. Keeping it archived is safe.')
          : null,
        lifecyclePlanSection('Effects', plan.effects),
        lifecyclePlanSection('Retained', plan.retained),
        lifecyclePlanSection('Deleted permanently', plan.deleted),
        lifecyclePlanSection('Blockers', plan.blockers, true),
      ].filter(Boolean));
    } else {
      planHost.replaceChildren();
    }

    const phrase = isPurge && plan ? String(plan.confirmation_phrase || '') : '';
    const confirmWrap = $('#lifecycle-confirm-wrap');
    confirmWrap.hidden = !phrase;
    $('#lifecycle-confirm-phrase').textContent = phrase;
    if (!phrase) $('#lifecycle-confirm').value = '';

    const submit = $('#lifecycle-submit');
    submit.classList.toggle('lifecycle-danger', isPurge && stage === 'planned');
    submit.textContent = busy
      ? (stage === 'planning' ? 'Reviewing…' : isRestore ? 'Restoring…' : 'Applying…')
      : isRestore ? 'Restore'
        : stage === 'planned' ? (isPurge ? 'Remove permanently' : (isWorkerRemove ? 'Archive worker' : 'Archive'))
          : (isWorkerRemove ? (model.archivedInThisJourney ? 'Review permanent removal' : 'Review removal')
            : (isPurge ? 'Review removal' : 'Review archive'));
    $('#lifecycle-cancel').textContent = isWorkerRemove && model.archivedInThisJourney
      ? 'Keep archived'
      : 'Cancel';
    const blocked = lifecycleList(plan?.blockers).length > 0;
    const phraseMismatch = !!phrase && $('#lifecycle-confirm').value !== phrase;
    submit.disabled = busy || blocked || phraseMismatch;
  }

  function openWorkerRemovalDialog(server, trigger) {
    if (state.session?.accessAdmin !== true || !server?.supervision) return;
    const inventoryProblem = inventoryMutationProblemOf(state.overview, {
      target_kind: 'server', target_id: server.id,
    });
    if (inventoryProblem) {
      showBanner(inventoryProblem.kind === 'inventory'
        ? 'Worker removal is disabled because the repository inventory contract is invalid.'
        : 'Worker removal is disabled only for this worker until its ownership problem is resolved.');
      return;
    }
    ui.lifecycleDialog = {
      action: 'worker-remove',
      target: lifecycleTarget('server', server.id, server.name || 'Unnamed worker', 'servers'),
      stage: 'intro',
      plan: null,
      archivedInThisJourney: false,
      returnFocusKey: trigger?.dataset?.fk || null,
    };
    $('#lifecycle-form').reset();
    $('#lifecycle-form-error').hidden = true;
    renderLifecycleDialog();
    const dialog = $('#lifecycle-dialog');
    dialog.showModal();
    queueMicrotask(() => $('#lifecycle-reason').focus());
  }

  function openLifecycleDialog(action, target, trigger) {
    if (!lifecycleAvailable() || !target) return;
    const inventoryProblem = inventoryMutationProblemOf(state.overview, target);
    if (inventoryProblem) {
      showBanner(inventoryProblem.kind === 'inventory'
        ? 'Lifecycle controls are disabled because the repository inventory contract is invalid.'
        : 'Lifecycle controls are disabled only for this affected resource until its ownership problem is resolved.');
      return;
    }
    ui.lifecycleDialog = {
      action,
      target,
      stage: 'intro',
      plan: null,
      returnFocusKey: trigger?.dataset?.fk || null,
    };
    $('#lifecycle-form').reset();
    $('#lifecycle-form-error').hidden = true;
    renderLifecycleDialog();
    const dialog = $('#lifecycle-dialog');
    dialog.showModal();
    queueMicrotask(() => $('#lifecycle-reason').focus());
  }

  function closeLifecycleDialog({ restoreFocus = true } = {}) {
    const model = ui.lifecycleDialog;
    const dialog = $('#lifecycle-dialog');
    if (dialog.open) dialog.close();
    ui.lifecycleDialog = null;
    if (restoreFocus && model?.returnFocusKey) {
      queueMicrotask(() => document.querySelector(
        `[data-fk="${CSS.escape(model.returnFocusKey)}"]`,
      )?.focus({ preventScroll: true }));
    }
  }

  async function lifecycleSucceeded(model) {
    const archived = model.action === 'archive' || model.action === 'purge';
    const view = archived ? 'archived' : 'active';
    ui.lifecycleViews[model.target.page] = view;
    ui.lifecycleFocus = model.action === 'purge' ? null : {
      ...model.target,
      view,
      // A poll already in flight can finish before the post-action refresh.
      // Preserve reveal intent across that race; worktrees have no active row
      // on Projects, so they may fall back to the selected filter immediately.
      fallbackAfter: model.target.target_kind === 'worktree'
        ? Date.now() : Date.now() + (POLL_MS * 2),
    };
    closeLifecycleDialog({ restoreFocus: false });
    // A server/container can also be acted on from the Projects tree. Its
    // durable record belongs to Servers/Docker, so move to that canonical
    // collection before refreshing and revealing the post-action target.
    lifecycleRefreshInFlight = true;
    const refreshes = Promise.all([
      refreshOverview({ force: true, fresh: true }),
      loadArchives({ force: true }),
    ]);
    if (currentPage() !== model.target.page) location.hash = `#/${model.target.page}`;
    try {
      await refreshes;
    } finally {
      lifecycleRefreshInFlight = false;
    }
    syncLifecycleFilters();
    renderAll(true);
    if (model.action === 'purge') {
      queueMicrotask(() => document.querySelector(
        `[data-lifecycle-filter="${model.target.page}"] [data-lifecycle-view="archived"]`,
      )?.focus({ preventScroll: true }));
    }
    announce(model.action === 'archive'
      ? `${model.target.display_name} archived`
      : model.action === 'purge'
        ? `${model.target.display_name} removed permanently`
        : `${model.target.display_name} restored; it remains stopped`);
  }

  async function submitLifecycleDialog() {
    const model = ui.lifecycleDialog;
    if (!model || ['planning', 'applying'].includes(model.stage)) return;
    const error = $('#lifecycle-form-error');
    error.hidden = true;
    const inventoryProblem = inventoryMutationProblemOf(state.overview, model.target);
    if (inventoryProblem) {
      error.textContent = inventoryProblem.kind === 'inventory'
        ? 'Inventory changed: the repository tree contract is invalid, so this action cannot continue.'
        : 'Inventory changed: this exact resource now has an ownership or lifecycle problem, so its action cannot continue.';
      error.hidden = false;
      return;
    }
    try {
      if (model.action === 'worker-remove') {
        const workerRequest = (plan = null, confirmationPhrase = null) => {
          const body = {
            id: model.target.target_id,
            action: 'remove',
            reason: $('#lifecycle-reason').value,
          };
          if (plan) {
            body.remove_plan_id = plan.plan_id;
            body.remove_plan_fingerprint = plan.plan_fingerprint || plan.fingerprint;
            body.remove_confirmation_phrase = confirmationPhrase == null
              ? String(plan.confirmation_phrase || '')
              : confirmationPhrase;
          }
          return api('/api/workers/action', { method: 'POST', body });
        };
        const checkedPlan = (response) => {
          const runtime = response?.runtime;
          const candidate = runtime?.result?.plan;
          if (
            runtime?.action !== 'remove'
            || runtime?.target?.kind !== 'service'
            || String(runtime?.target?.id ?? '') !== String(model.target.target_id)
            || !candidate?.plan_id
            || !(candidate.plan_fingerprint || candidate.fingerprint)
            || !['archive', 'purge', 'forget'].includes(candidate.action)
            || !['effects', 'retained', 'deleted', 'blockers'].every(
              (field) => Array.isArray(candidate[field]),
            )
          ) {
            throw new ApiError('Coordinator returned an incomplete worker removal plan', 502);
          }
          return candidate;
        };

        if (model.stage === 'intro') {
          model.stage = 'planning';
          renderLifecycleDialog();
          model.plan = checkedPlan(await workerRequest());
          model.stage = 'planned';
          renderLifecycleDialog();
          queueMicrotask(() => {
            if (['purge', 'forget'].includes(model.plan.action)
                && model.plan.confirmation_phrase) $('#lifecycle-confirm').focus();
            else $('#lifecycle-submit').focus();
          });
          return;
        }

        const permanent = ['purge', 'forget'].includes(model.plan?.action);
        const phrase = String(model.plan?.confirmation_phrase || '');
        if (permanent && (!phrase || $('#lifecycle-confirm').value !== phrase)) {
          throw new ApiError('Type the exact confirmation phrase before permanent removal', 400);
        }
        model.stage = 'applying';
        renderLifecycleDialog();
        const applied = await workerRequest(
          model.plan,
          permanent ? $('#lifecycle-confirm').value : '',
        );
        const runtime = applied?.runtime;
        if (permanent) {
          if (runtime?.classification !== 'worker_removed') {
            throw new ApiError('Coordinator did not prove permanent worker removal', 409, applied);
          }
          closeLifecycleDialog({ restoreFocus: false });
          await Promise.all([
            refreshOverview({ force: true, fresh: true }),
            loadArchives({ force: true }),
          ]);
          renderAll(true);
          announce(`${model.target.display_name} removed permanently`);
          return;
        }
        if (runtime?.classification !== 'worker_archived') {
          throw new ApiError('Coordinator did not prove the worker was archived and stopped', 409, applied);
        }

        // Archival and permanent deletion are intentionally two distinct
        // mutations. The only automatic follow-up is a read-only purge plan.
        model.archivedInThisJourney = true;
        model.plan = null;
        model.stage = 'planning';
        renderLifecycleDialog();
        await Promise.all([
          refreshOverview({ force: true, fresh: true }),
          loadArchives({ force: true }),
        ]);
        model.plan = checkedPlan(await workerRequest());
        if (!['purge', 'forget'].includes(model.plan.action)) {
          throw new ApiError('Worker was archived, but the coordinator did not return a permanent-removal plan', 502);
        }
        model.stage = 'planned';
        renderLifecycleDialog();
        queueMicrotask(() => $('#lifecycle-confirm').focus());
        announce(`${model.target.display_name} archived and hidden`);
        return;
      }
      if (model.action === 'restore') {
        model.stage = 'applying';
        renderLifecycleDialog();
        await api('/api/lifecycle/restore', {
          method: 'POST',
          body: {
            target_kind: model.target.target_kind,
            target_id: model.target.target_id,
            reason: $('#lifecycle-reason').value,
          },
        });
        await lifecycleSucceeded(model);
        return;
      }
      if (model.stage === 'intro') {
        model.stage = 'planning';
        renderLifecycleDialog();
        const result = await api('/api/lifecycle/plan', {
          method: 'POST',
          body: {
            target_kind: model.target.target_kind,
            target_id: model.target.target_id,
            action: model.action,
            reason: $('#lifecycle-reason').value,
          },
        });
        if (!result?.plan?.plan_id || !(result.plan.plan_fingerprint || result.plan.fingerprint)) {
          throw new ApiError('Coordinator returned an incomplete lifecycle plan', 502);
        }
        if (!['effects', 'retained', 'deleted', 'blockers'].every(
          (field) => Array.isArray(result.plan[field]),
        )) {
          throw new ApiError('Coordinator returned incomplete lifecycle plan details', 502);
        }
        model.plan = result.plan;
        model.stage = 'planned';
        renderLifecycleDialog();
        queueMicrotask(() => {
          if (model.action === 'purge' && model.plan.confirmation_phrase) $('#lifecycle-confirm').focus();
          else $('#lifecycle-submit').focus();
        });
        return;
      }
      const phrase = String(model.plan?.confirmation_phrase || '');
      if (model.action === 'purge' && (!phrase || $('#lifecycle-confirm').value !== phrase)) {
        throw new ApiError('Type the exact confirmation phrase before permanent removal', 400);
      }
      model.stage = 'applying';
      renderLifecycleDialog();
      await api('/api/lifecycle/apply', {
        method: 'POST',
        body: {
          plan_id: model.plan.plan_id,
          plan_fingerprint: model.plan.plan_fingerprint || model.plan.fingerprint,
          confirmation_phrase: phrase ? $('#lifecycle-confirm').value : '',
        },
      });
      await lifecycleSucceeded(model);
    } catch (err) {
      if (!ui.lifecycleDialog || err.status === 401) return;
      model.stage = model.plan ? 'planned' : 'intro';
      error.textContent = model.action === 'worker-remove' && model.archivedInThisJourney && !model.plan
        ? `Worker was archived successfully, but its permanent-removal plan is unavailable: ${err.message}`
        : err.message;
      error.hidden = false;
      renderLifecycleDialog();
    }
  }

  function wireLifecycle() {
    for (const filter of document.querySelectorAll('[data-lifecycle-filter]')) {
      for (const button of filter.querySelectorAll('[data-lifecycle-view]')) {
        button.addEventListener('click', () => setLifecycleView(
          filter.dataset.lifecycleFilter,
          button.dataset.lifecycleView,
        ));
      }
    }
    $('#lifecycle-dialog-close').append(icon('x'));
    $('#lifecycle-dialog-close').addEventListener('click', () => closeLifecycleDialog());
    $('#lifecycle-cancel').addEventListener('click', () => closeLifecycleDialog());
    $('#lifecycle-dialog').addEventListener('cancel', (event) => {
      event.preventDefault();
      closeLifecycleDialog();
    });
    $('#lifecycle-confirm').addEventListener('input', renderLifecycleDialog);
    $('#lifecycle-form').addEventListener('submit', (event) => {
      event.preventDefault();
      submitLifecycleDialog();
    });
  }

  // ---------------------------------------------------------------- metrics history

  let metricsFetching = false;

  async function refreshMetrics() {
    if (metricsFetching) return;
    metricsFetching = true;
    const limit = currentPage() === 'performance' ? METRICS_LIMIT_FULL : METRICS_LIMIT_SPARK;
    try {
      const data = await api(`/api/metrics/history?limit=${limit}`);
      state.metrics = data;
      state.metricsAt = Date.now();
      state.metricsMap = new Map((data?.entities || []).map((e) => [e.key, e]));
      bump();
      renderAll();
      if (currentPage() === 'tests') loadTests();
    } catch (err) {
      // Quiet failure: charts just go stale; the overview poll owns the banner.
      if (err.status === 401) return;
    } finally {
      metricsFetching = false;
    }
  }

  const metricsEntity = (key) => state.metricsMap.get(key) || null;

  // ---------------------------------------------------------------- hidden items (prefs)

  // Hidden identities: servers by identity key ("<project>::<name>"),
  // containers by name, projects by usage_key. Hiding is persisted server-side
  // (shared across devices); an item is auto-unhidden the moment the
  // coordinator reports it running again, so nothing active can stay hidden.

  function hiddenSet(kind) {
    return new Set(state.prefs?.hidden?.[kind] ?? []);
  }

  let prefsLoaded = false;
  let prefsSaving = false;

  async function loadPrefs() {
    try {
      state.prefs = await api('/api/prefs');
      prefsLoaded = true;
      bump();
      renderAll();
    } catch {
      // Display-only fallback; all mutations are DELTAS, so a stale (even
      // empty) local copy can never wipe hides made elsewhere. The next
      // overview poll retries the fetch.
      if (!state.prefs) state.prefs = { version: 1, hidden: { servers: [], docker: [], projects: [] } };
    }
  }

  // All hidden-state mutations are hide/unhide deltas — never full lists — so
  // concurrent writers (rapid clicks, the auto-unhide poll, another device)
  // merge server-side instead of clobbering each other.
  async function sendHiddenDelta(delta) {
    try {
      state.prefs = await api('/api/prefs', { method: 'PATCH', body: delta });
      prefsLoaded = true;
      bump();
      renderAll();
    } catch (err) {
      if (err.status !== 401) showBanner(err, () => sendHiddenDelta(delta));
    }
  }

  function hideItem(kind, key, label) {
    announce(`${label} hidden — it reappears automatically when it runs`);
    sendHiddenDelta({ hide: { [kind]: [key] } });
  }

  function unhideItem(kind, key, label) {
    announce(`${label} shown again`);
    sendHiddenDelta({ unhide: { [kind]: [key] } });
  }

  const isServerRunning = (s) => ['running', 'starting', 'unhealthy'].includes(s.status);
  const isOperationalServer = (s) => [
    'running', 'starting', 'unhealthy', 'stopping', 'stopped',
  ].includes(s.status);
  // Hide-gating and auto-unhide use "active" (anything not cleanly down):
  // a crash-looping "Restarting (1) …" container is very much running work
  // and must be neither hideable nor kept hidden.
  const isContainerActive = (c) => !/^\s*(exited|created|dead|stopped)\b/i.test(String(c.status || ''));
  // Framework-owned Testcontainers are disposable test dependencies, not
  // deployable project services. Keep them out of normal inventory attention.
  const isTransientTestContainer = (c) => c?.transient_test === true;

  // ---- docker-hosted web servers ------------------------------------------
  // Mirrors src/routes.mjs parsePublishedPorts: `docker ps` Ports column
  // ("0.0.0.0:5001->5001/tcp, :::9000-9001->9000-9001/tcp, 5432/tcp") into
  // loopback-reachable published TCP mappings.
  function parsePublishedPorts(text) {
    const out = [];
    for (const rawEntry of String(text ?? '').split(',')) {
      const entry = rawEntry.trim();
      if (!entry || !entry.includes('->')) continue;
      const arrow = entry.lastIndexOf('->');
      const right = entry.slice(arrow + 2).trim().match(/^(\d+)(?:-(\d+))?\/([a-z0-9]+)$/i);
      if (!right || right[3].toLowerCase() !== 'tcp') continue;
      const left = entry.slice(0, arrow).trim().match(/^(.*):(\d+)(?:-(\d+))?$/);
      if (!left) continue;
      const hostAddr = left[1].replace(/^\[/, '').replace(/\]$/, '');
      const hostStart = Number(left[2]);
      const hostEnd = left[3] ? Number(left[3]) : hostStart;
      const contStart = Number(right[1]);
      const contEnd = right[2] ? Number(right[2]) : contStart;
      if (hostEnd - hostStart !== contEnd - contStart || hostEnd < hostStart) continue;
      for (let i = 0; i <= hostEnd - hostStart; i += 1) {
        out.push({ hostAddr, hostPort: hostStart + i, containerPort: contStart + i });
      }
    }
    return out;
  }

  // Only v4-reachable publishes count — the proxy dials 127.0.0.1, and v4/v6
  // loopback are separate namespaces (mirrors src/routes.mjs).
  const V4_ADDRS = new Set(['0.0.0.0', '127.0.0.1', '']);

  // Distinct container ports with the host port each is reachable on.
  function publishedContainerPorts(text) {
    const mappings = parsePublishedPorts(text);
    const byPort = new Map();
    for (const m of mappings) {
      if (byPort.has(m.containerPort)) continue;
      const v4 = mappings.find((x) => x.containerPort === m.containerPort && V4_ADDRS.has(x.hostAddr));
      if (v4) byPort.set(m.containerPort, v4.hostPort);
    }
    return [...byPort.entries()]
      .map(([containerPort, hostPort]) => ({ containerPort, hostPort }))
      .sort((a, b) => a.containerPort - b.containerPort);
  }

  // The route (if any) that publishes this container at a subdomain.
  function dockerRouteFor(o, c) {
    return (o.routes || []).find((r) => r.kind === 'docker' && r.containerName === c.name) || null;
  }

  // A container earns a row on the Servers page when a browser could reach
  // it: it publishes a non-database TCP port, or it already has a subdomain
  // route (a stopped container publishes nothing, so the route keeps it
  // startable from this page).
  function isWebServerContainer(o, group, c) {
    if (group.dbNames.has(c.name)) return false;
    return publishedContainerPorts(c.ports).length > 0 || !!dockerRouteFor(o, c);
  }

  function containerStatusMeta(c) {
    const status = String(c.status || '');
    // Real docker reports paused as "Up 3 minutes (Paused)" — check it
    // before the generic Up match or it reads as a healthy green badge.
    if (/\(paused\)/i.test(status)) return { css: 'warn', label: 'paused' };
    if (isContainerRunning(c)) {
      if (/\(unhealthy\)/i.test(status)) return { css: 'err', label: 'unhealthy' };
      if (/\(health: starting\)/i.test(status)) return { css: 'warn', label: 'starting' };
      return { css: 'ok', label: 'running' };
    }
    if (/^\s*restarting/i.test(status)) return { css: 'err', label: 'restarting' };
    return { css: 'dim', label: 'stopped' };
  }

  // Anything the coordinator reports as running must never stay hidden.
  async function autoUnhide(o) {
    if (!state.prefs || !o?.inventory || prefsSaving) return;
    const hidden = state.prefs.hidden || {};
    const unhide = {};

    const servers = o.inventory.servers || [];
    const runningServerKeys = new Set(servers.filter(isServerRunning).map((s) => s.key));
    const unhideServers = (hidden.servers || []).filter((k) => runningServerKeys.has(k));
    if (unhideServers.length) unhide.servers = unhideServers;

    const containers = o.inventory.docker?.available
      ? (o.inventory.docker.containers || []).filter((c) => !isTransientTestContainer(c)) : [];
    const activeContainers = new Set(containers.filter(isContainerActive).map((c) => c.name));
    const unhideDocker = (hidden.docker || []).filter((n) => activeContainers.has(n));
    if (unhideDocker.length) unhide.docker = unhideDocker;

    const activeProjects = new Set(
      projectGroupsOf(o).filter((g) => g.runningCount > 0).map((g) => g.key),
    );
    const unhideProjects = (hidden.projects || []).filter((k) => activeProjects.has(k));
    if (unhideProjects.length) unhide.projects = unhideProjects;

    if (Object.keys(unhide).length === 0) return;
    prefsSaving = true;
    try {
      state.prefs = await api('/api/prefs', { method: 'PATCH', body: { unhide } });
      prefsLoaded = true;
      bump();
      renderAll();
    } catch {
      // Quiet: the next poll retries.
    } finally {
      prefsSaving = false;
    }
  }

  function hideButton(kind, key, label) {
    return h('button', {
      class: 'iconbtn', type: 'button',
      'data-fk': `hide:${kind}:${key}`,
      'aria-label': `Hide ${label} until it runs again`,
      title: 'Hide until it runs again',
      onclick: () => hideItem(kind, key, label),
    }, icon('eyeoff'));
  }

  function unhideButton(kind, key, label) {
    return h('button', {
      class: 'iconbtn', type: 'button',
      'data-fk': `unhide:${kind}:${key}`,
      'aria-label': `Show ${label} again`,
      title: 'Show again',
      onclick: () => unhideItem(kind, key, label),
    }, icon('eye'));
  }

  // Per-page toggle revealing hidden rows (dimmed, with an unhide control).
  function revealToggle(page, hiddenCount) {
    if (!hiddenCount && !ui.reveal.has(page)) return null;
    const revealing = ui.reveal.has(page);
    return h('p', { class: 'hidden-note' },
      h('button', {
        class: 'linklike', type: 'button',
        'data-fk': `reveal:${page}`,
        onclick: () => {
          if (revealing) ui.reveal.delete(page); else ui.reveal.add(page);
          bump();
          renderAll(true);
        },
      }, icon(revealing ? 'eyeoff' : 'eye'),
        revealing ? 'Conceal hidden items' : `Show ${hiddenCount} hidden item${sfx(hiddenCount)}`));
  }

  // Large host-wide inventories are losslessly paged rather than appended to
  // one document. Besides keeping ordinary rendering responsive, this bounds
  // the element-candidate set inspected by the Codex in-app annotation layer.
  function pageSlice(items, requestedPage) {
    const total = items.length;
    const pageCount = Math.max(1, Math.ceil(total / RESOURCE_PAGE_SIZE));
    const requested = Number.isInteger(requestedPage) ? requestedPage : 0;
    const page = Math.min(Math.max(0, requested), pageCount - 1);
    const offset = page * RESOURCE_PAGE_SIZE;
    const pagedItems = items.slice(offset, offset + RESOURCE_PAGE_SIZE);
    return {
      items: pagedItems,
      total,
      page,
      pageCount,
      start: total ? offset + 1 : 0,
      end: offset + pagedItems.length,
    };
  }

  function resourcePager(kind, label, info) {
    if (info.pageCount <= 1) return null;
    const go = (page) => {
      ui.resourcePages[kind] = page;
      bump();
      renderAll(true);
    };
    return h('nav', { class: 'resource-pager', 'aria-label': `${label} pages` },
      h('span', { class: 'resource-page-status', 'aria-live': 'polite' },
        `Showing ${info.start}–${info.end} of ${info.total} visible ${label.toLowerCase()}`),
      h('span', { class: 'resource-page-actions' },
        h('button', {
          class: 'btn small', type: 'button',
          'data-fk': `pager:${kind}:prev`,
          disabled: info.page === 0 || undefined,
          'aria-label': `Previous ${label.toLowerCase()} page`,
          'data-disabled-focus-fallback': `pager:${kind}:next`,
          onclick: () => go(info.page - 1),
        }, 'Previous'),
        h('span', { class: 'meta-passive' }, `Page ${info.page + 1} of ${info.pageCount}`),
        h('button', {
          class: 'btn small', type: 'button',
          'data-fk': `pager:${kind}:next`,
          disabled: info.page + 1 >= info.pageCount || undefined,
          'aria-label': `Next ${label.toLowerCase()} page`,
          'data-disabled-focus-fallback': `pager:${kind}:prev`,
          onclick: () => go(info.page + 1),
        }, 'Next')));
  }

  function projectScopePager(scopeKey, label, info) {
    if (info.pageCount <= 1) return null;
    const go = (page) => {
      ui.projectScopePages.set(scopeKey, page);
      bump();
      renderAll(true);
    };
    return h('nav', { class: 'resource-pager', 'aria-label': `${label} pages` },
      h('span', { class: 'resource-page-status', 'aria-live': 'polite' },
        `Showing ${info.start}–${info.end} of ${info.total} visible ${label.toLowerCase()}`),
      h('span', { class: 'resource-page-actions' },
        h('button', {
          class: 'btn small', type: 'button',
          'data-fk': `pager:projects:${scopeKey}:prev`,
          disabled: info.page === 0 || undefined,
          'aria-label': `Previous ${label.toLowerCase()} page`,
          'data-disabled-focus-fallback': `pager:projects:${scopeKey}:next`,
          onclick: () => go(info.page - 1),
        }, 'Previous'),
        h('span', { class: 'meta-passive' }, `Page ${info.page + 1} of ${info.pageCount}`),
        h('button', {
          class: 'btn small', type: 'button',
          'data-fk': `pager:projects:${scopeKey}:next`,
          disabled: info.page + 1 >= info.pageCount || undefined,
          'aria-label': `Next ${label.toLowerCase()} page`,
          'data-disabled-focus-fallback': `pager:projects:${scopeKey}:prev`,
          onclick: () => go(info.page + 1),
        }, 'Next')));
  }

  // One disclosed project at a time keeps long operational collections
  // scannable and preserves the bounded mounted-resource contract.
  function setExclusiveExpansion(expandedKeys, key) {
    const wasExpanded = expandedKeys.has(key);
    expandedKeys.clear();
    if (!wasExpanded) expandedKeys.add(key);
  }

  // ---------------------------------------------------------------- project grouping

  // Repository families come only from the coordinator's authoritative tree.
  // The browser joins resources by supplied immutable IDs and fails closed if
  // the producer omits or corrupts that tree; paths, names, and flat usage rows
  // never manufacture repository associations.
  function repositoryTreeContractProblemsOf(inv) {
    const invalid = (name) => [{ kind: 'inventory', name }];
    if (!inv || typeof inv !== 'object' || Array.isArray(inv)) {
      return invalid('normalized inventory is missing or malformed');
    }
    if (!Array.isArray(inv.repository_trees)) {
      return invalid('the authoritative repository tree is missing or malformed');
    }
    const records = (value) => Array.isArray(value)
      && value.every((item) => item && typeof item === 'object' && !Array.isArray(item));
    const exactIds = (value) => Array.isArray(value)
      && value.every((item) => typeof item === 'string' && item.length > 0)
      && new Set(value).size === value.length;
    const repositories = inv.repositories;
    if (!records(repositories)) return invalid('repository records are missing or malformed');

    const repositoriesById = new Map();
    const repositoryRoots = new Set();
    for (const repository of repositories) {
      const repoId = repository.repo_id;
      const canonicalRoot = repository.canonical_root;
      if (typeof repoId !== 'string' || !repoId
          || typeof canonicalRoot !== 'string' || !canonicalRoot.startsWith('/')
          || repositoriesById.has(repoId) || repositoryRoots.has(canonicalRoot)) {
        return invalid('repository identities are incomplete or duplicated');
      }
      repositoriesById.set(repoId, repository);
      repositoryRoots.add(canonicalRoot);
    }

    const normalizedResources = inv.resources;
    if (!normalizedResources || typeof normalizedResources !== 'object'
        || !records(normalizedResources.servers)
        || !records(normalizedResources.docker)
        || !records(normalizedResources.databases)
        || !records(inv.observations?.docker)
        || !records(inv.observations?.databases)
        || !records(inv.unassigned_resources)
        || !records(inv.lifecycle_violations)) {
      return invalid('normalized repository resource evidence is missing or malformed');
    }

    // An authoritative tree can coexist with producer-reported ownership
    // failures. Those resources remain visible as blocked diagnostics, but
    // are not invented as repository members by this client.
    const reportedProblems = [...inv.unassigned_resources, ...inv.lifecycle_violations];
    const reportedUnassignedServers = new Set();
    const reportedUnassignedContainers = new Set();
    const reportedUnassignedDatabases = new Set();
    const reportedLifecycleServers = new Set();
    const reportedLifecycleContainers = new Set();
    for (const item of reportedProblems) {
      const kind = item.resource_kind;
      const id = item.resource_id;
      if (typeof kind !== 'string' || !kind || typeof id !== 'string' || !id) {
        return invalid('an ownership problem has no immutable resource identity');
      }
      const lifecycle = item.lifecycle_violation === true
        || inv.lifecycle_violations.includes(item);
      if (kind === 'server') {
        (lifecycle ? reportedLifecycleServers : reportedUnassignedServers).add(id);
      } else if (kind === 'container') {
        (lifecycle ? reportedLifecycleContainers : reportedUnassignedContainers).add(id);
      } else if (kind === 'database') {
        reportedUnassignedDatabases.add(id);
      }
    }

    const serversById = new Map();
    for (const server of normalizedResources.servers) {
      const id = server.server_definition_id;
      if (typeof id !== 'string' || !id) return invalid('a server has no immutable ID');
      const matches = serversById.get(id) || [];
      matches.push(server);
      serversById.set(id, matches);
    }
    const containersById = new Map();
    for (const container of normalizedResources.docker) {
      const id = container.docker_resource_id;
      if (typeof id !== 'string' || !id) return invalid('a container has no immutable ID');
      const matches = containersById.get(id) || [];
      matches.push(container);
      containersById.set(id, matches);
    }
    const databasesById = new Map();
    for (const database of normalizedResources.databases) {
      const id = database.database_binding_id;
      if (typeof id !== 'string' || !id) return invalid('a database has no immutable binding ID');
      const matches = databasesById.get(id) || [];
      matches.push(database);
      databasesById.set(id, matches);
    }

    const familyIds = new Set();
    const classifiedRepositoryIds = new Set();
    const classifiedServerIds = new Set();
    const classifiedContainerIds = new Set();
    const classifiedDatabaseIds = new Set();
    for (const tree of inv.repository_trees) {
      const familyId = tree.family_id;
      const root = tree.root_repository;
      if (typeof familyId !== 'string' || !familyId || familyIds.has(familyId)
          || !root || typeof root !== 'object' || Array.isArray(root)) {
        return invalid('a repository family identity is missing or duplicated');
      }
      familyIds.add(familyId);
      const rootRepository = repositoriesById.get(root.repo_id);
      if (!rootRepository
          || root.canonical_root !== rootRepository.canonical_root
          || root.display_name !== rootRepository.display_name) {
        return invalid('a repository family root contradicts its repository record');
      }
      if (!records(tree.scopes) || tree.scopes.length === 0) {
        return invalid('a repository family has no valid scopes');
      }
      const rootScopes = tree.scopes.filter((scope) => scope.kind === 'root');
      if (rootScopes.length !== 1 || rootScopes[0].repo_id !== root.repo_id) {
        return invalid('a repository family must contain exactly its own root scope');
      }
      for (const scope of tree.scopes) {
        if (scope.kind !== 'root' && scope.kind !== 'temporary') {
          return invalid('a repository scope has an unknown kind');
        }
        const repository = repositoriesById.get(scope.repo_id);
        if (!repository || classifiedRepositoryIds.has(scope.repo_id)
            || repository.host_id !== rootRepository.host_id
            || scope.canonical_root !== repository.canonical_root
            || scope.display_name !== repository.display_name
            || (scope.kind === 'temporary' && scope.repo_id === root.repo_id)
            || !exactIds(scope.server_ids)
            || !exactIds(scope.container_resource_ids)
            || !exactIds(scope.database_binding_ids)) {
          return invalid('a repository scope is inconsistent or duplicated');
        }
        classifiedRepositoryIds.add(scope.repo_id);
        for (const serverId of scope.server_ids) {
          const matches = serversById.get(serverId);
          if (!matches || matches.length !== 1 || matches[0].repo_id !== scope.repo_id
              || classifiedServerIds.has(serverId)) {
            return invalid('a server is missing, duplicated, or assigned to the wrong repository scope');
          }
          classifiedServerIds.add(serverId);
        }
        for (const containerId of scope.container_resource_ids) {
          const matches = containersById.get(containerId);
          if (!matches || matches.length !== 1 || matches[0].repo_id !== scope.repo_id
              || classifiedContainerIds.has(containerId)) {
            return invalid('a container is missing, duplicated, or assigned to the wrong repository scope');
          }
          classifiedContainerIds.add(containerId);
        }
        for (const databaseId of scope.database_binding_ids) {
          const matches = databasesById.get(databaseId);
          if (!matches || matches.length !== 1 || matches[0].repo_id !== scope.repo_id
              || !scope.container_resource_ids.includes(matches[0].docker_resource_id)
              || classifiedDatabaseIds.has(databaseId)) {
            return invalid('a database is missing, duplicated, or assigned to the wrong repository scope');
          }
          classifiedDatabaseIds.add(databaseId);
        }
      }
    }

    const sameSet = (left, right) => left.size === right.size
      && [...left].every((item) => right.has(item));
    const observedDockerIds = new Set(inv.observations.docker
      .map((item) => item.docker_resource_id).filter((item) => typeof item === 'string' && item));
    const observedDatabaseIds = new Set(inv.observations.databases
      .map((item) => item.database_binding_id).filter((item) => typeof item === 'string' && item));
    const serverEvidenceIds = new Set([
      ...classifiedServerIds,
      ...reportedUnassignedServers,
      ...reportedLifecycleServers,
    ]);
    const allowedObservedDockerIds = new Set([
      ...classifiedContainerIds,
      ...reportedUnassignedContainers,
      ...reportedLifecycleContainers,
    ]);
    const allowedObservedDatabaseIds = new Set([
      ...classifiedDatabaseIds,
      ...reportedUnassignedDatabases,
    ]);
    if (!sameSet(classifiedRepositoryIds, new Set(repositoriesById.keys()))
        || !sameSet(serverEvidenceIds, new Set(serversById.keys()))
        || [...reportedUnassignedServers].some((item) => classifiedServerIds.has(item))
        || [...reportedUnassignedContainers].some((item) => classifiedContainerIds.has(item))
        || [...observedDockerIds].some((item) => !allowedObservedDockerIds.has(item))
        || [...observedDatabaseIds].some((item) => !allowedObservedDatabaseIds.has(item))) {
      return invalid('the repository tree and explicit ownership problems do not cover every normalized resource exactly once');
    }
    return [];
  }

  function projectGroupsOf(o) {
    const inv = o?.inventory;
    if (!inv) return [];
    if (repositoryTreeContractProblemsOf(inv).length) return [];
    const groups = [];
    // Older broker projections may include enrollment-only definitions whose
    // only purpose is to bind a port lease ACL.  They have no concrete server
    // lifecycle and belong to the Ports workflow, never Servers or Projects.
    const servers = (inv.servers || []).filter(isOperationalServer);
    const containers = inv.docker?.available
      ? (inv.docker.containers || []).filter((c) => c?.transient_test !== true) : [];
    const containerIdOf = (container) => container?.host_resource_id ?? container?.docker_resource_id ?? null;
    const databases = Array.isArray(inv.resources?.databases) ? inv.resources.databases : [];
    const databaseById = new Map(databases
      .filter((database) => database?.database_binding_id)
      .map((database) => [String(database.database_binding_id), database]));
    const postgresByBindingId = new Map((inv.docker?.postgres || [])
      .filter((database) => database?.database_binding_id)
      .map((database) => [String(database.database_binding_id), database]));
    const scopeOf = (familyKey, rawScope, index) => {
        const serverIds = new Set((rawScope.server_ids || []).map(String));
        const containerResourceIds = new Set((rawScope.container_resource_ids || []).map(String));
        const databaseBindingIds = new Set((rawScope.database_binding_ids || []).map(String));
        const dbNames = new Set();

        // A database binding is independent domain evidence. Its exact ID may
        // identify the backing Docker resource and the compatibility display
        // row; neither names nor paths are used to establish association.
        for (const bindingId of databaseBindingIds) {
          const database = databaseById.get(bindingId);
          const postgres = postgresByBindingId.get(bindingId);
          const dockerResourceId = database?.docker_resource_id
            ?? postgres?.docker_resource_id
            ?? postgres?.host_resource_id
            ?? null;
          if (dockerResourceId) containerResourceIds.add(String(dockerResourceId));
          const linkedContainer = dockerResourceId
            ? containers.find((container) => String(containerIdOf(container)) === String(dockerResourceId))
            : null;
          if (linkedContainer?.name) dbNames.add(linkedContainer.name);
          else if (postgres?.name) dbNames.add(postgres.name);
        }

        const members = {
          servers: servers.filter((server) => serverIds.has(String(server.id))),
          containers: containers.filter((container) => {
            const resourceId = containerIdOf(container);
            return resourceId != null && containerResourceIds.has(String(resourceId));
          }),
        };
        const runningCount = members.servers.filter(isServerRunning).length
          + members.containers.filter(isContainerActive).length;
        const repoId = rawScope.repo_id == null ? null : String(rawScope.repo_id);
        return {
          key: `${familyKey}:${repoId ?? `scope-${index}`}`,
          repoId,
          kind: rawScope.kind === 'temporary' ? 'temporary' : 'root',
          name: rawScope.display_name || projectTail(rawScope.canonical_root),
          project: rawScope.canonical_root || null,
          runId: rawScope.run_id ?? null,
          expiresAt: rawScope.expires_at ?? null,
          killAfterRun: typeof rawScope.kill_after_run === 'boolean' ? rawScope.kill_after_run : null,
          usage: rawScope.usage || {},
          members,
          databaseBindingIds,
          dbNames,
          runningCount,
        };
    };

    for (const [familyIndex, tree] of inv.repository_trees.entries()) {
        const root = tree?.root_repository || {};
        const familyKey = String(tree?.family_id ?? root.repo_id ?? `family-${familyIndex}`);
        const scopes = (tree?.scopes || []).map((scope, index) => scopeOf(familyKey, scope, index));
        const rootScopes = scopes.filter((scope) => scope.kind === 'root');
        const temporaryScopes = scopes.filter((scope) => scope.kind === 'temporary');
        const rootMembers = {
          servers: rootScopes.flatMap((scope) => scope.members.servers),
          containers: rootScopes.flatMap((scope) => scope.members.containers),
        };
        const members = {
          servers: scopes.flatMap((scope) => scope.members.servers),
          containers: scopes.flatMap((scope) => scope.members.containers),
        };
        const dbNames = new Set(scopes.flatMap((scope) => [...scope.dbNames]));
        const runningCount = members.servers.filter(isServerRunning).length
          + members.containers.filter(isContainerActive).length;
        const name = root.display_name || projectTail(root.canonical_root);
        const usage = tree?.usage || {};
        const row = {
          ...usage,
          name,
          project: root.canonical_root || null,
          repo_id: root.repo_id || null,
          temporary_repo_count: temporaryScopes.length,
          server_count: members.servers.length,
          container_count: members.containers.length,
          process_count: usage.process_count || 0,
        };
      groups.push({
          key: familyKey,
          metricsKey: `family:${familyKey}`,
          name,
          project: root.canonical_root || null,
          repoId: root.repo_id || null,
          row,
          members,
          dbNames,
          runningCount,
          authoritative: true,
          scopes,
          rootScope: {
            key: `${familyKey}:root`,
            repoId: root.repo_id || null,
            kind: 'root',
            name,
            project: root.canonical_root || null,
            usage: rootScopes[0]?.usage || {},
            members: rootMembers,
            dbNames: new Set(rootScopes.flatMap((scope) => [...scope.dbNames])),
            runningCount: rootMembers.servers.filter(isServerRunning).length
              + rootMembers.containers.filter(isContainerActive).length,
          },
          temporaryScopes,
      });
    }

    groups.sort(projectGroupOrder);
    return groups;
  }

  function authoritativeInventoryProblemsOf(o) {
    const inv = o?.inventory;
    if (!inv) return [];
    const contractProblems = repositoryTreeContractProblemsOf(inv);
    if (contractProblems.length) return contractProblems;
    const claimedServers = new Set();
    const claimedContainers = new Set();
    const claimedDatabases = new Set();
    for (const tree of inv.repository_trees) {
      for (const scope of tree?.scopes || []) {
        for (const id of scope.server_ids || []) claimedServers.add(String(id));
        for (const id of scope.container_resource_ids || []) claimedContainers.add(String(id));
        for (const id of scope.database_binding_ids || []) claimedDatabases.add(String(id));
      }
    }

    const databases = Array.isArray(inv.resources?.databases) ? inv.resources.databases : [];
    const databaseById = new Map(databases
      .filter((database) => database?.database_binding_id)
      .map((database) => [String(database.database_binding_id), database]));
    for (const bindingId of claimedDatabases) {
      const dockerResourceId = databaseById.get(bindingId)?.docker_resource_id;
      if (dockerResourceId != null) claimedContainers.add(String(dockerResourceId));
    }

    const problems = [];
    const reportedKeys = new Set();
    const reportedResourceKeys = new Set();
    const pushReportedProblem = (item, fallbackKind, fallbackName) => {
      if (item?.transient_test === true) return;
      const kind = item.resource_kind || fallbackKind;
      const resourceId = item.resource_id || item.host_resource_id || '';
      const reasonCode = item.reason_code || '';
      const key = `${kind}|${resourceId}|${reasonCode}`;
      if (reportedKeys.has(key)) return;
      reportedKeys.add(key);
      if (resourceId) reportedResourceKeys.add(`${kind}|${resourceId}`);
      problems.push({
        kind,
        resourceId: resourceId ? String(resourceId) : null,
        repoId: item.affected_repo_id || item.repo_id || null,
        reasonCode: reasonCode || null,
        parentResourceKind: item.parent_resource_kind || null,
        parentResourceId: item.parent_resource_id == null
          ? null : String(item.parent_resource_id),
        parentDisplayName: item.parent_display_name || null,
        canAttach: typeof item.can_attach === 'boolean' ? item.can_attach : null,
        canRetire: typeof item.can_retire === 'boolean' ? item.can_retire : null,
        name: item.display_name || fallbackName,
        reason: item.explanation || item.reason_code || null,
        nextStep: item.recommended_next_step
          || `Rerun Coordinator installation for the original root repository, or attach or retire this exact ${kind}.`,
      });
    };
    for (const item of inv.unassigned_resources || []) {
      pushReportedProblem(item, 'resource', 'Unassigned resource');
    }
    for (const item of inv.lifecycle_violations || []) {
      pushReportedProblem(item, 'lifecycle', 'Lifecycle violation');
    }
    for (const server of inv.servers || []) {
      if (isServerRunning(server) && !claimedServers.has(String(server.id))
          && !reportedResourceKeys.has(`server|${server.id}`)) {
        problems.push({
          kind: 'server', resourceId: String(server.id), repoId: server.repo_id || null,
          reasonCode: 'missing_inventory_evidence', name: server.name || 'Unnamed server',
          reason: 'The running server is absent from both the repository tree and the coordinator ownership-problem list.',
          nextStep: 'Rerun Coordinator installation for the original root repository, or attach or retire this exact server, then refresh.',
        });
      }
    }
    const containers = inv.docker?.available ? (inv.docker.containers || []) : [];
    const activeContainerIds = new Set();
    for (const container of containers) {
      // Keep this helper self-contained: its contract is unit-tested by
      // extracting it independently from the page module.
      if (container?.transient_test === true) continue;
      const resourceId = container.host_resource_id ?? container.docker_resource_id ?? null;
      const status = String(container.status || '').trim();
      const active = isContainerActive(container) && !/^stopped\b/i.test(status);
      if (active && resourceId != null) activeContainerIds.add(String(resourceId));
      if (active && (resourceId == null || !claimedContainers.has(String(resourceId)))
          && !reportedResourceKeys.has(`container|${resourceId}`)) {
        problems.push({
          kind: 'container', resourceId: resourceId == null ? null : String(resourceId),
          repoId: container.repo_id || null, reasonCode: 'missing_inventory_evidence',
          name: container.name || 'Unnamed container',
          reason: 'The active container is absent from both the repository tree and the coordinator ownership-problem list.',
          nextStep: 'Rerun Coordinator installation for the original root repository, or attach or retire this exact container, then refresh.',
        });
      }
    }
    for (const database of databases) {
      const bindingId = database.database_binding_id == null
        ? null : String(database.database_binding_id);
      const lifecycle = String(database.lifecycle ?? database.status ?? '').trim();
      const active = lifecycle
        ? !/^(stopped|exited|removed|inactive)\b/i.test(lifecycle)
        : activeContainerIds.has(String(database.docker_resource_id));
      if (active && (bindingId == null || !claimedDatabases.has(bindingId))
          && !reportedResourceKeys.has(`database|${bindingId}`)) {
        problems.push({
          kind: 'database', resourceId: bindingId, repoId: database.repo_id || null,
          reasonCode: 'missing_inventory_evidence',
          name: database.database_name || 'Unnamed database',
          reason: 'The active database binding is absent from both the repository tree and the coordinator ownership-problem list.',
          nextStep: 'Rerun Coordinator installation for the original root repository, or bind this exact database stack, then refresh.',
        });
      }
    }
    return problems;
  }

  function inventoryProblemMatchesTarget(o, problem, target) {
    if (!problem || !target) return false;
    const inv = o?.inventory;
    const kind = target.target_kind || target.kind;
    const id = target.target_id ?? target.id;
    if (!inv || id == null) return false;
    const targetId = String(id);
    if (kind === problem.kind && problem.resourceId != null
        && String(problem.resourceId) === targetId) return true;
    if (kind === 'container' && problem.kind === 'database' && problem.resourceId != null) {
      const database = (inv.resources?.databases || []).find((item) => (
        String(item?.database_binding_id) === String(problem.resourceId)
      ));
      if (database?.docker_resource_id != null
          && String(database.docker_resource_id) === targetId) return true;
    }
    if (kind !== 'project') return false;
    if (problem.repoId != null && String(problem.repoId) === targetId) return true;
    const scope = (inv.repository_trees || []).flatMap((tree) => tree?.scopes || [])
      .find((item) => String(item?.repo_id) === targetId);
    if (!scope || problem.resourceId == null) return false;
    const ids = problem.kind === 'server' ? scope.server_ids
      : problem.kind === 'container' ? scope.container_resource_ids
        : problem.kind === 'database' ? scope.database_binding_ids : [];
    return (ids || []).some((resourceId) => String(resourceId) === String(problem.resourceId));
  }

  function inventoryMutationProblemOf(o, targets = []) {
    const structural = repositoryTreeContractProblemsOf(o?.inventory);
    if (structural.length) return structural[0];
    const exactTargets = Array.isArray(targets) ? targets.filter(Boolean) : [targets].filter(Boolean);
    if (!exactTargets.length) return null;
    return authoritativeInventoryProblemsOf(o).find((problem) => exactTargets.some(
      (target) => inventoryProblemMatchesTarget(o, problem, target),
    )) || null;
  }

  function authoritativeInventoryErrorPanel(o) {
    const problems = repositoryTreeContractProblemsOf(o?.inventory);
    if (!problems.length) return null;
    return h('div', { class: 'degraded repository-inventory-error', role: 'alert' },
      icon('warn'),
      h('div', null,
        h('p', { class: 'deg-title' }, 'Repository inventory contract is invalid'),
        h('p', { class: 'deg-msg' },
          'The coordinator returned a malformed or contradictory repository tree. Lifecycle controls are disabled; refresh after correcting the producer.'),
        h('ul', { class: 'inventory-problem-list' },
          problems.map((problem) => h('li', null,
            h('strong', null, `${problem.kind}: ${problem.name}`),
            problem.reason ? h('span', null, problem.reason) : null,
            problem.nextStep ? h('span', { class: 'inventory-problem-next-step' }, problem.nextStep) : null)))));
  }

  function authoritativeInventoryDiagnosticPanel(o) {
    if (repositoryTreeContractProblemsOf(o?.inventory).length) return null;
    const problems = authoritativeInventoryProblemsOf(o);
    if (!problems.length) return null;

    // Database problems projected from one unassigned PostgreSQL container
    // are evidence about that parent problem, not dozens of independently
    // actionable ownership failures. Keep the exact child bindings available
    // on demand while counting and presenting the parent as the one repair.
    const childrenByParent = new Map();
    for (const problem of problems) {
      if (!problem.parentResourceKind || problem.parentResourceId == null) continue;
      const key = `${problem.parentResourceKind}:${problem.parentResourceId}`;
      if (!childrenByParent.has(key)) childrenByParent.set(key, []);
      childrenByParent.get(key).push(problem);
    }
    const issues = [];
    const representedParents = new Set();
    for (const problem of problems) {
      if (problem.parentResourceKind && problem.parentResourceId != null) continue;
      const key = problem.resourceId == null ? null : `${problem.kind}:${problem.resourceId}`;
      const children = key == null ? [] : (childrenByParent.get(key) || []);
      if (key != null) representedParents.add(key);
      issues.push({ problem, children });
    }
    // A valid producer normally reports the parent too. If it does not, keep
    // the children visible as one parent-scoped diagnostic instead of turning
    // them back into one top-level warning per database.
    for (const [key, children] of childrenByParent) {
      if (representedParents.has(key)) continue;
      const child = children[0];
      issues.push({
        problem: {
          kind: child.parentResourceKind,
          resourceId: child.parentResourceId,
          name: child.parentDisplayName || `${child.parentResourceKind} ${child.parentResourceId}`,
          reason: `The Coordinator reported ${children.length} affected child resource${sfx(children.length)} for this parent.`,
          nextStep: child.nextStep,
        },
        children,
      });
    }
    const issueCount = issues.length;
    const affectedResourceCount = problems.length;
    return h('aside', {
      class: 'inventory-diagnostics', role: 'status',
      'aria-label': 'Repository ownership diagnostics',
    },
      h('div', { class: 'inventory-diagnostics-head' },
        icon('warn'),
        h('div', null,
          h('p', { class: 'deg-title' },
            `${issueCount} ownership issue${sfx(issueCount)} need${issueCount === 1 ? 's' : ''} attention`),
          h('p', { class: 'deg-msg' },
            `${issueCount} actionable issue${sfx(issueCount)} affect${issueCount === 1 ? 's' : ''} `
            + `${affectedResourceCount} resource${sfx(affectedResourceCount)}. `
            + 'Healthy repositories remain available; only actions that affect the listed resources are disabled.'))),
      h('div', { class: 'inventory-diagnostic-groups' },
        issues.map(({ problem, children }) => {
          const kind = problem.kind || 'resource';
          const childDatabases = children.filter((child) => child.kind === 'database');
          const childCountLabel = childDatabases.length
            ? `${childDatabases.length} database${sfx(childDatabases.length)} affected`
            : `${children.length} child resource${sfx(children.length)} affected`;
          const issueLabel = children.length
            ? `${problem.name} · ${childCountLabel}`
            : `${problem.name} · ${kind}`;
          const disclosureKey = `inventory-diagnostic:${kind}:${problem.resourceId || problem.name}`;
          const childrenDisclosureKey = `${disclosureKey}:children`;
          // The exact ID remains the primary key. The sibling match key is
          // deliberately stable across an inventory observer replacing an
          // opaque host resource ID (or an aggregate count) for the same
          // ownership finding. setSection uses it only when it identifies one
          // disclosure on both sides of a refresh, so separate findings can
          // never inherit each other's expanded state.
          const normalizedName = String(problem.name || '')
            .trim()
            .replace(/^\d+\s+(?:containers?|servers?|databases?|resources?)$/i, '')
            .toLowerCase();
          const disclosureMatch = [
            'inventory-diagnostic',
            kind,
            problem.reasonCode || 'unspecified',
            problem.parentResourceKind || 'root',
            problem.parentResourceId || normalizedName || 'aggregate',
          ].join(':');
          const childrenDisclosureMatch = `${disclosureMatch}:children`;
          return h('details', {
            class: 'inventory-diagnostic-group',
            'data-section-disclosure': disclosureKey,
            'data-section-disclosure-match': disclosureMatch,
          },
            h('summary', {
              'data-fk': disclosureKey,
              'data-section-disclosure-match': disclosureMatch,
            }, issueLabel),
            h('ul', { class: 'inventory-problem-list' },
              h('li', null,
                h('strong', null, problem.name),
                problem.reason ? h('span', null, problem.reason) : null,
                problem.nextStep
                  ? h('span', { class: 'inventory-problem-next-step' }, problem.nextStep) : null)),
            children.length
              ? h('details', {
                  class: 'inventory-diagnostic-children',
                  'data-section-disclosure': childrenDisclosureKey,
                  'data-section-disclosure-match': childrenDisclosureMatch,
                },
                  h('summary', {
                    'data-fk': childrenDisclosureKey,
                    'data-section-disclosure-match': childrenDisclosureMatch,
                  },
                    `View exact ${childCountLabel}`),
                  h('ul', { class: 'inventory-problem-list' },
                    children.map((child) => h('li', null,
                      h('strong', null, child.name),
                      child.reason ? h('span', null, child.reason) : null))))
              : null);
        })));
  }

  // Stable project-group order: groups with something running first, then
  // name, then key. Live CPU/memory must NEVER be an ordering key on
  // persistent lists — fluctuating readings would reshuffle the groups on
  // every poll, so nothing stays where the user is about to click
  // (docs/journeys.md "Stable ordering contract").
  function projectGroupOrder(a, b) {
    return (b.runningCount ? 1 : 0) - (a.runningCount ? 1 : 0)
      || String(a.name).localeCompare(String(b.name))
      || String(a.key).localeCompare(String(b.key));
  }

  // Docker ownership is a mutation boundary, not a display hint. Mirror the
  // server-side action gate exactly: ordinary lifecycle controls require
  // Docker labels or coordinator sidecar metadata. Broker-owned ephemeral
  // containers are also verified, but remain read-only here because their
  // TTL/lease state machine must be changed only through ephemeral
  // renew/finish. This deliberately never promotes a container from its name,
  // image or Compose-project text.
  function containerOwnershipState(c) {
    const rawAttribution = c?.attribution && typeof c.attribution === 'object'
      && !Array.isArray(c.attribution) ? c.attribution : null;
    const source = c?.metadata_source;
    const verified = Boolean(
      c?.project
      && ['docker_labels', 'coordinator_sidecar', 'coordinator_ephemeral'].includes(source)
      && !rawAttribution,
    );
    if (verified) {
      const ephemeral = source === 'coordinator_ephemeral';
      return {
        verified: true,
        genericLifecycle: !ephemeral,
        ephemeral,
        attribution: null,
      };
    }

    const explanation = typeof rawAttribution?.explanation === 'string'
      && rawAttribution.explanation.trim()
      ? rawAttribution.explanation.trim()
      : 'The coordinator could not prove one repository owner for this container.';
    const recommendedNextStep = typeof rawAttribution?.recommended_next_step === 'string'
      && rawAttribution.recommended_next_step.trim()
      ? rawAttribution.recommended_next_step.trim()
      : null;
    return {
      verified: false,
      genericLifecycle: false,
      ephemeral: false,
      attribution: {
        ...(rawAttribution || {}),
        reason_code: typeof rawAttribution?.reason_code === 'string'
          && rawAttribution.reason_code.trim()
          ? rawAttribution.reason_code.trim()
          : 'unverified_ownership',
        explanation,
        recommended_next_step: recommendedNextStep,
        can_attach: rawAttribution?.can_attach === true,
        can_retire: rawAttribution?.can_retire === true,
      },
    };
  }

  function ownershipResolutionText(attribution) {
    if (attribution.recommended_next_step) return attribution.recommended_next_step;
    if (attribution.can_attach && attribution.can_retire) {
      return 'Coordinator administration can attach it to a verified project or retire it as a standalone resource.';
    }
    if (attribution.can_attach) {
      return 'Coordinator administration can attach it to a verified project.';
    }
    if (attribution.can_retire) {
      return 'Coordinator administration can retire it as a standalone resource.';
    }
    return 'Refresh or repair coordinator ownership evidence before attempting a lifecycle change.';
  }

  function unverifiedOwnershipNote(ownership) {
    if (ownership.ephemeral) {
      return h('span', {
        class: 'ownership-warning ownership-managed', role: 'note',
        'data-attribution-reason': 'coordinator_ephemeral',
      },
        h('span', { class: 'ownership-warning-icon', 'aria-hidden': 'true' }, icon('clock')),
        h('span', { class: 'ownership-warning-copy' },
          h('span', { class: 'ownership-warning-title' }, 'Coordinator-managed ephemeral'),
          h('span', { class: 'ownership-warning-detail' },
            'Ownership is verified. Its sealed TTL, lease and exact Docker identity are managed by the coordinator.'),
          h('span', { class: 'ownership-warning-next' },
            'Use the coordinator ephemeral status, renew or finish command; ordinary Docker actions are disabled.')));
    }
    if (ownership.verified) return null;
    const attribution = ownership.attribution;
    return h('span', {
      class: 'ownership-warning', role: 'note',
      'data-attribution-reason': attribution.reason_code,
    },
      h('span', { class: 'ownership-warning-icon', 'aria-hidden': 'true' }, icon('warn')),
      h('span', { class: 'ownership-warning-copy' },
        h('span', { class: 'ownership-warning-title' }, 'Ownership not verified'),
        h('span', { class: 'ownership-warning-detail' }, attribution.explanation),
        h('span', { class: 'ownership-warning-next' }, ownershipResolutionText(attribution))));
  }

  function blockedContainerAction(
    focusKey, label, iconName, { compact = false, ephemeral = false } = {},
  ) {
    const reason = ephemeral
      ? 'this broker-owned ephemeral container must use its TTL-aware lifecycle'
      : 'container ownership is not verified';
    return h('button', {
      class: compact ? 'iconbtn' : `btn small ${ACTION_CLS[label.toLowerCase()] || ''}`,
      type: 'button',
      'data-fk': focusKey,
      disabled: true,
      'aria-disabled': 'true',
      'aria-label': `${label} unavailable — ${reason}`,
      title: ephemeral
        ? `${label} is unavailable here; use coordinator ephemeral renew or finish`
        : `${label} is unavailable until the coordinator proves one repository owner`,
    }, icon(iconName), compact ? null : label);
  }

  const groupsByProjectPath = (o) => {
    const map = new Map();
    for (const g of projectGroupsOf(o)) {
      if (g.project) map.set(g.project, g);
      for (const scope of g.scopes || []) if (scope.project) map.set(scope.project, g);
    }
    return map;
  };

  // Header row shown above each project's items on the grouped tabs.
  function groupHeader(group, extraText) {
    const usage = group.row
      ? h('span', { class: 'proj-usage mono' },
          h('span', { class: 'u-cpu' }, fmtCpu(group.row.cpu_percent)),
          ' · ',
          h('span', { class: 'u-mem' }, fmtBytes(group.row.memory_bytes || 0)))
      : null;
    return h('div', { class: 'proj-head', title: group.project || '' },
      h('strong', { class: 'proj-name' }, group.name),
      h('span', { class: 'meta-passive' }, extraText),
      group.metricsKey ? sparkline(metricsEntity(group.metricsKey)) : null,
      usage);
  }

  // ---------------------------------------------------------------- charts

  const SVG_NS = 'http://www.w3.org/2000/svg';

  function svgEl(tag, attrs) {
    const el = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        el.setAttribute(k, String(v));
      }
    }
    return el;
  }

  const fmtCpu = (v) => `${(Number(v) || 0).toFixed(1)}%`;

  // points: [[epochMs, cpuPercent, memBytes], ...] oldest first.
  // `fixedMax` pins the y-scale: CPU series render on 0..max(100%, observed)
  // so an idle 1% wiggle reads as the flat line it is; memory has no natural
  // ceiling and keeps the 0..observed-max scale.
  function seriesLine(points, pick, w, hgt, pad, fixedMax) {
    const t0 = points[0][0];
    const span = Math.max(1, points[points.length - 1][0] - t0);
    let vMax = 0;
    for (const p of points) vMax = Math.max(vMax, Number(pick(p)) || 0);
    const scale = Math.max(fixedMax || 0, vMax) || 1;
    const coords = points.map((p) => {
      const x = pad + ((p[0] - t0) / span) * (w - pad * 2);
      const y = hgt - pad - (Math.max(0, Number(pick(p)) || 0) / scale) * (hgt - pad * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    });
    return { line: coords.join(' '), vMax };
  }

  function sparkline(entity) {
    const points = entity?.points || [];
    if (points.length < 2) {
      return h('span', { class: 'spark spark-empty', 'aria-hidden': 'true' });
    }
    const w = 92;
    const hgt = 24;
    const svg = svgEl('svg', {
      class: 'spark',
      viewBox: `0 0 ${w} ${hgt}`,
      preserveAspectRatio: 'none',
      'aria-hidden': 'true',
    });
    svg.append(
      svgEl('polyline', { class: 'spark-mem', fill: 'none', points: seriesLine(points, (p) => p[2], w, hgt, 2).line }),
      svgEl('polyline', { class: 'spark-cpu', fill: 'none', points: seriesLine(points, (p) => p[1], w, hgt, 2, CPU_SCALE_MAX).line }),
    );
    return svg;
  }

  const CPU_SCALE_MAX = 100; // CPU charts use a fixed 0-100% scale (multicore peaks extend it)

  function timeSpanText(ms) {
    const min = Math.round(ms / 60_000);
    if (min < 2) return 'last minute';
    if (min < 90) return `last ${min} min`;
    return `last ${(min / 60).toFixed(1)} h`;
  }

  // One labeled history chart (CPU or Memory) for popovers and the
  // performance page. Labels live in HTML so scaling never distorts text.
  function chartBlock(label, points, pick, fmtVal, cssClass) {
    const head = h('div', { class: 'chart-head' }, h('span', { class: 'chart-label' }, label));
    if (!points || points.length < 2) {
      head.append(h('span', { class: 'meta-passive' }, 'collecting…'));
      return h('div', { class: 'chart-block' }, head);
    }
    const w = 600;
    const hgt = 110;
    const pad = 3;
    const { line, vMax } = seriesLine(points, pick, w, hgt, pad, cssClass === 'c-cpu' ? CPU_SCALE_MAX : 0);
    const svg = svgEl('svg', {
      class: `chart ${cssClass}`,
      viewBox: `0 0 ${w} ${hgt}`,
      preserveAspectRatio: 'none',
      'aria-hidden': 'true',
    });
    svg.append(
      svgEl('polygon', { class: 'chart-area', points: `${pad},${hgt - pad} ${line} ${w - pad},${hgt - pad}` }),
      svgEl('polyline', { class: 'chart-line', fill: 'none', points: line }),
    );
    const last = Number(pick(points[points.length - 1])) || 0;
    const span = points[points.length - 1][0] - points[0][0];
    head.append(
      // Current value in the same color as its plot line.
      h('span', { class: `chart-now mono ${cssClass === 'c-cpu' ? 'u-cpu' : 'u-mem'}` }, fmtVal(last)),
      h('span', { class: 'meta-passive' }, `peak ${fmtVal(vMax)} · ${timeSpanText(span)}`),
    );
    return h('div', { class: 'chart-block' }, head, svg);
  }

  // Compact per-row control: live numbers + sparkline, click for full charts.
  // `scope` keeps data-fk/popover keys unique when the same entity renders on
  // several pages at once (tabs, Projects tree, project headers).
  function usageCellNode({ key, title, cpu, mem, running, scope = 'tab' }) {
    const ent = metricsEntity(key);
    const hasLive = running && (cpu !== null && cpu !== undefined || mem !== null && mem !== undefined);
    if (!hasLive && (!ent || ent.points.length < 2)) {
      return h('span', { class: 'cell usage-cell dim', 'data-label': 'CPU / Mem' }, '—');
    }
    // CPU and memory numbers wear their plot-line colors so the two series
    // are tellable apart at a glance.
    const nums = hasLive
      ? [h('span', { class: 'u-cpu' }, fmtCpu(cpu)), ' · ', h('span', { class: 'u-mem' }, fmtBytes(Number(mem) || 0))]
      : '—';
    const fkey = `usage:${scope}:${key}`;
    return h('span', { class: 'cell usage-cell', 'data-label': 'CPU / Mem' },
      h('button', {
        class: 'usage-btn', type: 'button',
        'data-fk': fkey, 'aria-haspopup': 'dialog',
        'aria-expanded': popover.key === fkey ? 'true' : 'false',
        'aria-label': hasLive
          ? `${title}: CPU ${fmtCpu(cpu)}, memory ${fmtBytes(Number(mem) || 0)} — show history charts`
          : `${title}: not running — show recent history charts`,
        title: 'Show CPU / memory history',
        onclick: (e) => popover.toggle(fkey, e.currentTarget, () => usagePop(key, title)),
      },
        h('span', { class: 'usage-nums mono' }, nums),
        sparkline(ent)));
  }

  function usagePop(key, title) {
    const ent = metricsEntity(key);
    const points = ent?.points || [];
    const intervalMs = state.metrics?.intervalMs;
    return h('div', null,
      popHead(title),
      points.length >= 2
        ? [
            chartBlock('CPU', points, (p) => p[1], fmtCpu, 'c-cpu'),
            chartBlock('Memory', points, (p) => p[2], fmtBytes, 'c-mem'),
          ]
        : h('p', { class: 'pop-hint' }, 'No history yet — the console samples continuously, so charts appear within a minute.'),
      h('p', { class: 'pop-hint' },
        intervalMs ? `Sampled about every ${Math.round(intervalMs / 1000)}s; history resets when the console restarts. ` : '',
        h('a', { href: '#/performance' }, 'Open Performance'),
        ' for every chart.'));
  }

  // ---------------------------------------------------------------- data fetch

  let fetching = false;
  let refetchQueued = false;
  let inventoryWarmupStartedAt = null;

  async function refreshOverview({ force = false, fresh = false } = {}) {
    if (fetching) { refetchQueued = true; return; }
    fetching = true;
    try {
      let data = await api(`/api/overview${fresh ? '?fresh=1' : ''}`);
      if (
        !data.inventory
        && state.overview?.inventory
        && (
          data.coordinator?.inventoryState === 'loading'
          || Boolean(data.coordinator?.failureKind)
        )
      ) {
        // Loading and refresh failures are metadata, not a reason to erase
        // the last authoritative screen. Keep rendering that snapshot until
        // the coalesced refresh settles, so polling never flashes or blanks a
        // healthy Console because of project or control-plane work.
        data = {
          ...data,
          inventory: state.overview.inventory,
          routes: state.overview.routes,
          coordinator: {
            ...data.coordinator,
            inventoryState: 'stale',
            inventoryRefreshing: true,
          },
        };
      }
      state.overview = data;
      state.stale = false;
      state.lastFetch = Date.now();
      if (currentPage() === 'bugs') {
        // The out-of-band bug registry exists specifically for reporting a
        // broken Coordinator. Its collection remains the complete page-level
        // truth while the normal overview path is unavailable; do not obscure
        // it with the failure of the system being reported.
        clearBanner('maintenance');
        clearBanner('overview');
      } else if (data.coordinator?.failureKind === 'maintenance') {
        clearBanner('overview');
        if (data.inventory) {
          // The retained authority snapshot is still a healthy decision
          // surface. A background control-plane fence must not turn a project
          // page into a global incident banner or make the screen blink.
          clearBanner('maintenance');
        } else {
          showBanner({ classification: 'maintenance' }, null, 'maintenance');
        }
      } else {
        clearBanner('maintenance');
        clearBanner('overview');
      }
      renderAll(force);
      if (data.coordinator?.inventoryState === 'loading' && !data.inventory) {
        inventoryWarmupStartedAt ??= Date.now();
        if (Date.now() - inventoryWarmupStartedAt < 15_000) {
          // The API deliberately returns the first cold response inside its
          // first-byte budget while one coalesced inventory read warms the
          // server cache.  Follow that read until it resolves instead of
          // abandoning the loading screen after four sub-second retries.
          setTimeout(() => refreshOverview(), 200);
        }
      } else if (data.coordinator?.inventoryState !== 'loading') {
        inventoryWarmupStartedAt = null;
      }
      if (currentPage() === 'tests') loadTests();
      if (state.session?.accessAdmin === true && state.access && accessRoutesSig !== currentAccessRoutesSig()) {
        loadAccess({ force: true });
      }
      // A failed boot-time prefs fetch retries with the polling cadence.
      if (!prefsLoaded) loadPrefs();
      // Anything running must never stay hidden (fire-and-forget PATCH).
      autoUnhide(data);
      // A lifecycle mutation owns one generation-ordered archive refresh and
      // awaits it before revealing the result. Starting another unawaited
      // archive read here can replace the newly focused result row.
      if (lifecycleAvailable() && !lifecycleRefreshInFlight) {
        loadArchives({ force: true });
      }
    } catch (err) {
      if (err.status === 401) return;
      state.stale = true;
      if (currentPage() === 'bugs') {
        clearBanner('overview');
      } else {
        showBanner(err, () => refreshOverview({ force: true, fresh: true }), 'overview');
      }
      if (!state.overview) renderFirstLoadError();
      else renderHeader();
    } finally {
      fetching = false;
      if (refetchQueued) {
        // A mutation finished while a poll was in flight — fetch once more so
        // the UI reflects post-mutation state instead of the stale response.
        refetchQueued = false;
        refreshOverview({ force, fresh });
      }
    }
  }

  function renderFirstLoadError() {
    const page = currentPage();
    unmountInactiveSections(page);
    for (const [id, ownerPage] of Object.entries(SECTION_BODY_PAGES)) {
      if (ownerPage !== page || id === 'access-body' || id === 'bugs-body') continue;
      document.getElementById(id).replaceChildren(
        h('p', { class: 'empty err' }, 'Could not load — use Retry in the error banner above.'));
    }
  }

  // ---------------------------------------------------------------- mutations

  async function runAction(busyKey, fn, { confirmText, onError, inventoryTargets = [] } = {}) {
    const inventoryProblem = inventoryMutationProblemOf(state.overview, inventoryTargets);
    if (inventoryProblem) {
      showBanner(inventoryProblem.kind === 'inventory'
        ? 'Coordinator mutation is disabled because the repository inventory contract is invalid.'
        : 'This action is disabled only for the affected resource until its ownership problem is resolved.');
      return false;
    }
    if (confirmText && !window.confirm(confirmText)) return false;
    ui.busy.add(busyKey);
    bump();
    renderAll(true);
    try {
      await fn();
      ui.busy.delete(busyKey);
      bump();
      await refreshOverview({ force: true, fresh: true });
      return true;
    } catch (err) {
      ui.busy.delete(busyKey);
      bump();
      renderAll(true);
      if (err.status !== 401) {
        showBanner(err, () => runAction(busyKey, fn, { onError, inventoryTargets }));
        onError?.(err);
      }
      return false;
    }
  }

  // ---------------------------------------------------------------- current tests

  function testRepositories() {
    return (state.testsRepositories?.repositories || [])
      .filter((repository) => repository && typeof repository.repo_id === 'string' && repository.repo_id)
      .map((repository) => ({
        ...repository,
        project: repository.canonical_root || repository.repo_id,
      }))
      .slice()
      .sort((a, b) => String(a.display_name || a.canonical_root || a.repo_id)
        .localeCompare(String(b.display_name || b.canonical_root || b.repo_id)));
  }

  async function loadTests({ force = false } = {}) {
    if (!force && state.testsRepositories) return renderTests();
    if (state.testsLoading) return;
    state.testsLoading = true;
    renderTests();
    try {
      const catalog = await api('/api/tests/repositories');
      if (!catalog || catalog.schema_version !== 1 || !Array.isArray(catalog.repositories)) {
        throw new Error('test repository catalog is invalid');
      }
      state.testsRepositories = catalog;
      state.testsError = null;
      clearBanner('tests');
    } catch (err) {
      if (!state.testsRepositories && err.status !== 401 && err.classification !== 'maintenance') {
        state.testsError = err;
      }
    } finally {
      state.testsLoading = false;
      renderTests();
    }
  }

  function refreshTestsInPlace() {
    if (document.hidden || currentPage() !== 'tests') return;
    // Keep the current catalog mounted during refresh; unchanged content is a no-op.
    loadTests({ force: true });
  }

  async function loadTestRuns({ force = false } = {}) {
    const project = state.testsProject;
    const current = state.testsRuns?.repo_id === project ? state.testsRuns : null;
    if (!project || state.testsRunsLoading || (!force && current)) return;
    state.testsRunsLoading = true;
    state.testsRunsError = null;
    renderTestDetail();
    try {
      const query = new URLSearchParams({ repo_id: project });
      const result = await api(`/api/tests/runs?${query.toString()}`);
      if (project !== state.testsProject) return;
      if (!result || ((result.repo_id ?? result.repository_id) !== project) || !Array.isArray(result.runs)) {
        throw new ApiError('current repository test runs are invalid', 502);
      }
      state.testsRuns = {
        ...result,
        repo_id: project,
      };
    } catch (err) {
      if (project === state.testsProject && err.status !== 401 && err.classification !== 'maintenance') {
        state.testsRunsError = err;
      }
    } finally {
      state.testsRunsLoading = false;
      if (project === state.testsProject) {
        renderTestDetail();
      }
    }
  }

  function fmtTestCount(value) {
    const count = Number(value || 0);
    if (!Number.isFinite(count)) return '—';
    if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(count >= 10_000_000 ? 0 : 1)}m`;
    if (count >= 1_000) return `${(count / 1_000).toFixed(count >= 10_000 ? 0 : 1)}k`;
    return String(Math.round(count));
  }

  function testLocalFailure(title, error, retry) {
    return h('section', { class: 'test-local-failure', role: 'alert' },
      h('div', null,
        h('strong', null, title),
        error?.message ? h('p', null, String(error.message)) : null),
      h('button', { class: 'btn small', type: 'button', onclick: retry }, 'Try again'));
  }
  const testDetailNarrowViewport = window.matchMedia('(max-width: 680px)');

  function positionTestDetail() {
    const dialog = $('#test-detail-dialog');
    if (!dialog?.open) return;
    const top = Math.max(0, Math.round($('#topbar')?.getBoundingClientRect().bottom || 0));
    dialog.style.setProperty('--test-detail-top', `${top}px`);
  }

  function showTestDetailSurface() {
    const dialog = $('#test-detail-dialog');
    document.documentElement.classList.add('test-detail-open');
    if (!dialog.open) {
      if (testDetailNarrowViewport.matches) dialog.showModal();
      else dialog.show();
    }
    positionTestDetail();
  }

  function syncTestDetailSurface() {
    const dialog = $('#test-detail-dialog');
    if (!dialog?.open) return;
    positionTestDetail();
    const modal = dialog.matches(':modal');
    if (modal === testDetailNarrowViewport.matches) return;
    const focusWasInside = dialog.contains(document.activeElement);
    dialog.close();
    if (testDetailNarrowViewport.matches) dialog.showModal();
    else dialog.show();
    document.documentElement.classList.add('test-detail-open');
    positionTestDetail();
    if (focusWasInside) $('#test-detail-close').focus({ preventScroll: true });
  }

  function openTestRuns(repoId) {
    const repository = testRepositories().find((item) => item.repo_id === repoId);
    if (!repository) return;
    if (state.testsProject !== repoId) {
      state.testsProject = repoId;
      state.testsRuns = null;
      state.testsRunsError = null;
      state.testsRunEvidence = new Map();
    }
    $('#test-detail-h').textContent = repository.display_name || repository.repo_id;
    $('#test-detail-status').textContent = 'Current runs';
    showTestDetailSurface();
    renderTestDetail();
    loadTestRuns();
  }

  function closeTestDetail() {
    const dialog = $('#test-detail-dialog');
    if (dialog.open) dialog.close();
    dialog.style.removeProperty('--test-detail-top');
    document.documentElement.classList.remove('test-detail-open');
  }
  function testRunStateLabel(value) {
    return ({
      queued: 'Queued', running: 'Running', cancelling: 'Cancelling', superseding: 'Superseding',
      succeeded: 'Passed', failed: 'Failed', timed_out: 'Timed out', cancelled: 'Cancelled',
      incomplete: 'Incomplete', abandoned: 'Abandoned', superseded: 'Superseded',
    })[value] || 'Unknown';
  }

  async function operateTestRun(run, action) {
    const repoId = run.repo_id || run.repository_id || state.testsProject;
    const endpoint = `/api/tests/repositories/${encodeURIComponent(repoId)}/runs/${encodeURIComponent(run.run_id)}/${action}`;
    const body = { reason: 'Cancelled from DevOps Console', operation_id: crypto.randomUUID() };
    try {
      await api(endpoint, { method: 'POST', body });
      state.testsRunEvidence.delete(run.run_id);
      await Promise.all([loadTestRuns({ force: true }), loadTests({ force: true })]);
    } catch (error) {
      state.testsRunsError = error;
      renderTestDetail();
    }
  }

  function testRunMemoryWait(run) {
    const targets = Array.isArray(run?.targets) ? run.targets : [];
    const candidates = [run?.wait, ...targets.map((target) => target?.wait)];
    return candidates.find((wait) => wait && typeof wait === 'object'
      && !Array.isArray(wait) && wait.code === 'host_memory') || null;
  }

  function testMemorySize(mib) {
    if (mib === null || mib === undefined || typeof mib !== 'number'
      || !Number.isFinite(mib) || mib < 0) return null;
    return fmtBytes(mib * 1024 * 1024);
  }

  function testRunMemoryWaitLabel(wait) {
    if (!wait || wait.code !== 'host_memory') return null;
    const required = testMemorySize(wait.required_mib);
    const available = testMemorySize(wait.available_mib);
    return [
      'Waiting for memory',
      required ? `~${required} needed` : null,
      available ? `${available} available` : null,
    ].filter(Boolean).join(' · ');
  }

  function testRunUsage(detail, summary, run) {
    const candidates = [detail?.usage, summary?.usage, run?.usage].filter((usage) => (
      usage && typeof usage === 'object' && !Array.isArray(usage)
      && typeof usage.available === 'boolean'
    ));
    return candidates.find((usage) => usage.available === true) || candidates[0] || null;
  }

  function testRunMeasurementCoverage(usage) {
    if (!usage || usage.available !== true) return null;
    const measured = usage.measured_attempts;
    const total = usage.total_attempts;
    if (!Number.isInteger(measured) || measured < 0) return null;
    if (Number.isInteger(total) && total >= measured) {
      return `${measured} of ${total} ${total === 1 ? 'attempt' : 'attempts'}`;
    }
    return `${measured} measured ${measured === 1 ? 'attempt' : 'attempts'}`;
  }

  function testRunEvidenceFact(label, value, { wide = false, mono = false } = {}) {
    if (value === null || value === undefined || value === '') return null;
    return h('div', { class: wide ? 'test-run-evidence-wide' : null },
      h('dt', null, label), h('dd', { class: mono ? 'mono' : null }, value));
  }

  function testRunEvidenceContent(run, evidence) {
    const detail = evidence?.detail || run;
    const summary = detail?.summary || {};
    const failures = evidence?.failures?.failures || [];
    const artifacts = evidence?.artifacts?.artifacts || [];
    const wait = (detail.state || run.state) === 'queued'
      ? testRunMemoryWait(detail) || testRunMemoryWait(run) : null;
    const waitLabel = testRunMemoryWaitLabel(wait);
    const usage = testRunUsage(detail, summary, run);
    const peakMemory = usage?.available === true ? testMemorySize(usage.peak_memory_mib) : null;
    const cpuTime = usage?.available === true && typeof usage.cpu_seconds === 'number'
      && Number.isFinite(usage.cpu_seconds) && usage.cpu_seconds >= 0
      ? fmtSeconds(usage.cpu_seconds) : null;
    const evidenceFacts = [
      testRunEvidenceFact('Run ID', run.run_id, { mono: true }),
      testRunEvidenceFact('Queue status', waitLabel, { wide: true }),
      testRunEvidenceFact('Queue wait', fmtSeconds(summary.queue_seconds ?? run.queue_seconds)),
      testRunEvidenceFact('Test time', fmtSeconds(summary.aggregate_test_seconds ?? run.aggregate_test_seconds)),
      testRunEvidenceFact('Peak memory', peakMemory),
      testRunEvidenceFact('CPU time', cpuTime),
      testRunEvidenceFact('Measurements', testRunMeasurementCoverage(usage)),
      testRunEvidenceFact('Conclusion', detail.conclusion || run.conclusion || '—'),
      testRunEvidenceFact('Failures', fmtTestCount(summary.failure_record_count ?? failures.length)),
      testRunEvidenceFact('Artifacts', fmtTestCount(summary.artifact_count ?? artifacts.length)),
    ].filter(Boolean);
    return [
      h('dl', { class: 'test-run-evidence' }, evidenceFacts),
      failures.length ? h('section', { class: 'test-run-failures' },
        h('strong', null, 'Top actionable failures'),
        h('ol', null, failures.slice(0, 3).map((failure) => h('li', null,
          h('span', { class: 'mono' }, failure.target_name || failure.case_id || failure.classification || 'failure'),
          h('span', null, failure.message || 'No bounded failure message was recorded.'))))) : null,
      artifacts.length ? h('section', { class: 'test-run-artifacts' },
        h('strong', null, 'Artifacts'),
        h('ul', null, artifacts.slice(0, 12).map((artifact) => h('li', null,
          h('span', null, artifact.kind || 'artifact'),
          h('span', { class: 'mono' }, artifact.artifact_id || artifact.name || '—'),
          h('span', null, fmtBytes(Number(artifact.size_bytes || 0))))))) : null,
      run.can_cancel ? h('button', {
        class: 'btn small', type: 'button', onclick: () => operateTestRun(run, 'cancel'),
      }, 'Cancel run') : null,
    ].filter(Boolean);
  }

  async function loadTestRunEvidence(run, host) {
    const cached = state.testsRunEvidence.get(run.run_id);
    if (cached?.value) {
      host.replaceChildren(...testRunEvidenceContent(run, cached.value));
      return;
    }
    if (cached?.loading) return;
    state.testsRunEvidence.set(run.run_id, { loading: true });
    host.replaceChildren(h('p', { class: 'meta-passive' }, 'Loading bounded run evidence…'));
    try {
      const runId = encodeURIComponent(run.run_id);
      const repoId = run.repo_id || run.repository_id || state.testsProject;
      const base = `/api/tests/repositories/${encodeURIComponent(repoId)}/runs/${encodeURIComponent(runId)}`;
      const [detail, failures, artifacts] = await Promise.all([
        api(base),
        api(`${base}/failures?limit=3`),
        api(`${base}/artifacts?limit=12`),
      ]);
      if ([detail, failures, artifacts].some((value) => value?.run_id !== run.run_id)) {
        throw new ApiError('run evidence identity is invalid', 502);
      }
      const value = { detail, failures, artifacts };
      state.testsRunEvidence.set(run.run_id, { loading: false, value });
      if (host.isConnected) host.replaceChildren(...testRunEvidenceContent(run, value));
    } catch (error) {
      state.testsRunEvidence.set(run.run_id, { loading: false, error });
      if (host.isConnected) host.replaceChildren(testLocalFailure(
        'Run evidence is unavailable', error, () => loadTestRunEvidence(run, host),
      ));
    }
  }

  function testRunHistoryCard(run) {
    const targetCount = Number(run.target_count || run.targets?.length || 0);
    const completed = Number(run.completed_target_count || 0);
    const progress = targetCount > 0
      ? Math.max(0, Math.min(100, (completed / targetCount) * 100)) : 100;
    const active = ['queued', 'running', 'cancelling', 'superseding'].includes(run.state);
    const wallSeconds = run.wall_seconds ?? (run.started_at
      ? Number(run.finished_at || Date.now() / 1000) - Number(run.started_at) : null);
    const waitLabel = run.state === 'queued'
      ? testRunMemoryWaitLabel(testRunMemoryWait(run)) : null;
    const evidenceHost = h('div', { class: 'test-run-history-evidence-body' });
    const evidence = h('details', {
      class: 'test-run-history-evidence',
      'data-test-run-id': run.run_id,
      ontoggle: (event) => {
        if (event.currentTarget.open) loadTestRunEvidence(run, evidenceHost);
      },
    }, h('summary', { 'data-test-focus-key': `run:${run.run_id}` }, 'Run evidence'), evidenceHost);
    return h('article', { class: `test-run-history-card is-${run.state || 'unknown'}` },
      h('div', { class: 'test-run-history-main' },
        h('div', null,
          h('strong', null, `${run.intent || 'manual'} · ${run.actor || 'unknown actor'}`),
          h('span', { class: `test-run-status is-${run.state || 'unknown'}` }, testRunStateLabel(run.state))),
        h('p', null, `${run.queued_at ? fmtWhen(run.queued_at) : 'Time unavailable'} · ${run.source_mode || 'unknown'} source`)),
      h('div', { class: 'test-run-history-metrics' },
        h('span', null, `${completed}/${targetCount} targets`),
        h('span', null, wallSeconds === null ? '— wall' : `${fmtSeconds(wallSeconds)} wall`)),
      waitLabel ? h('p', { class: 'test-run-wait' }, waitLabel) : null,
      active ? h('div', {
        class: 'test-run-history-progress', role: 'progressbar',
        'aria-label': `${completed} of ${targetCount} targets complete`,
        'aria-valuemin': 0, 'aria-valuemax': targetCount, 'aria-valuenow': completed,
      }, h('span', { style: `width:${progress.toFixed(1)}%` })) : null,
      evidence);
  }

  function renderCurrentTestRuns() {
    if (state.testsRunsLoading && !state.testsRuns) {
      return [h('div', { class: 'skel', 'aria-hidden': 'true' })];
    }
    if (!state.testsRuns) {
      return [testLocalFailure('Current runs are unavailable', state.testsRunsError,
        () => loadTestRuns({ force: true }))];
    }
    const rows = state.testsRuns.runs || [];
    if (!rows.length) {
      return [h('p', { class: 'empty-inline' }, 'No tests are currently running for this repository.')];
    }
    return [h('section', {
      class: 'test-run-history',
      'aria-label': 'Current repository test runs',
      'aria-busy': String(state.testsRunsLoading),
    }, rows.map(testRunHistoryCard))];
  }

  function renderTestDetail() {
    const host = $('#test-detail-body');
    if (!host || !$('#test-detail-dialog').open) return;
    const focusKey = document.activeElement?.dataset?.testFocusKey || null;
    const openRuns = new Set([...host.querySelectorAll('details[open][data-test-run-id]')]
      .map((node) => node.dataset.testRunId));
    host.replaceChildren(...renderCurrentTestRuns());
    for (const disclosure of host.querySelectorAll('details[data-test-run-id]')) {
      if (openRuns.has(disclosure.dataset.testRunId)) disclosure.open = true;
    }
    if (focusKey) {
      const restore = [...host.querySelectorAll('[data-test-focus-key]')]
        .find((node) => node.dataset.testFocusKey === focusKey);
      restore?.focus({ preventScroll: true });
    }
  }
  function fillTestRunRepositories(selected = null) {
    const repositories = testRepositories();
    const select = $('#test-run-project');
    select.replaceChildren(...repositories.map((repository) => h('option', {
      value: repository.repo_id,
      selected: repository.repo_id === selected,
    }, repository.display_name || repository.repo_id)));
  }

  function sourceKey(selector) {
    if (!selector || typeof selector !== 'object' || Array.isArray(selector)
      || Object.keys(selector).sort().join(',') !== [
        'kind', 'repository_generation', 'repository_id', 'schema_version',
      ].sort().join(',')
      || selector.schema_version !== 1
      || !['original', 'temporary'].includes(selector.kind)
      || typeof selector.repository_id !== 'string'
      || !selector.repository_id
      || !Number.isInteger(selector.repository_generation)
      || selector.repository_generation < 0) return '';
    return `${selector.kind}:${selector.repository_id}:${selector.repository_generation}`;
  }

  function selectedTestRunSource() {
    const catalog = state.testsRunSourceCatalog;
    if (!catalog || catalog.repository_id !== $('#test-run-project').value) return null;
    const selected = $('#test-run-source').value;
    return (catalog.sources || []).find((source) => sourceKey(source.selector) === selected) || null;
  }

  function updateTestRunPreviewAvailability() {
    const button = $('#test-run-preview-button');
    if (!button) return;
    button.disabled = state.testsRunSourceLoading || !selectedTestRunSource();
  }

  function renderTestRunSources() {
    const select = $('#test-run-source');
    const repoId = $('#test-run-project').value;
    const catalog = state.testsRunSourceCatalog?.repository_id === repoId
      ? state.testsRunSourceCatalog : null;
    const previous = state.testsRunSourceSelections.get(repoId)
      || sourceKey(catalog?.default_source);
    if (state.testsRunSourceLoading && !catalog) {
      select.replaceChildren(h('option', { value: '' }, 'Reading configured sources…'));
      select.disabled = true;
      updateTestRunPreviewAvailability();
      return;
    }
    if (!catalog) {
      const detail = state.testsRunSourceError?.message || 'Authorized sources are unavailable';
      select.replaceChildren(h('option', { value: '' }, detail));
      select.disabled = true;
      updateTestRunPreviewAvailability();
      return;
    }
    const options = (catalog.sources || []).map((source) => h('option', {
      value: sourceKey(source.selector),
      selected: sourceKey(source.selector) === previous,
    }, source.selector.kind === 'temporary'
      ? `${source.label} · temporary worktree`
      : source.label));
    select.replaceChildren(...options);
    if (!select.value && options.length) select.value = sourceKey(catalog.default_source);
    select.disabled = options.length === 0;
    const selected = selectedTestRunSource();
    if (selected) state.testsRunSourceSelections.set(repoId, sourceKey(selected.selector));
    updateTestRunPreviewAvailability();
  }

  async function loadTestRunSources(repoId) {
    if (!repoId) return;
    if (state.testsRunSourceCatalog?.repository_id === repoId) {
      renderTestRunSources();
      return;
    }
    const request = state.testsRunSourceRequest + 1;
    state.testsRunSourceRequest = request;
    state.testsRunSourceLoading = true;
    state.testsRunSourceError = null;
    renderTestRunSources();
    try {
      const catalog = await api(`/api/tests/repositories/${encodeURIComponent(repoId)}/sources`);
      if (request !== state.testsRunSourceRequest || $('#test-run-project').value !== repoId) return;
      if (!catalog || catalog.schema_version !== 1 || catalog.repository_id !== repoId
        || !Array.isArray(catalog.sources) || catalog.sources.length === 0) {
        throw new ApiError('repository test source authority is invalid', 502);
      }
      const keys = catalog.sources.map((source) => sourceKey(source.selector));
      if (keys.some((key) => !key) || new Set(keys).size !== keys.length
        || !keys.includes(sourceKey(catalog.default_source))) {
        throw new ApiError('repository test source identities are invalid', 502);
      }
      state.testsRunSourceCatalog = catalog;
    } catch (error) {
      if (request !== state.testsRunSourceRequest || $('#test-run-project').value !== repoId) return;
      state.testsRunSourceCatalog = null;
      state.testsRunSourceError = error;
    } finally {
      if (request === state.testsRunSourceRequest) {
        state.testsRunSourceLoading = false;
        renderTestRunSources();
      }
    }
  }

  function resetTestRunPreview() {
    state.testsPlan = null;
    state.testsPlanOperationId = null;
    $('#test-run-submit').disabled = true;
    $('#test-run-error').hidden = true;
    $('#test-run-preview').replaceChildren(h('p', { class: 'meta-passive' },
      'Preview the plan to see selected targets, reasons, dependency waves and resource policy.'));
    updateTestRunPreviewAvailability();
  }

  function testRunTargetNames(setup) {
    const declared = Array.isArray(setup?.targets)
      ? setup.targets.map((target) => (typeof target === 'string' ? target : target?.name))
      : Object.keys(setup?.target_graph || {});
    return [...new Set(declared
      .filter((target) => typeof target === 'string' && target)
      .map(String))].sort((a, b) => a.localeCompare(b));
  }

  function selectedTestRunTargets() {
    return [...document.querySelectorAll('#test-run-targets input[type="checkbox"]:checked')]
      .map((input) => input.value);
  }

  function renderTestRunTargets() {
    const host = $('#test-run-targets');
    const repoId = $('#test-run-project').value;
    if (state.testsRunTargetLoading && state.testsRunTargetSetup?.repo_id !== repoId) {
      host.replaceChildren(h('p', { class: 'meta-passive' }, 'Reading declared targets…'));
      return;
    }
    if (state.testsRunTargetError && state.testsRunTargetSetup?.repo_id !== repoId) {
      host.replaceChildren(h('p', { class: 'meta-passive' }, state.testsRunTargetError.message));
      return;
    }
    const targets = state.testsRunTargetSetup?.repo_id === repoId
      ? testRunTargetNames(state.testsRunTargetSetup) : [];
    if (!targets.length) {
      host.replaceChildren(h('p', { class: 'meta-passive' }, 'No runnable targets are declared for this repository.'));
      return;
    }
    host.replaceChildren(...targets.map((target) => h('label', null,
      h('input', {
        type: 'checkbox', value: target, checked: true,
        onchange: resetTestRunPreview,
      }),
      h('span', { title: target }, target))));
  }

  function updateTestRunTargetField() {
    const manual = $('#test-run-intent').value === 'manual';
    $('#test-run-target-field').hidden = !manual;
    if (manual) renderTestRunTargets();
  }

  async function loadTestRunTargets(repoId) {
    if (!repoId || $('#test-run-intent').value !== 'manual') return;
    if (state.testsRunTargetSetup?.repo_id === repoId) {
      renderTestRunTargets();
      return;
    }
    const request = state.testsRunTargetRequest + 1;
    state.testsRunTargetRequest = request;
    state.testsRunTargetLoading = true;
    state.testsRunTargetError = null;
    renderTestRunTargets();
    try {
      const setup = await api(`/api/tests/repositories/${encodeURIComponent(repoId)}/setup`);
      if (request !== state.testsRunTargetRequest || $('#test-run-project').value !== repoId) return;
      if (!setup || (setup.repo_id && setup.repo_id !== repoId)) {
        throw new ApiError('repository test setup identity is invalid', 502);
      }
      state.testsRunTargetSetup = { ...setup, repo_id: repoId };
    } catch (err) {
      if (request !== state.testsRunTargetRequest || $('#test-run-project').value !== repoId) return;
      state.testsRunTargetError = err;
      state.testsRunTargetSetup = null;
    } finally {
      if (request === state.testsRunTargetRequest) {
        state.testsRunTargetLoading = false;
        renderTestRunTargets();
      }
    }
  }

  function openTestRunDialog(repoId = null) {
    fillTestRunRepositories(repoId || state.testsProject);
    $('#test-run-intent').value = 'manual';
    state.testsRunTargetSetup = null;
    state.testsRunTargetError = null;
    state.testsRunSourceCatalog = null;
    state.testsRunSourceError = null;
    resetTestRunPreview();
    updateTestRunTargetField();
    const dialog = $('#test-run-dialog');
    if (!dialog.open) dialog.showModal();
    const selectedRepoId = $('#test-run-project').value;
    loadTestRunTargets(selectedRepoId);
    loadTestRunSources(selectedRepoId);
  }

  function closeTestRunDialog() {
    state.testsRunTargetRequest += 1;
    state.testsRunSourceRequest += 1;
    const dialog = $('#test-run-dialog');
    if (dialog.open) dialog.close();
  }

  async function previewTestRun() {
    const error = $('#test-run-error');
    error.hidden = true;
    $('#test-run-preview-button').disabled = true;
    try {
      const intent = $('#test-run-intent').value;
      const source = selectedTestRunSource();
      if (!source) {
        throw new ApiError('Choose a configured repository source.', 400);
      }
      const requestedTargets = intent === 'manual' ? selectedTestRunTargets() : [];
      if (intent === 'manual' && requestedTargets.length === 0) {
        throw new ApiError('Select at least one declared target for a manual run.', 400);
      }
      const operationId = state.testsPlanOperationId || crypto.randomUUID();
      state.testsPlanOperationId = operationId;
      const plan = await api('/api/tests/plan', {
        method: 'POST',
        body: {
          repo_id: $('#test-run-project').value,
          intent,
          operation_id: operationId,
          source: source.selector,
          ...(intent === 'manual' ? { requested_targets: requestedTargets } : {}),
        },
      });
      if (plan.operation_id !== operationId) {
        throw new ApiError('repository test plan operation identity is invalid', 502);
      }
      if (sourceKey(plan.source_selector) !== sourceKey(source.selector)) {
        throw new ApiError('repository test plan source identity is invalid', 502);
      }
      state.testsPlan = plan;
      const planDocument = plan.plan || plan;
      const targets = planDocument.targets || planDocument.selected_targets || [];
      const reasons = planDocument.selection_reasons || planDocument.reasons
        || Object.values(planDocument.selection || {}).flatMap((item) => item?.reasons || []);
      $('#test-run-preview').replaceChildren(
        h('div', { class: 'test-run-preview-head' },
          h('strong', null, `${targets.length} selected target${sfx(targets.length)}`),
          h('span', null, plan.estimated_seconds ? `~${fmtSeconds(plan.estimated_seconds)}` : 'Estimate unavailable')),
        h('p', null, reasons.slice(0, 3).join(' · ') || 'Targets selected by the repository manifest and dependency graph.'),
        h('dl', null,
          h('div', null, h('dt', null, 'Source'), h('dd', null, plan.source_label || source.label)),
          h('div', null, h('dt', null, 'Waves'), h('dd', null, String((planDocument.waves || planDocument.dependency_waves || []).length || '—'))),
          h('div', null, h('dt', null, 'Parallelism'), h('dd', null, String(planDocument.parallelism || planDocument.max_parallel || 'policy'))),
          h('div', null, h('dt', null, 'Network'), h('dd', null, planDocument.network || 'manifest policy'))));
      $('#test-run-submit').disabled = !plan.plan_id;
    } catch (err) {
      error.textContent = err.message;
      error.hidden = false;
    } finally {
      updateTestRunPreviewAvailability();
    }
  }

  async function submitTestRun() {
    const error = $('#test-run-error');
    error.hidden = true;
    const submit = $('#test-run-submit');
    submit.disabled = true;
    try {
      const result = await api('/api/tests/runs', {
        method: 'POST',
        body: {
          repo_id: state.testsPlan?.repository_id ?? state.testsPlan?.repo_id,
          plan_id: state.testsPlan?.plan_id,
          operation_id: crypto.randomUUID(),
        },
      });
      closeTestRunDialog();
      await loadTests({ force: true });
      const submittedRepoId = result.repo_id ?? result.repository_id;
      if (submittedRepoId === state.testsProject) {
        // An accepted submission changes the current-run collection.
        state.testsRuns = null;
        state.testsRunsError = null;
      }
      if (submittedRepoId) openTestRuns(submittedRepoId);
    } catch (err) {
      error.textContent = err.message;
      error.hidden = false;
      submit.disabled = false;
    }
  }

  function testRepositoryCount() {
    return state.testsRepositories ? testRepositories().length : null;
  }

  function renderTests() {
    if (currentPage() !== 'tests') return;
    const host = $('#tests-body');
    const repositoryCount = testRepositoryCount();
    setCount('tests-count', repositoryCount);
    $('#tests-run').disabled = !repositoryCount;
    if (state.testsLoading && !state.testsRepositories) {
      if (state.testsRenderSignature === 'loading') return;
      host.replaceChildren(h('div', { class: 'skel', 'aria-hidden': 'true' }));
      state.testsRenderSignature = 'loading';
      return;
    }
    if (!state.testsRepositories) {
      const failureSignature = `failure:${state.testsError?.message || ''}`;
      if (state.testsRenderSignature === failureSignature) return;
      host.replaceChildren(testLocalFailure(
        'Test repositories are unavailable',
        state.testsError,
        () => loadTests({ force: true }),
      ));
      state.testsRenderSignature = failureSignature;
      return;
    }
    const repositories = testRepositories();
    const renderSignature = JSON.stringify(repositories);
    if (state.testsRenderSignature === renderSignature && host.childElementCount) return;
    host.replaceChildren(
      h('section', { class: 'test-current-repositories', 'aria-label': 'Test repositories' },
        repositories.length
          ? repositories.map((repository) => h('button', {
            class: 'test-current-repository test-repository-button',
            type: 'button',
            onclick: () => openTestRunDialog(repository.repo_id),
          },
            h('strong', null, repository.display_name || repository.name || 'Repository'),
            h('span', null, repository.status || repository.setup_status || 'Configured'),
          ))
          : h('p', { class: 'empty' }, 'No test repositories are configured'),
      ),
    );
    state.testsRenderSignature = renderSignature;
  }

  // ---------------------------------------------------------------- render root

  const SECTION_BODY_PAGES = Object.freeze({
    'projects-body': 'projects',
    'tests-body': 'tests',
    'efficiency-body': 'efficiency',
    'bugs-body': 'bugs',
    'routes-body': 'routes',
    'servers-body': 'servers',
    'docker-body': 'docker',
    'leases-body': 'ports',
    'assignments-body': 'ports',
    'perf-body': 'performance',
    'access-body': 'access',
    'invites-body': 'invites',
    'telegram-body': 'telegram',
  });

  function unmountInactiveSections(page) {
    for (const [id, ownerPage] of Object.entries(SECTION_BODY_PAGES)) {
      if (ownerPage === page) continue;
      const host = document.getElementById(id);
      if (host.childNodes.length) host.replaceChildren();
      delete sigs[id];
    }
  }

  function renderAll(force = false) {
    const page = currentPage();
    if (page !== 'projects') hideResourceKindTooltip(null, true);
    unmountInactiveSections(page);
    const o = state.overview;
    if (page === 'bugs') {
      if (o) renderHeader();
      renderBugs(force);
      return;
    }
    if (page === 'efficiency') {
      if (o) renderHeader();
      renderEfficiency(force);
      return;
    }
    if (!o) {
      if (page === 'performance') {
        setSection('perf-body', sig(state.metricsAt, 'metrics-only'), () => buildPerf(null), force);
        renderPerformanceProjectDialog();
        const count = performanceProjectCount(null);
        setCount('perf-count', count);
        setNavCount('performance', count);
      }
      return;
    }
    if (popover.key !== null) {
      if (!force) { popover.pending = true; return; }
      popover.pending = false;
      popover.close();
    }
    renderHeader();
    if (page === 'routes') {
      updateServerOptions(o);
      updateContainerOptions(o);
    }

    // Only render-relevant coordinator facts belong in section signatures:
    // lastOkAt changes on every poll and would defeat the memoization,
    // rebuilding every card each 6s even when nothing visible changed.
    const coordSig = o.coordinator ? [o.coordinator.ok, o.coordinator.lastError] : null;

    if (page === 'projects') {
      setSection('projects-body',
        sig(o.inventory?.servers ?? null, o.inventory?.docker ?? null, o.inventory?.project_usage ?? null,
          o.inventory?.repository_trees ?? null, o.inventory?.repositories ?? null,
          o.inventory?.resources?.databases ?? null, o.inventory?.unassigned_resources ?? null,
          o.inventory?.lifecycle_violations ?? null, o.routes ?? null, state.archives,
          ui.lifecycleViews.projects, coordSig),
        () => ui.lifecycleViews.projects === 'archived'
          ? buildArchivedCollection('projects') : buildProjects(o), force);
    } else if (page === 'tests') {
      renderTests();
    } else if (page === 'routes') {
      setSection('routes-body', sig(o.routes), () => buildRoutes(o), force);
      restorePendingCreatedRouteFocus();
    } else if (page === 'servers') {
      setSection('servers-body',
        sig(o.inventory?.servers ?? null, o.inventory?.port_assignments ?? null,
          o.inventory?.docker ?? null, o.inventory?.repository_trees ?? null,
          o.inventory?.resources?.databases ?? null, o.inventory?.unassigned_resources ?? null,
          o.inventory?.lifecycle_violations ?? null, o.routes ?? null, state.archives,
          ui.lifecycleViews.servers, coordSig),
        () => ui.lifecycleViews.servers === 'archived'
          ? buildArchivedCollection('servers') : buildServers(o), force);
    } else if (page === 'docker') {
      setSection('docker-body',
        sig(o.inventory?.docker ?? null, o.inventory?.repository_trees ?? null,
          o.inventory?.resources?.databases ?? null, o.inventory?.unassigned_resources ?? null,
          o.inventory?.lifecycle_violations ?? null, o.routes ?? null, state.archives,
          ui.lifecycleViews.docker, coordSig),
        () => ui.lifecycleViews.docker === 'archived'
          ? buildArchivedCollection('docker') : buildDocker(o), force);
    } else if (page === 'ports') {
      setSection('leases-body', sig(o.inventory?.leases ?? null, coordSig), () => buildLeases(o), force);
      setSection('assignments-body', sig(o.inventory?.port_assignments ?? null, coordSig), () => buildAssignments(o), force);
      restorePendingCreatedLeaseFocus();
    } else if (page === 'performance') {
      setSection('perf-body',
        sig(state.metricsAt, o.inventory?.project_usage ?? null,
          o.inventory?.repository_trees ?? null, coordSig),
        () => buildPerf(o), force);
      renderPerformanceProjectDialog();
    } else if (page === 'invites') {
      renderInvites();
    } else if (page === 'telegram') {
      renderTelegram();
    }

    const perfEntities = performanceProjectCount(o);
    const projectGroups = o.inventory ? projectGroupsOf(o).length : null;
    // The Servers page lists coordinator servers plus docker-hosted web
    // servers, so its badges count both.
    const webContainerCount = o.inventory
      ? projectGroupsOf(o).reduce(
          (n, g) => n + g.members.containers.filter((c) => isWebServerContainer(o, g, c)).length, 0)
      : 0;
    setCount('projects-count', ui.lifecycleViews.projects === 'archived'
      ? (archivesCurrent ? archivesForPage('projects').length : null) : projectGroups);
    setCount('tests-count', testRepositoryCount());
    setCount('routes-count', (o.routes || []).length);
    setCount('servers-count', ui.lifecycleViews.servers === 'archived'
      ? (archivesCurrent ? archivesForPage('servers').length : null)
      : o.inventory ? (o.inventory.servers || []).length + webContainerCount : null);
    setCount('docker-count', ui.lifecycleViews.docker === 'archived'
      ? (archivesCurrent ? archivesForPage('docker').length : null)
      : o.inventory?.docker?.available
        ? (o.inventory.docker.containers || []).filter((c) => !isTransientTestContainer(c)).length : null);
    setCount('leases-count', o.inventory ? (o.inventory.leases || []).length : null);
    setCount('assignments-count', o.inventory ? (o.inventory.port_assignments || []).length : null);
    setCount('perf-count', perfEntities);
    setCount('projects-active-count', projectGroups);
    setCount('servers-active-count', o.inventory ? (o.inventory.servers || []).length + webContainerCount : null);
    setCount('docker-active-count', o.inventory?.docker?.available
      ? (o.inventory.docker.containers || []).filter((c) => !isTransientTestContainer(c)).length : null);
    syncLifecycleFilters();

    setNavCount('projects', projectGroups);
    setNavCount('tests', testRepositoryCount());
    setNavCount('servers', o.inventory ? (o.inventory.servers || []).length + webContainerCount : null);
    setNavCount('routes', (o.routes || []).length);
    setNavCount('docker', o.inventory?.docker?.available
      ? (o.inventory.docker.containers || []).filter((c) => !isTransientTestContainer(c)).length : null);
    setNavCount('ports', o.inventory
      ? (o.inventory.leases || []).length + (o.inventory.port_assignments || []).length
      : null);
    setNavCount('performance', perfEntities);
    focusLifecycleTarget();
  }

  function focusLifecycleTarget() {
    const focus = ui.lifecycleFocus;
    if (!focus || focus.page !== currentPage()) return;
    // Mutation refreshes can rebuild the same collection more than once.
    // Focus only after both inventory and archive truth are settled so the
    // focused node is not immediately replaced and focus lost to <body>.
    if (lifecycleRefreshInFlight) return;
    queueMicrotask(() => {
      const target = document.querySelector(
        `#sec-${focus.page} [data-lifecycle-target="${CSS.escape(`${focus.target_kind}:${focus.target_id}`)}"]`,
      );
      // The archive list may still be catching up with the inventory refresh;
      // keep the pending focus until its authoritative fetch renders the row.
      if (!target && (lifecycleRefreshInFlight || (focus.view === 'archived' && archivesFetching))) return;
      if (!target && Date.now() < (focus.fallbackAfter || 0)) return;
      if (!target) {
        ui.lifecycleFocus = null;
        document.querySelector(
          `[data-lifecycle-filter="${focus.page}"] [data-lifecycle-view="${focus.view}"]`,
        )?.focus({ preventScroll: true });
        return;
      }
      ui.lifecycleFocus = null;
      target.scrollIntoView({ block: 'nearest' });
      target.focus({ preventScroll: true });
    });
  }

  function sig(...slices) {
    return `${ui.version}|${JSON.stringify(slices)}`;
  }

  function setSection(id, signature, build, force) {
    if (!force && sigs[id] === signature) return;
    sigs[id] = signature;
    const host = document.getElementById(id);

    // Polling replaces section nodes when visible inventory facts change. Keep
    // user-controlled native disclosures stable across that replacement just
    // like the custom project accordions: a five-second refresh must not close
    // the ownership evidence someone is reading. The key is scoped to this
    // section, so identical diagnostics on Servers and Docker remain
    // independent. Inventory observers can also replace one opaque resource
    // ID while preserving the same finding; use the optional match key only
    // when it is unambiguous on both the old and new DOM.
    const disclosures = new Map();
    const disclosureMatchCounts = new Map();
    const disclosureStateKey = (key) => `${id}\u0000${key}`;
    const countDisclosureMatch = (match) => {
      if (!match) return;
      disclosureMatchCounts.set(match, (disclosureMatchCounts.get(match) || 0) + 1);
    };
    const rememberDisclosure = (el) => {
      const key = el.dataset.sectionDisclosure;
      if (key) ui.sectionDisclosures.set(disclosureStateKey(key), el.open);
      const match = el.dataset.sectionDisclosureMatch;
      if (match) ui.sectionDisclosures.set(disclosureStateKey(match), el.open);
    };
    for (const el of host.querySelectorAll('details[data-section-disclosure]')) {
      disclosures.set(el.dataset.sectionDisclosure, el.open);
      countDisclosureMatch(el.dataset.sectionDisclosureMatch);
      rememberDisclosure(el);
    }
    const scrolls = new Map();
    for (const el of host.querySelectorAll('[data-scrollkey]')) scrolls.set(el.dataset.scrollkey, el.scrollTop);
    const preserveViewport = host.childNodes.length > 0;
    const viewport = preserveViewport ? { x: window.scrollX, y: window.scrollY } : null;
    const active = document.activeElement;
    const fk = active && host.contains(active) ? active.dataset.fk : null;
    const fkMatch = active && host.contains(active)
      ? active.dataset.sectionDisclosureMatch : null;

    const nodes = build();
    host.replaceChildren(...(Array.isArray(nodes) ? nodes.filter(Boolean) : [nodes]));

    const replacementDisclosures = [...host.querySelectorAll('details[data-section-disclosure]')];
    const replacementMatchCounts = new Map();
    for (const el of replacementDisclosures) {
      const match = el.dataset.sectionDisclosureMatch;
      if (match) replacementMatchCounts.set(match, (replacementMatchCounts.get(match) || 0) + 1);
    }
    for (const el of replacementDisclosures) {
      const key = el.dataset.sectionDisclosure;
      const match = el.dataset.sectionDisclosureMatch;
      const storedExact = key ? ui.sectionDisclosures.get(disclosureStateKey(key)) : undefined;
      const storedMatch = match ? ui.sectionDisclosures.get(disclosureStateKey(match)) : undefined;
      if (storedExact !== undefined) {
        el.open = storedExact;
      } else if (
        match
        && disclosureMatchCounts.get(match) === 1
        && replacementMatchCounts.get(match) === 1
        && storedMatch !== undefined
      ) {
        el.open = storedMatch;
      } else if (disclosures.has(key)) {
        el.open = disclosures.get(key);
      }
      el.addEventListener('toggle', () => rememberDisclosure(el));
    }
    for (const el of host.querySelectorAll('[data-scrollkey]')) {
      if (scrolls.has(el.dataset.scrollkey)) el.scrollTop = scrolls.get(el.dataset.scrollkey);
    }
    if (fk) {
      const again = host.querySelector(`[data-fk="${CSS.escape(fk)}"]`)
        || (fkMatch ? host.querySelector(
          `[data-fk][data-section-disclosure-match="${CSS.escape(fkMatch)}"]`,
        ) : null);
      let focusTarget = again;
      if (again?.matches(':disabled') && again.dataset.disabledFocusFallback) {
        focusTarget = host.querySelector(
          `[data-fk="${CSS.escape(again.dataset.disabledFocusFallback)}"]`,
        );
      }
      if (focusTarget && !focusTarget.matches(':disabled')) {
        focusTarget.focus({ preventScroll: true });
      }
    }
    if (viewport) window.scrollTo(viewport.x, viewport.y);
    if (id === 'projects-body') queueMicrotask(refreshResourceKindTooltip);
  }

  function setCount(id, n) {
    const el = document.getElementById(id);
    if (n === null || n === undefined) { el.hidden = true; return; }
    el.hidden = false;
    el.textContent = String(n);
  }

  function setNavCount(page, n) {
    const el = document.getElementById(`nav-count-${page}`);
    if (!el) return;
    if (n === null || n === undefined) { el.hidden = true; return; }
    el.hidden = false;
    el.textContent = String(n);
  }

  // ---------------------------------------------------------------- summary bar

  function tlsDaysLeft(o) {
    const notAfter = o.console?.tls?.notAfter;
    if (!notAfter) return null;
    const t = Date.parse(notAfter);
    if (Number.isNaN(t)) return null;
    return Math.floor((t - Date.now()) / 86_400_000);
  }

  // Everything the header should warn about, worst first. Each problem is
  // { severity: 'err'|'warn', title, body() } — the header stays clean when
  // this list is empty; otherwise one badge carries the count and its
  // popover explains every problem with facts, instructions and actions.
  function headerProblems(o) {
    const problems = [];
    if (!o) return problems;
    const reportingCoordinatorBug = currentPage() === 'bugs';

    const c = o.coordinator || {};
    const coordOk = !!c.ok && !!o.inventory;
    if (!reportingCoordinatorBug && !coordOk && c.failureKind !== 'maintenance') {
      problems.push({
        severity: 'err',
        title: coordinatorFailureTitle(o),
        body: () => [
          kv('URL', c.url || '—', { mono: true }),
          kv('Last OK', fmtWhen(c.lastOkAt)),
          c.lastError ? kv('Error', String(c.lastError), { mono: true }) : null,
          h('p', { class: 'pop-hint' }, coordinatorFailureHint(o)),
          h('div', { class: 'prob-actions' },
            h('button', {
              class: 'btn small', type: 'button', 'data-fk': 'hdr-coord-retry',
              onclick: () => refreshOverview({ force: true, fresh: true }),
            }, icon('refresh'), 'Try again')),
        ],
      });
    }

    const days = tlsDaysLeft(o);
    const tls = o.console?.tls;
    const tlsFacts = () => [
      tls?.subject ? kv('Subject', tls.subject, { mono: true }) : null,
      tls?.issuer ? kv('Issuer', tls.issuer, { mono: true }) : null,
      tls?.notAfter ? kv('Expires', `${tls.notAfter}${days !== null ? ` (${days} day${sfx(days)} left)` : ''}`) : null,
      h('p', { class: 'pop-hint' }, 'certbot renews via DNS-01 on a timer and the console hot-reloads the files. If this warning persists, renew by hand:'),
      h('div', { class: 'prob-actions' },
        h('code', { class: 'prob-cmd' }, 'sudo certbot renew'),
        h('button', {
          class: 'btn small', type: 'button', 'data-fk': 'hdr-tls-copy',
          title: 'Copy the renewal command',
          onclick: (e) => copyText('sudo certbot renew', e.currentTarget),
        }, icon('copy'), 'Copy')),
    ];
    if (days !== null && days < 0) {
      problems.push({ severity: 'err', title: 'TLS certificate has EXPIRED', body: tlsFacts });
    } else if (days !== null && days < 14) {
      problems.push({ severity: 'warn', title: `TLS certificate expires in ${days} day${sfx(days)}`, body: tlsFacts });
    } else if (days === null && !o.console?.devInsecureHttp) {
      problems.push({ severity: 'warn', title: 'TLS status unknown', body: tlsFacts });
    }

    if (o.console?.devInsecureHttp) {
      problems.push({
        severity: 'warn',
        title: 'Insecure dev HTTP mode',
        body: () => [h('p', { class: 'pop-hint' }, 'DEV_HTTP=1 — plain HTTP, session cookies are not Secure. Never expose this mode to the internet.')],
      });
    }

    if (coordOk) {
      const bad = (o.inventory.servers || []).filter(
        (s) => s.status === 'unhealthy' || s.health?.classification === 'wrong-listener',
      );
      if (bad.length) {
        problems.push({
          severity: 'warn',
          title: `${bad.length} server${sfx(bad.length)} unhealthy`,
          body: () => [
            kv('Servers', bad.map((s) => s.name).join(', '), { mono: true }),
            h('p', { class: 'pop-hint' }, 'The process is alive but its health check fails — the log usually says why.'),
            h('div', { class: 'prob-actions' },
              h('a', { class: 'btn small', href: '#/servers' }, 'Open Servers')),
          ],
        });
      }
      const broken = (o.routes || []).filter((r) => r.resolved && r.resolved.port == null);
      if (broken.length) {
        problems.push({
          severity: 'warn',
          title: `${broken.length} route${sfx(broken.length)} not resolving`,
          body: () => [
            ...broken.slice(0, 5).map((r) => kv(r.slug, r.resolved?.reason || 'no upstream', { mono: true })),
            h('p', { class: 'pop-hint' }, 'Visitors get an upstream-unavailable page until the target runs again.'),
            h('div', { class: 'prob-actions' },
              h('a', { class: 'btn small', href: '#/routes' }, 'Open Routes')),
          ],
        });
      }
      const docker = o.inventory.docker;
      if (docker && docker.available === false) {
        problems.push({
          severity: 'warn',
          title: 'Docker unavailable',
          body: () => [
            docker.error ? kv('Error', String(docker.error), { mono: true }) : null,
            h('p', { class: 'pop-hint' }, 'Containers cannot be listed or controlled until the Docker daemon answers.'),
          ],
        });
      }
    }

    if (!reportingCoordinatorBug && state.stale && state.lastFetch) {
      problems.push({
        severity: 'warn',
        title: 'Live data is stale',
        body: () => [
          kv('Last update', fmtClock(state.lastFetch)),
          h('div', { class: 'prob-actions' },
            h('button', {
              class: 'btn small', type: 'button', 'data-fk': 'hdr-stale-retry',
              onclick: () => refreshOverview({ force: true, fresh: true }),
            }, icon('refresh'), 'Refresh now')),
        ],
      });
    }

    return problems;
  }

  function alertPop(problems) {
    return h('div', { class: 'alert-pop' },
      popHead('Needs attention'),
      ...problems.map((p) => h('div', { class: `prob ${p.severity}` },
        h('p', { class: 'prob-title' }, h('span', { class: 'dot', 'aria-hidden': 'true' }), p.title),
        ...[p.body()].flat().filter(Boolean))));
  }

  // One-row header: brand + nav + (warning badge only when something is
  // wrong) + account. No status sentence, no always-on chips.
  function renderHeader() {
    const o = state.overview;
    const side = $('#hdr-side');
    // Keep the popover's anchor stable while it is open.
    if (popover.key !== null && String(popover.key).startsWith('hdr-')) return;
    if (o) $('#brand-domain').textContent = o.console?.domain || '';

    const problems = headerProblems(o);
    const worst = problems.some((p) => p.severity === 'err') ? 'err' : 'warn';
    const alert = problems.length
      ? h('button', {
          class: `hdr-alert ${worst}`, type: 'button',
          'data-fk': 'hdr-alert', 'aria-haspopup': 'dialog',
          'aria-expanded': popover.key === 'hdr-alert' ? 'true' : 'false',
          'aria-label': `${problems.length} issue${sfx(problems.length)} need${problems.length === 1 ? 's' : ''} attention — show details and actions`,
          title: problems.map((p) => p.title).join(' · '),
          onclick: (e) => popover.toggle('hdr-alert', e.currentTarget, () => alertPop(headerProblems(state.overview))),
        }, icon('warn'), String(problems.length))
      : null;
    side.replaceChildren(...[alert, userChip()].filter(Boolean));
  }

  function userChip() {
    const email = state.session?.email || '';
    return h('button', {
      class: 'hdr-user', type: 'button',
      'data-fk': 'hdr-user', 'aria-haspopup': 'dialog',
      'aria-expanded': popover.key === 'hdr-user' ? 'true' : 'false',
      'aria-label': `Account ${email || 'signed in'} — show account details and sign out`,
      title: email || 'Signed in',
      onclick: (e) => popover.toggle('hdr-user', e.currentTarget, () => (
        h('div', null,
          popHead('Account'),
          kv('Signed in as', email || '—', { mono: true }),
          h('div', { class: 'prob-actions' },
            h('a', { class: 'btn small', href: '/auth/logout', title: 'Sign out of the console' }, 'Sign out')))
      )),
    }, (email[0] || '?').toUpperCase());
  }

  // ---------------------------------------------------------------- shared bits

  function coordErrorText(o) {
    if (o?.coordinator?.failureKind === 'maintenance') {
      return 'Live data and controls reconnect automatically. Existing services keep running.';
    }
    const e = o?.coordinator?.lastError;
    return e ? String(e) : 'The control engine on 127.0.0.1 did not respond.';
  }

  function coordinatorFailureTitle(o) {
    if (o?.coordinator?.failureKind === 'maintenance') return 'Controls temporarily paused';
    return o?.coordinator?.failureKind === 'request'
      ? 'Coordinator request failed'
      : 'Coordinator unreachable';
  }

  function coordinatorFailureHint(o) {
    if (o?.coordinator?.failureKind === 'maintenance') {
      return 'No action is needed. The Console will resume live updates as soon as the maintenance window finishes.';
    }
    if (o?.coordinator?.failureKind === 'request') {
      return 'The Console could not retrieve inventory, but this was not a network connection failure. Controls remain disabled until the reported request error is resolved; the console keeps retrying. Routes to fixed ports keep working meanwhile.';
    }
    return 'Servers, containers and leases cannot be managed until the Coordinator answers. The console keeps retrying; in production the dedicated coordinator service is restarted by systemd. Routes to fixed ports keep working meanwhile.';
  }

  function degradedPanel(o) {
    const maintenance = o?.coordinator?.failureKind === 'maintenance';
    if (o?.coordinator?.inventoryState === 'loading' || maintenance) {
      return h('div', { class: 'skel', 'aria-hidden': 'true' });
    }
    return h('div', {
      class: 'degraded',
    },
      icon('warn'),
      h('div', null,
        h('p', { class: 'deg-title' }, coordinatorFailureTitle(o)),
        h('p', { class: 'deg-msg' }, coordErrorText(o)),
        h('button', {
          class: 'btn small', type: 'button',
          onclick: () => refreshOverview({ force: true, fresh: true }),
        }, icon('refresh'), 'Try again')));
  }

  function emptyState(text) {
    return h('p', { class: 'empty' }, text);
  }

  function isContainerRunning(c) {
    const status = String(c.status || '').trim();
    return /^up\b/i.test(status) || /^running$/i.test(status);
  }

  async function copyText(text, btn) {
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.append(ta);
        ta.select();
        ok = document.execCommand('copy');
        ta.remove();
      } catch { ok = false; }
    }
    announce(ok ? 'Copied to clipboard' : 'Copy failed');
    if (btn) {
      btn.classList.add('copied');
      const old = btn.firstChild;
      btn.replaceChild(icon(ok ? 'check' : 'x'), old);
      setTimeout(() => {
        if (btn.isConnected) {
          btn.classList.remove('copied');
          btn.replaceChild(icon('copy'), btn.firstChild);
        }
      }, 1200);
    }
  }

  // ---------------------------------------------------------------- routes

  function buildRoutes(o) {
    const routes = o.routes || [];
    const domain = o.console?.domain || 'vr.ae';
    if (!routes.length) {
      return [emptyState(`No routes yet — choose Create route to publish an HTTP target at https://<name>.${domain}.`)];
    }
    const out = [
      h('div', { class: 'grid-head routes-grid', 'aria-hidden': 'true' },
        h('span', null, 'URL'), h('span', null, 'Target'), h('span', null, 'Status'),
        h('span', null, 'Access'), h('span', null, '')),
    ];
    for (const r of routes) {
      out.push(h('div', {
        class: 'item',
        'data-route-slug': r.slug,
        'data-fk': `route-row:${r.slug}`,
        tabindex: '-1',
        'aria-label': `Route ${r.slug}.${domain}`,
      }, routeRow(o, r)));
    }
    if (o.coordinator && o.coordinator.ok === false && o.coordinator.failureKind !== 'maintenance') {
      out.push(h('p', { class: 'inline-note warn-note' },
        'Coordinator is unreachable — live status for server-linked routes may be stale.'));
    }
    return out;
  }

  function routeRow(o, r) {
    const domain = o.console?.domain || 'vr.ae';
    const host = `${r.slug}.${domain}`;
    const url = r.url || `https://${host}`;
    const busy = ui.busy.has(`route:${r.slug}`);
    const res = r.resolved || null;
    const live = !!(res && res.port != null);

    const dotKey = `route-dot:${r.slug}`;
    const dot = h('button', {
      class: `dotbtn ${live ? 'ok' : 'err'}`, type: 'button',
      'data-fk': dotKey, 'aria-haspopup': 'dialog',
      'aria-expanded': popover.key === dotKey ? 'true' : 'false',
      'aria-label': live
        ? `Route status: serving over HTTP from port ${res.port} — show details`
        : 'Route status: not reachable — show details',
      title: live ? `Proxying to http://127.0.0.1:${res.port}` : (res?.reason || 'Not resolvable'),
      onclick: (e) => popover.toggle(dotKey, e.currentTarget, () => (
        h('div', null,
          popHead(`https://${host}`),
          kv('State', live ? 'live' : 'not reachable'),
          live ? kv('Upstream', `http://127.0.0.1:${res.port}`, { mono: true }) : null,
          res?.serverStatus ? kv('Server status', res.serverStatus) : null,
          res?.containerStatus ? kv('Container status', res.containerStatus, { mono: true }) : null,
          !live && res?.reason ? kv('Reason', res.reason, { mono: true }) : null,
          kv('Kind', r.kind === 'port' ? `fixed port ${r.port}`
            : r.kind === 'docker' ? `container "${r.containerName}" port ${r.containerPort}`
            : `server "${r.serverName}"`),
          r.kind === 'server' ? kv('Project', r.project, { mono: true }) : null,
          kv('Created', fmtWhen(r.createdAt)),
          kv('Updated', fmtWhen(r.updatedAt)),
          !live ? h('p', { class: 'pop-hint' },
            r.kind === 'server'
              ? 'Start or restart the linked server on the Servers page, then this route resolves again.'
              : r.kind === 'docker'
                ? 'Start the container on the Servers or Docker page, then this route resolves again.'
                : 'Nothing answered on the fixed port. Start the process listening on it, or repoint the route.')
            : null)
      )),
    }, h('span', { class: 'dot', 'aria-hidden': 'true' }),
      h('span', { class: 'dot-label' }, live ? 'live' : 'down'));

    const isPublic = r.auth === 'public';
    const accessSwitch = h('button', {
      class: `switch${isPublic ? ' public-on' : ''}`, type: 'button', role: 'switch',
      'aria-checked': String(!isPublic),
      'data-fk': `route-auth:${r.slug}`,
      disabled: busy || undefined,
      'aria-label': `Access for ${host}: ${isPublic ? 'public — anyone can open it' : 'Google sign-in required'}. Toggle to change.`,
      title: isPublic ? 'Public — click to require sign-in' : 'Sign-in required — click to make public',
      onclick: () => {
        const makingPublic = !isPublic;
        runAction(`route:${r.slug}`,
          () => api(`/api/routes/${encodeURIComponent(r.slug)}`, {
            method: 'PATCH', body: { auth: makingPublic ? 'public' : 'google' },
          }),
          {
            confirmText: makingPublic
              ? `Make https://${host} public?\n\nAnyone on the internet will reach this dev server without signing in.`
              : undefined,
            onError: (error) => {
              if (!isEdgePublicationError(error)) return;
              void refreshOverview({ force: true, fresh: true }).finally(() => {
                showSectionPublicationError(
                  'routes-body', error,
                  () => refreshOverview({ force: true, fresh: true }),
                );
              });
            },
          });
      },
    }, h('span', { class: 'knob', 'aria-hidden': 'true' }),
      h('span', { class: 'sw-label' }, busy ? 'Saving…' : (isPublic ? 'Public' : 'Login')));

    const targetText = r.kind === 'port'
      ? `fixed port ${r.port}`
      : r.kind === 'docker'
        ? `${r.containerName} · HTTP container :${r.containerPort}`
        : `${r.serverName} · HTTP · ${projectTail(r.project)}`;

    return h('div', { class: 'row routes-grid' },
      h('span', { class: 'cell url-cell', 'data-label': 'URL' },
        h('a', {
          class: 'route-url', href: url, target: '_blank', rel: 'noopener noreferrer',
          title: `Open ${url} in a new tab`,
        }, host),
        h('button', {
          class: 'iconbtn copybtn', type: 'button',
          'data-fk': `route-copy:${r.slug}`,
          'aria-label': `Copy ${url}`, title: 'Copy URL',
          onclick: (e) => copyText(url, e.currentTarget),
        }, icon('copy'))),
      h('span', { class: 'cell', 'data-label': 'Target', title: r.kind === 'server' ? (r.project || '') : '' },
        targetText,
        r.kind === 'server' || r.kind === 'docker'
          ? h('a', {
              class: 'target-srv-link', href: '#/servers',
              title: 'Manage this server and its subdomain on the Servers page',
            }, 'view server')
          : null,
        r.title ? h('span', { class: 'title-line' }, r.title) : null),
      h('span', { class: 'cell', 'data-label': 'Status' }, dot),
      h('span', { class: 'cell', 'data-label': 'Access' }, accessSwitch),
      h('span', { class: 'cell actions' },
        h('button', {
          class: 'iconbtn danger', type: 'button',
          'data-fk': `route-del:${r.slug}`,
          'aria-label': `Delete route ${host}`, title: 'Delete route',
          disabled: busy || undefined,
          onclick: () => runAction(`route:${r.slug}`,
            () => api(`/api/routes/${encodeURIComponent(r.slug)}`, { method: 'DELETE' }),
            {
              confirmText: `Remove the route https://${host}?\n\nThe dev server keeps running — only this public URL stops working.`,
              onError: (error) => {
                if (!isEdgePublicationError(error)) return;
                void refreshOverview({ force: true, fresh: true }).finally(() => {
                  showSectionPublicationError(
                    'routes-body', error,
                    () => refreshOverview({ force: true, fresh: true }),
                  );
                });
              },
            }),
        }, icon('trash'))));
  }

  // ---------------------------------------------------------------- create form

  function accessRequired() {
    return $('#rf-access').getAttribute('aria-checked') === 'true';
  }

  function slugProblem(v) {
    if (!SLUG_RE.test(v)) return 'Use lowercase letters, digits and hyphens; start and end with a letter or digit.';
    const consoleLabel = state.overview?.console?.consoleHost?.split('.')[0];
    if (RESERVED_SLUGS.has(v) || v === consoleLabel) return `"${v}" is a reserved name.`;
    if ((state.overview?.routes || []).some((r) => r.slug === v)) return `"${v}" is already routed.`;
    return null;
  }

  function updatePreview() {
    const v = $('#rf-slug').value.trim();
    const p = $('#rf-preview');
    const domain = state.overview?.console?.domain || 'vr.ae';
    if (!v) {
      p.className = 'preview';
      p.textContent = `Pick a short name — it becomes https://<name>.${domain}`;
      return;
    }
    const problem = slugProblem(v);
    if (problem) {
      p.className = 'preview bad';
      p.textContent = problem;
    } else {
      p.className = 'preview ok';
      p.textContent = `Will be served at https://${v}.${domain}`;
    }
  }

  let containerOptsSig = '';

  // One option per (running container, published port): the value carries
  // both so the submit handler needs no second control.
  function updateContainerOptions(o) {
    const rows = [];
    if (o.inventory?.docker?.available) {
      const dbNames = new Set((o.inventory.docker.postgres || []).map((c) => c.name));
      for (const c of o.inventory.docker.containers || []) {
        if (isTransientTestContainer(c)) continue;
        if (!c?.name || dbNames.has(c.name) || !isContainerRunning(c)) continue;
        for (const p of publishedContainerPorts(c.ports)) {
          rows.push({ name: c.name, port: p.containerPort, hostPort: p.hostPort, project: c.project || c.compose_project || '' });
        }
      }
    }
    rows.sort((a, b) => a.name.localeCompare(b.name) || a.port - b.port);
    // The placeholder wording depends on WHY the list is empty, so that
    // state is part of the rebuild signature too.
    const emptyReason = !o.inventory
      ? 'Coordinator unavailable'
      : (o.inventory.docker?.available !== true
        ? 'Docker unavailable'
        : 'No running containers publish a port');
    const newSig = JSON.stringify([emptyReason, rows]);
    if (newSig === containerOptsSig) return;
    containerOptsSig = newSig;

    const sel = $('#rf-container');
    const prev = sel.value;
    sel.replaceChildren();
    if (!rows.length) {
      sel.append(h('option', { value: '' }, emptyReason));
      sel.disabled = true;
      return;
    }
    sel.disabled = false;
    sel.append(h('option', { value: '' }, 'Choose a container…'));
    for (const row of rows) {
      const value = JSON.stringify([row.name, row.port]);
      sel.append(h('option', {
        value,
        selected: value === prev || undefined,
      }, `${row.name}${row.project ? ` · ${projectTail(row.project)}` : ''} · HTTP :${row.port} (host :${row.hostPort})`));
    }
  }

  let serverOptsSig = '';

  function updateServerOptions(o) {
    const servers = (o.inventory?.servers || [])
      .slice()
      .sort((a, b) => (a.status === 'running' ? 0 : 1) - (b.status === 'running' ? 0 : 1)
        || String(a.name).localeCompare(String(b.name)));
    const newSig = JSON.stringify(servers.map((s) => [s.id, s.name, s.status, s.port]));
    if (newSig === serverOptsSig) return;
    serverOptsSig = newSig;

    const sel = $('#rf-server');
    const prev = sel.value;
    sel.replaceChildren();
    if (!servers.length) {
      sel.append(h('option', { value: '' },
        o.inventory ? 'No coordinator servers yet' : 'Coordinator unavailable'));
      sel.disabled = true;
      return;
    }
    sel.disabled = false;
    sel.append(h('option', { value: '' }, 'Choose a server…'));
    for (const s of servers) {
      sel.append(h('option', {
        value: s.id,
        disabled: s.status === 'stopped' || undefined,
        selected: s.id === prev || undefined,
      }, `${s.name} · ${projectTail(s.project)} · :${s.port} (${s.status})`));
    }
  }

  let routeDialogReturnFocus = null;
  let pendingCreatedRouteFocus = null;

  function createdRouteRow(slug) {
    return [...document.querySelectorAll('#routes-body [data-route-slug]')]
      .find((candidate) => candidate.dataset.routeSlug === String(slug || '')) || null;
  }

  function restorePendingCreatedRouteFocus() {
    const pending = pendingCreatedRouteFocus;
    if (!pending || currentPage() !== 'routes' || $('#route-dialog').open) return;
    const active = document.activeElement;
    const mayRestore = active === document.body
      || active === $('#route-add')
      || active?.dataset?.routeSlug === pending.slug;
    if (!mayRestore) return;
    setTimeout(() => {
      if (pendingCreatedRouteFocus !== pending) return;
      const row = createdRouteRow(pending.slug);
      if (!row) return;
      row.focus({ preventScroll: true });
      row.scrollIntoView({ block: 'center' });
    }, 0);
  }

  function requestCreatedRouteFocus(slug) {
    const pending = { slug: String(slug || '') };
    pendingCreatedRouteFocus = pending;
    restorePendingCreatedRouteFocus();
    setTimeout(() => {
      if (pendingCreatedRouteFocus === pending) pendingCreatedRouteFocus = null;
    }, 5_000);
  }

  function updateRouteTargetFields() {
    const kind = $('#route-form').querySelector('input[name="rf-kind"]:checked')?.value || 'port';
    $('#rf-port-wrap').hidden = kind !== 'port';
    $('#rf-server-wrap').hidden = kind !== 'server';
    $('#rf-container-wrap').hidden = kind !== 'docker';
  }

  function resetRouteForm() {
    $('#route-form').reset();
    $('#rf-error').hidden = true;
    $('#rf-error').textContent = '';
    const access = $('#rf-access');
    access.setAttribute('aria-checked', 'true');
    access.classList.remove('public-on');
    $('#rf-access-text').textContent = 'Google sign-in required';
    updateRouteTargetFields();
    updatePreview();
  }

  function openRouteDialog() {
    const dialog = $('#route-dialog');
    routeDialogReturnFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement : $('#route-add');
    resetRouteForm();
    dialog.showModal();
    queueMicrotask(() => $('#rf-slug').focus());
  }

  function focusAfterRouteDialog(target) {
    routeDialogReturnFocus = null;
    setTimeout(() => {
      if (!target?.isConnected) return;
      target.focus({ preventScroll: true });
      target.scrollIntoView({ block: 'nearest' });
    }, 0);
  }

  function closeRouteDialog(focusTarget = null) {
    const dialog = $('#route-dialog');
    const target = focusTarget || routeDialogReturnFocus || $('#route-add');
    if (dialog.open) dialog.close();
    focusAfterRouteDialog(target);
  }

  async function waitForCreatedRouteRow(slug, timeoutMs = 5_000) {
    const deadline = Date.now() + timeoutMs;
    do {
      const row = createdRouteRow(slug);
      if (row && !fetching && !refetchQueued) {
        await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        if (row.isConnected && !fetching && !refetchQueued) return row;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    } while (Date.now() < deadline);
    return null;
  }

  function wireForm() {
    const form = $('#route-form');
    const slug = $('#rf-slug');
    const access = $('#rf-access');

    $('#route-add').addEventListener('click', openRouteDialog);
    $('#route-dialog-close').append(icon('x'));
    $('#route-dialog-close').addEventListener('click', () => closeRouteDialog());
    $('#route-cancel').addEventListener('click', () => closeRouteDialog());
    $('#route-dialog').addEventListener('cancel', (event) => {
      event.preventDefault();
      closeRouteDialog();
    });

    slug.addEventListener('input', () => {
      const lower = slug.value.toLowerCase();
      if (lower !== slug.value) slug.value = lower;
      updatePreview();
    });

    for (const radio of form.querySelectorAll('input[name="rf-kind"]')) {
      radio.addEventListener('change', updateRouteTargetFields);
    }

    access.addEventListener('click', () => {
      const now = access.getAttribute('aria-checked') === 'true';
      access.setAttribute('aria-checked', String(!now));
      access.classList.toggle('public-on', now);
      $('#rf-access-text').textContent = now ? 'Public — no sign-in' : 'Google sign-in required';
    });

    form.addEventListener('submit', onCreateRoute);
    resetRouteForm();
  }

  async function onCreateRoute(e) {
    e.preventDefault();
    const errEl = $('#rf-error');
    errEl.hidden = true;
    errEl.textContent = '';
    const fail = (msg) => { errEl.textContent = msg; errEl.hidden = false; };

    const domain = state.overview?.console?.domain || 'vr.ae';
    const slug = $('#rf-slug').value.trim();
    if (!slug) { fail('Enter a subdomain name.'); $('#rf-slug').focus(); return; }
    const problem = slugProblem(slug);
    if (problem) { fail(problem); $('#rf-slug').focus(); return; }

    const kind = document.querySelector('input[name="rf-kind"]:checked').value;
    const body = { slug, kind, auth: accessRequired() ? 'google' : 'public' };

    if (kind === 'port') {
      const port = Number($('#rf-port').value);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        fail('Enter a port between 1 and 65535.');
        $('#rf-port').focus();
        return;
      }
      body.port = port;
    } else if (kind === 'docker') {
      let picked = null;
      try {
        picked = JSON.parse($('#rf-container').value || 'null');
      } catch {
        picked = null;
      }
      if (!Array.isArray(picked) || picked.length !== 2) {
        fail('Pick a container (and port) for this route.');
        $('#rf-container').focus();
        return;
      }
      body.containerName = picked[0];
      body.containerPort = picked[1];
    } else {
      const id = $('#rf-server').value;
      const srv = (state.overview?.inventory?.servers || []).find((s) => s.id === id);
      if (!srv) { fail('Pick a coordinator server for this route.'); $('#rf-server').focus(); return; }
      body.project = srv.project;
      body.serverName = srv.name;
    }

    const title = $('#rf-title').value.trim();
    if (title) body.title = title;

    if (body.auth === 'public'
      && !window.confirm(`Create https://${slug}.${domain} as a PUBLIC route?\n\nAnyone on the internet will reach it without signing in.`)) {
      return;
    }

    const btn = $('#rf-submit');
    btn.disabled = true;
    const oldText = btn.textContent;
    btn.textContent = 'Creating…';
    try {
      await api('/api/routes', { method: 'POST', body });
      resetRouteForm();
      announce(`Route ${slug}.${domain} created`);
      await refreshOverview({ force: true, fresh: true });
      const createdRow = await waitForCreatedRouteRow(slug);
      closeRouteDialog(createdRow || $('#route-add'));
      requestCreatedRouteFocus(slug);
    } catch (err) {
      if (err.status !== 401) {
        if (isEdgePublicationError(err)) {
          renderLocalPublicationError(errEl, err, {
            onActivated: async () => {
              resetRouteForm();
              announce(`Route ${slug}.${domain} created`);
              await refreshOverview({ force: true, fresh: true });
              const createdRow = await waitForCreatedRouteRow(slug);
              closeRouteDialog(createdRow || $('#route-add'));
              requestCreatedRouteFocus(slug);
            },
          });
        } else {
          fail(err.message);
          showBanner(err, () => $('#route-form').requestSubmit());
        }
      }
    } finally {
      btn.disabled = false;
      btn.textContent = oldText;
    }
  }

  // ---------------------------------------------------------------- archived lifecycle collections

  function archivedParentId(row) {
    if (row?.project_id) return String(row.project_id);
    if (typeof row?.parent === 'string') return row.parent;
    if (row?.parent?.target_id) return String(row.parent.target_id);
    if (row?.parent_id) return String(row.parent_id);
    return null;
  }

  function archiveDisplayName(row) {
    return row?.display_name || row?.name || `Archived ${lifecycleKindLabel(row?.target_kind).toLowerCase()}`;
  }

  function archivedGroups(page) {
    const all = state.archives || [];
    const groups = [];
    if (page === 'projects') {
      const projects = all.filter((row) => row?.target_kind === 'project');
      const worktrees = all.filter(
        (row) => row?.target_kind === 'worktree' && row?.removable === true,
      );
      for (const project of projects) {
        groups.push({
          key: `archive-project:${project.target_id}`,
          name: archiveDisplayName(project),
          entries: [project, ...worktrees.filter((row) => archivedParentId(row) === String(project.target_id))],
        });
      }
    } else {
      const kind = page === 'servers' ? 'server' : 'container';
      const byParent = new Map();
      for (const row of all.filter((item) => item?.target_kind === kind)) {
        const parent = archivedParentId(row) || 'unassigned';
        if (!byParent.has(parent)) {
          byParent.set(parent, {
            key: `archive-${page}:${parent}`,
            name: row.project_display_name || row.project_name || row.parent?.display_name
              || (parent === 'unassigned' ? 'Archived resources' : 'Archived project resources'),
            entries: [],
          });
        }
        byParent.get(parent).entries.push(row);
      }
      groups.push(...byParent.values());
    }
    for (const group of groups) {
      group.entries.sort((a, b) => archiveDisplayName(a).localeCompare(archiveDisplayName(b))
        || String(a.target_id).localeCompare(String(b.target_id)));
    }
    groups.sort((a, b) => String(a.name).localeCompare(String(b.name))
      || String(a.key).localeCompare(String(b.key)));
    return groups;
  }

  function archivedResourceRow(page, row) {
    const name = archiveDisplayName(row);
    const target = lifecycleTarget(row.target_kind, row.target_id, name, page, {
      parentId: archivedParentId(row),
    });
    const archivedAt = row.archived_at ? fmtWhen(row.archived_at) : 'Archived';
    const actor = row.actor ? ` · by ${row.actor}` : '';
    const reason = row.reason ? ` · ${row.reason}` : '';
    const effects = lifecycleList(row.effects);
    const retained = lifecycleList(row.retained);
    const details = `${archivedAt}${actor}${reason}`;
    return h('div', {
      class: 'archive-row', tabindex: '-1',
      'data-fk': `archive-row:${row.target_kind}:${row.target_id}`,
      'data-lifecycle-target': `${row.target_kind}:${row.target_id}`,
    },
      h('div', { class: 'archive-main' },
        h('span', { class: 'archive-name' },
          h('span', { class: `kind-tag ${row.target_kind === 'container' ? 'k-dock' : row.target_kind === 'server' ? 'k-srv' : ''}` },
            lifecycleKindLabel(row.target_kind)),
          h('strong', null, name),
          h('span', { class: 'badge dim static-badge' },
            h('span', { class: 'dot', 'aria-hidden': 'true' }), row.status || 'archived')),
        h('span', { class: 'archive-detail' }, details),
        effects.length ? h('span', { class: 'archive-detail' }, `Effects: ${effects.join('; ')}`) : null,
        retained.length ? h('span', { class: 'archive-detail' }, `Retained: ${retained.join('; ')}`) : null),
      h('span', { class: 'archive-actions' },
        row.restorable === true ? h('button', {
          class: 'btn small act-start', type: 'button',
          'data-fk': `restore:${row.target_kind}:${row.target_id}`,
          title: 'Clear the lifecycle fence; this does not start the resource',
          onclick: (event) => openLifecycleDialog('restore', target, event.currentTarget),
        }, icon('refresh'), 'Restore') : null,
        row.removable === true ? h('button', {
          class: 'btn small lifecycle-danger', type: 'button',
          'data-fk': `purge:${row.target_kind}:${row.target_id}`,
          title: 'Review permanent removal of this exact archived target',
          onclick: (event) => openLifecycleDialog('purge', target, event.currentTarget),
        }, icon('trash'), 'Remove permanently') : null));
  }

  function archivedGroupBlock(page, group) {
    const expandedSet = ui.archiveGroupsExpanded[page];
    const focus = ui.lifecycleFocus;
    if (
      focus?.view === 'archived'
      && focus.page === page
      && group.entries.some((row) => row.target_kind === focus.target_kind && row.target_id === focus.target_id)
    ) {
      expandedSet.clear();
      expandedSet.add(group.key);
    }
    const expanded = expandedSet.has(group.key);
    const panelId = `archive-group-${page}-${encodeURIComponent(group.key)}`;
    const toggle = h('button', {
      class: 'server-project-toggle', type: 'button',
      'data-fk': `archive-group:${page}:${group.key}`,
      'aria-expanded': String(expanded),
      'aria-controls': panelId,
      'aria-label': `${expanded ? 'Collapse' : 'Expand'} ${group.name}, ${group.entries.length} archived item${sfx(group.entries.length)}`,
      onclick: () => {
        setExclusiveExpansion(expandedSet, group.key);
        ui.resourcePages[page] = 0;
        bump();
        renderAll(true);
      },
    },
      h('span', { class: `chev${expanded ? ' open' : ''}`, 'aria-hidden': 'true' }, icon('chevron')),
      h('strong', { class: 'proj-name' }, group.name),
      h('span', { class: 'meta-passive server-group-count' },
        `${group.entries.length} archived item${sfx(group.entries.length)}`));

    const children = [];
    if (expanded) {
      let requestedPage = ui.resourcePages[page];
      const focusIndex = focus?.view === 'archived' && focus.page === page
        ? group.entries.findIndex(
            (row) => row.target_kind === focus.target_kind && row.target_id === focus.target_id,
          )
        : -1;
      if (focusIndex >= 0) requestedPage = Math.floor(focusIndex / RESOURCE_PAGE_SIZE);
      const paged = pageSlice(group.entries, requestedPage);
      ui.resourcePages[page] = paged.page;
      children.push(...paged.items.map((row) => archivedResourceRow(page, row)));
      const pager = resourcePager(page, 'Archived resources', paged);
      if (pager) children.push(pager);
    }
    return h('div', { class: 'server-project-block' },
      h('h3', { class: `proj-head${expanded ? ' is-open' : ''}` }, toggle),
      h('div', {
        class: 'archive-group-items', id: panelId,
        hidden: expanded ? undefined : true,
      }, children));
  }

  function buildArchivedCollection(page) {
    if (state.session?.accessAdmin !== true) {
      return [emptyState('Only configured Console owners can manage archived host resources.')];
    }
    if (!lifecycleAvailable()) {
      return [emptyState('Archive management is not activated on this Console.')];
    }
    const inventoryError = authoritativeInventoryErrorPanel(state.overview);
    if (inventoryError) return [inventoryError];
    if (!state.archives) {
      return [
        h('div', { class: 'skel', 'aria-hidden': 'true' }),
        h('div', { class: 'skel', 'aria-hidden': 'true' }),
      ];
    }
    const groups = archivedGroups(page);
    if (!groups.length) {
      return [emptyState(`No archived ${page === 'docker' ? 'containers' : page} yet.`)];
    }
    return [
      h('p', { class: 'archive-note' },
        'Archived resources are stopped and fenced. Restore clears the fence but never starts anything.'),
      ...groups.map((group) => archivedGroupBlock(page, group)),
    ];
  }

  // ---------------------------------------------------------------- servers

  function serverStatusMeta(s) {
    if (s?.supervision?.breaker?.state === 'tripped' || s?.supervision?.state === 'tripped') {
      return { css: 'err', label: 'crash loop stopped' };
    }
    const cls = s.health?.classification || s.status || 'unknown';
    switch (cls) {
      case 'healthy': return { css: 'ok', label: 'running' };
      case 'starting': return { css: 'warn', label: 'starting' };
      case 'unhealthy': return { css: 'err', label: 'unhealthy' };
      case 'wrong-listener': return { css: 'err', label: 'wrong listener' };
      case 'stopped': return { css: 'dim', label: 'stopped' };
      default:
        if (s.status === 'running') return { css: 'ok', label: 'running' };
        if (s.status === 'stopped') return { css: 'dim', label: 'stopped' };
        return { css: 'warn', label: String(cls) };
    }
  }

  function workerDurationLabel(seconds) {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value <= 0) return 'the configured window';
    if (value % 3600 === 0) {
      const hours = value / 3600;
      return `${hours} hour${hours === 1 ? '' : 's'}`;
    }
    if (value % 60 === 0) {
      const minutes = value / 60;
      return `${minutes} minute${minutes === 1 ? '' : 's'}`;
    }
    return `${value} second${value === 1 ? '' : 's'}`;
  }

  function workerCrashLoopMessage(supervision) {
    const breaker = supervision?.breaker || {};
    const count = Number(breaker.crash_count_in_window) || 0;
    return `Crash loop stopped — ${count} crash${count === 1 ? '' : 'es'} in ${workerDurationLabel(breaker.window_seconds)}`;
  }

  function workerActionBody(server, action, options = {}) {
    const body = { id: server.id, action };
    if (Object.hasOwn(options, 'keepAlive')) body.keep_alive = options.keepAlive;
    if (Object.hasOwn(options, 'rearmCrashLoop')) {
      body.rearm_crash_loop = options.rearmCrashLoop;
    }
    return body;
  }

  function runWorkerAction(server, action, options = {}) {
    return runAction(
      `server:${server.id}`,
      () => api('/api/workers/action', {
        method: 'POST',
        body: workerActionBody(server, action, options),
      }),
      {
        ...(options.confirmText ? { confirmText: options.confirmText } : {}),
        inventoryTargets: [{ target_kind: 'server', target_id: server.id }],
      },
    );
  }

  function workerControlButtons(server, busy, prefix = 'srv') {
    const supervision = server.supervision;
    const tripped = supervision?.breaker?.state === 'tripped' || supervision?.state === 'tripped';
    const stopped = !tripped && (
      supervision?.desired_state === 'stopped'
      || server.status === 'stopped'
      || supervision?.state === 'stopped'
    );
    const inventoryProblem = inventoryMutationProblemOf(state.overview, {
      target_kind: 'server', target_id: server.id,
    });
    const button = (action, label, iconName, options = {}) => h('button', {
      class: `btn small act-${action}${busy ? ' is-busy' : ''}`, type: 'button',
      'data-fk': `${prefix}-worker-${action}:${server.id}`,
      disabled: (busy || options.disabled || inventoryProblem) || undefined,
      title: inventoryProblem
        ? `${label} is disabled only for this worker until its ownership problem is resolved`
        : (options.title || `${label} ${server.name}`),
      onclick: () => runWorkerAction(server, action, options),
    }, icon(iconName), busy ? 'Working…' : label);

    if (tripped) {
      return [button('start', 'Start and re-arm', 'play', {
        keepAlive: supervision.keep_alive === true,
        rearmCrashLoop: true,
        title: `Explicitly re-arm the crash breaker and start ${server.name}`,
      })];
    }
    if (stopped) {
      return [button('start', 'Start', 'play', {
        keepAlive: supervision.keep_alive === true,
        rearmCrashLoop: false,
        title: `Start ${server.name}${supervision.keep_alive ? ' and keep it alive' : ''}`,
      })];
    }
    return [
      button('restart', 'Restart', 'refresh', {
        keepAlive: supervision.keep_alive === true,
        rearmCrashLoop: false,
        title: `Restart ${server.name}`,
      }),
      button('stop', 'Stop', 'stop', {
        confirmText: `Stop worker ${server.name}?\n\nThis sets its desired state to stopped. It will not restart until explicitly started.`,
        title: `Stop ${server.name} and set desired state to stopped`,
      }),
    ];
  }

  function treeWorkerActionSlots(server, busy) {
    const supervision = server.supervision || {};
    const tripped = supervision.breaker?.state === 'tripped'
      || supervision.state === 'tripped';
    const stopped = !tripped && (
      supervision.desired_state === 'stopped'
      || server.status === 'stopped'
      || supervision.state === 'stopped'
    );
    const options = (action) => ({
      keepAlive: supervision.keep_alive === true,
      rearmCrashLoop: action === 'start' && tripped,
      ...(action === 'stop' ? {
        confirmText: `Stop worker ${server.name}?\n\nThis sets its desired state to stopped. It will not restart until explicitly started.`,
      } : {}),
    });
    const inventoryProblem = inventoryMutationProblemOf(state.overview, {
      target_kind: 'server', target_id: server.id,
    });
    const slot = (action, label, iconName, disabled, title) => ({
      fk: `tree-worker-${action}:${server.id}`,
      label,
      icon: iconName,
      busy,
      disabled: !!inventoryProblem || disabled,
      title: inventoryProblem
        ? `${label} is disabled only for this worker until its ownership problem is resolved`
        : title,
      onclick: () => runWorkerAction(server, action, options(action)),
    });
    return treeActionSlots({
      start: slot(
        'start',
        tripped ? 'Start and re-arm' : 'Start',
        'play',
        !tripped && !stopped,
        tripped
          ? `Explicitly re-arm the crash breaker and start ${server.name}`
          : (stopped ? `Start ${server.name}` : `${server.name} is already running`),
      ),
      restart: slot(
        'restart',
        'Restart',
        'refresh',
        tripped || stopped,
        tripped
          ? 'Re-arm the crash breaker with Start'
          : (stopped ? 'Worker is stopped — use Start' : `Restart ${server.name}`),
      ),
      stop: slot(
        'stop',
        'Stop',
        'stop',
        tripped || stopped,
        tripped
          ? 'Worker is already stopped by its crash breaker'
          : (stopped ? 'Worker is already stopped' : `Stop ${server.name} and set desired state to stopped`),
      ),
    });
  }

  function buildServers(o) {
    if (!o.inventory) return [degradedPanel(o)];
    const inventoryError = authoritativeInventoryErrorPanel(o);
    if (inventoryError) return [inventoryError];
    const inventoryDiagnostics = authoritativeInventoryDiagnosticPanel(o);
    const hidden = hiddenSet('servers');
    const hiddenDocker = hiddenSet('docker');
    const focus = ui.lifecycleFocus?.view === 'active' && ui.lifecycleFocus.page === 'servers'
      ? ui.lifecycleFocus : null;
    if (focus) ui.reveal.add('servers');
    const revealing = ui.reveal.has('servers');
    const rank = (s) => (s.status === 'running' ? 0 : s.status === 'stopped' ? 2 : 1);
    let total = 0;
    let hiddenCount = 0;
    const groups = [];

    const out = [
      inventoryDiagnostics,
      h('div', { class: 'grid-head srv-grid', 'aria-hidden': 'true' },
        h('span', null, ''), h('span', null, 'Server'), h('span', null, 'Port'),
        h('span', null, 'CPU / Mem'), h('span', null, 'Status'), h('span', null, ''),
        h('span', null, 'Actions')),
    ];

    for (const group of projectGroupsOf(o)) {
      const servers = group.members.servers.slice().sort((a, b) => rank(a) - rank(b) || String(a.name).localeCompare(String(b.name)));
      // Docker-hosted web servers belong in this list too: any container
      // serving a published (non-database) port, plus routed stopped ones.
      const webContainers = group.members.containers
        .filter((c) => isWebServerContainer(o, group, c))
        .sort((a, b) => (isContainerRunning(b) ? 1 : 0) - (isContainerRunning(a) ? 1 : 0)
          || String(a.name).localeCompare(String(b.name)));
      if (!servers.length && !webContainers.length) continue;
      total += servers.length + webContainers.length;
      const running = servers.filter(isServerRunning).length
        + webContainers.filter(isContainerRunning).length;
      const memberCount = servers.length + webContainers.length;
      const extraText = `${running} of ${memberCount} running`;
      const entries = [];
      for (const s of servers) {
        const isHidden = hidden.has(s.key);
        if (isHidden) hiddenCount += 1;
        if (isHidden && !revealing) continue;
        entries.push({ group, extraText, kind: 'server', item: s, isHidden });
      }
      for (const c of webContainers) {
        const isHidden = hiddenDocker.has(c.name);
        if (isHidden) hiddenCount += 1;
        if (isHidden && !revealing) continue;
        entries.push({ group, extraText, kind: 'docker', item: c, isHidden });
      }
      groups.push({ group, extraText, memberCount, entries });
    }

    if (focus) {
      for (const entry of groups) {
        const index = entry.entries.findIndex((member) => (
          member.kind === 'server'
            ? lifecycleIdentityMatches(focus, 'server', member.item.id)
            : lifecycleIdentityMatches(focus, 'container', member.item.host_resource_id)
        ));
        if (index < 0) continue;
        ui.serverGroupsExpanded.clear();
        ui.serverGroupsExpanded.add(entry.group.key);
        ui.resourcePages.servers = Math.floor(index / RESOURCE_PAGE_SIZE);
        break;
      }
    }

    if (total === 0) {
      return [inventoryDiagnostics,
        emptyState('No dev servers registered with the coordinator yet — start one with "server start" and it appears here.')].filter(Boolean);
    }
    for (const entry of groups) out.push(serverProjectBlock(o, entry));
    const toggle = revealToggle('servers', hiddenCount);
    if (toggle) out.push(toggle);
    return out;
  }

  // All project headers stay visible so the collection remains scannable.
  // Only the explicitly opened project's bounded member page is mounted.
  function serverProjectBlock(o, entry) {
    const expanded = ui.serverGroupsExpanded.has(entry.group.key);
    const panelId = `srv-group-panel-${encodeURIComponent(entry.group.key)}`;
    const usage = entry.group.row
      ? h('span', { class: 'proj-usage mono' },
          h('span', { class: 'u-cpu' }, fmtCpu(entry.group.row.cpu_percent)),
          ' · ',
          h('span', { class: 'u-mem' }, fmtBytes(entry.group.row.memory_bytes || 0)))
      : null;
    const usageLabel = entry.group.row
      ? `, CPU ${fmtCpu(entry.group.row.cpu_percent)}, memory ${fmtBytes(entry.group.row.memory_bytes || 0)}`
      : '';
    const toggle = h('button', {
      class: 'server-project-toggle', type: 'button',
      'data-fk': `srv-group:${entry.group.key}`,
      'aria-expanded': String(expanded),
      'aria-controls': panelId,
      'aria-label': `${expanded ? 'Collapse' : 'Expand'} ${entry.group.name}, ${entry.extraText}${usageLabel}`,
      title: expanded ? 'Collapse resource group' : 'Expand resource group',
      onclick: () => {
        setExclusiveExpansion(ui.serverGroupsExpanded, entry.group.key);
        ui.resourcePages.servers = 0;
        bump();
        renderAll(true);
      },
    },
      h('span', { class: `chev${expanded ? ' open' : ''}`, 'aria-hidden': 'true' }, icon('chevron')),
      h('strong', { class: 'proj-name' }, entry.group.name),
      h('span', { class: 'meta-passive server-group-count' }, entry.extraText),
      entry.group.metricsKey ? sparkline(metricsEntity(entry.group.metricsKey)) : null,
      usage);

    const children = [];
    if (expanded) {
      if (entry.entries.length) {
        const paged = pageSlice(entry.entries, ui.resourcePages.servers);
        ui.resourcePages.servers = paged.page;
        for (const member of paged.items) {
          children.push(member.kind === 'server'
            ? serverItem(o, member.item, member.isHidden)
            : dockerServerItem(o, member.item, member.isHidden));
        }
        const pager = resourcePager('servers', 'Project servers', paged);
        if (pager) children.push(pager);
      } else if (entry.memberCount > 0) {
        children.push(h('p', { class: 'inline-note' },
          'All servers in this resource group are hidden. Use the control below to reveal them.'));
      }
    }

    return h('div', { class: 'server-project-block' },
      h('h3', { class: `proj-head${expanded ? ' is-open' : ''}`, title: entry.group.project || '' }, toggle),
      h('div', {
        class: 'server-group-items', id: panelId,
        hidden: expanded ? undefined : true,
      }, children));
  }

  // A docker-hosted web server rendered as a first-class Servers row: same
  // columns, container-appropriate status/actions, and the shared subdomain
  // control saving through /api/docker/subdomain.
  function dockerServerItem(o, c, hiddenRow = false) {
    const name = c.name;
    const running = isContainerRunning(c);
    const open = ui.dockerOpen.has(name);
    const busy = ui.busy.has(`docker:${name}`);
    const meta = containerStatusMeta(c);
    const panelId = `srv-dock-panel-${name}`;
    const ownership = containerOwnershipState(c);
    const inventoryProblem = inventoryMutationProblemOf(o, {
      target_kind: 'container', target_id: c.host_resource_id,
    });
    const archiveTarget = ownership.genericLifecycle
      ? lifecycleTarget('container', c.host_resource_id, name, 'docker', {
          projectId: c.repo_id || null,
        })
      : null;

    const chev = h('button', {
      class: `chev${open ? ' open' : ''}`, type: 'button',
      'data-fk': `srv-dock-x:${name}`,
      'data-log-capable': 'true',
      'aria-expanded': String(open),
      'aria-controls': panelId,
      'aria-label': `${open ? 'Collapse' : 'Expand'} logs for ${name}`,
      title: open ? 'Collapse logs' : 'Expand container logs',
      onclick: () => toggleDocker(c),
    }, icon('chevron'));

    const badgeKey = `srv-dock-badge:${name}`;
    const badge = h('button', {
      class: `badge ${meta.css}`, type: 'button',
      'data-fk': badgeKey, 'aria-haspopup': 'dialog',
      'aria-expanded': popover.key === badgeKey ? 'true' : 'false',
      'aria-label': `Status of ${name}: ${meta.label} — show container details`,
      title: 'Show container details',
      onclick: (e) => popover.toggle(badgeKey, e.currentTarget, () => (
        h('div', null,
          popHead(name),
          kv('Status', c.status || '—', { mono: true }),
          kv('Image', c.image || '—', { mono: true }),
          kv('Ports', c.ports || '—', { mono: true }),
          kv('Project', c.project || c.compose_project || '—', { mono: true }),
          c.stats ? kv('CPU now', fmtCpu(c.stats.cpu_percent)) : null,
          c.stats ? kv('Memory now', fmtBytes(Number(c.stats.memory_usage_bytes) || 0)) : null,
          h('p', { class: 'pop-hint' }, ownership.ephemeral
            ? 'This is a broker-owned ephemeral container. Use its TTL-aware coordinator lifecycle.'
            : (ownership.verified
                ? 'This server runs as a Docker container — actions start, stop and restart the container itself.'
                : 'This container is read-only until the coordinator proves one repository owner.')))
      )),
    }, h('span', { class: 'dot', 'aria-hidden': 'true' }), meta.label);

    const act = (action, label, iconName, confirmText) => h('button', {
      class: `btn small ${ACTION_CLS[action]}${busy ? ' is-busy' : ''}`, type: 'button',
      'data-fk': `srv-dock-${action}:${name}`,
      disabled: (busy || inventoryProblem) || undefined,
      title: inventoryProblem
        ? `${label} is disabled only for this container until its ownership problem is resolved`
        : `${label} container ${name}`,
      onclick: () => runAction(`docker:${name}`,
        () => api('/api/docker/action', { method: 'POST', body: { name, action } }),
        {
          ...(confirmText ? { confirmText } : {}),
          inventoryTargets: [{ target_kind: 'container', target_id: c.host_resource_id }],
        }),
    }, icon(iconName), busy ? 'Working…' : label);

    const ports = publishedContainerPorts(c.ports);
    const portCell = ports.length
      ? ports.map((p) => `:${p.hostPort}`).join(' ')
      : '—';

    const row = h('div', {
      class: `row srv-grid expandable${hiddenRow ? ' is-hidden' : ''}${ownership.verified ? '' : ' ownership-unverified'}`,
      tabindex: '-1',
      'data-ownership': ownership.ephemeral
        ? 'coordinator-ephemeral' : (ownership.verified ? 'verified' : 'unverified'),
      'data-lifecycle-target': archiveTarget
        ? `${archiveTarget.target_kind}:${archiveTarget.target_id}` : null,
      onclick: (e) => {
        if (e.target.closest('button, a, input, select')) return;
        toggleDocker(c);
      },
    },
      chev,
      h('span', { class: 'cell c-primary', 'data-label': 'Server' },
        h('span', { class: 'srv-name' },
          h('strong', null, name),
          ' ',
          h('span', { class: 'kind-tag k-dock' }, 'docker'),
          ' ',
          h('span', { class: 'dim', title: c.project || '' }, projectTail(c.project || c.compose_project))),
        ownership.genericLifecycle ? dockerSubdomainControl(o, c, 'srv') : null,
        unverifiedOwnershipNote(ownership)),
      h('span', { class: 'cell mono srv-port', 'data-label': 'Port' }, portCell),
      usageCellNode({
        key: `dock:${name}`,
        title: name,
        cpu: c.stats?.cpu_percent ?? null,
        mem: c.stats?.memory_usage_bytes ?? null,
        running: running && !!c.stats,
        scope: 'srv',
      }),
      h('span', { class: 'cell srv-status', 'data-label': 'Status' }, badge),
      h('span', { class: 'srv-warning', 'aria-hidden': 'true' }),
      h('span', { class: 'cell actions srv-actions' },
        ownership.genericLifecycle && running
          ? [act('restart', 'Restart', 'refresh'),
             act('stop', 'Stop', 'stop', `Stop container ${name}?\n\nAnything depending on it (like a database) loses its service.`)]
          : (ownership.genericLifecycle
              ? act('start', 'Start', 'play')
              : (running
                  ? [blockedContainerAction(`srv-dock-restart:${name}`, 'Restart', 'refresh', { ephemeral: ownership.ephemeral }),
                     blockedContainerAction(`srv-dock-stop:${name}`, 'Stop', 'stop', { ephemeral: ownership.ephemeral })]
                  : blockedContainerAction(`srv-dock-start:${name}`, 'Start', 'play', { ephemeral: ownership.ephemeral }))),
        hiddenRow
          ? unhideButton('docker', name, name)
          : (!isContainerActive(c) ? hideButton('docker', name, name) : ghostIconSlot()),
        ownership.genericLifecycle
          ? archiveButton(archiveTarget, { compact: true })
          : (lifecycleAvailable()
              ? blockedContainerAction(`blocked-archive:${name}`, 'Archive', 'archive', {
                  compact: true, ephemeral: ownership.ephemeral,
                })
              : ghostIconSlot())));

    return h('div', { class: 'item' }, row, open ? dockerPanel(c, panelId) : null);
  }

  function serverHasAuthoritativeLog(server) {
    return typeof server?.log_path === 'string' && server.log_path.trim().length > 0;
  }

  function serverSupportsGenericLifecycle(server) {
    // Temporary services are owned by their bounded runtime session. Finish,
    // expiry, and the TTL reaper provide their exact cleanup path; exposing
    // generic Archive would promise an authority the broker intentionally
    // never grants to this resource class.
    return String(server?.role || '').toLowerCase() !== 'temporary';
  }

  function serverItem(o, s, hiddenRow = false) {
    const id = s.id;
    const open = ui.expanded.has(id);
    const hasAuthoritativeLog = serverHasAuthoritativeLog(s);
    const busy = ui.busy.has(`server:${id}`);
    const inventoryProblem = inventoryMutationProblemOf(o, {
      target_kind: 'server', target_id: id,
    });
    const meta = serverStatusMeta(s);
    const panelId = `srv-panel-${id}`;
    const archiveTarget = lifecycleTarget('server', id, s.name || 'Unnamed server', 'servers');

    const chev = h('button', {
      class: `chev${open ? ' open' : ''}`, type: 'button',
      'data-fk': `srv-x:${id}`,
      'data-log-capable': hasAuthoritativeLog ? 'true' : null,
      'aria-expanded': String(open),
      'aria-controls': panelId,
      'aria-label': `${open ? 'Collapse' : 'Expand'} details for ${s.name}`,
      title: open
        ? 'Collapse details'
        : (hasAuthoritativeLog ? 'Expand details and logs' : 'Expand details'),
      onclick: () => toggleServer(s),
    }, icon('chevron'));

    const badgeKey = `srv-badge:${id}`;
    const badge = h('button', {
      class: `badge ${meta.css}`, type: 'button',
      'data-fk': badgeKey, 'aria-haspopup': 'dialog',
      'aria-expanded': popover.key === badgeKey ? 'true' : 'false',
      'aria-label': `Status of ${s.name}: ${meta.label} — show health details`,
      title: 'Show health details',
      onclick: (e) => popover.toggle(badgeKey, e.currentTarget, () => serverPop(s, meta)),
    }, h('span', { class: 'dot', 'aria-hidden': 'true' }), meta.label);

    const warnFlag = s.url_is_current === false
      ? h('span', {
          class: 'warnflag', role: 'img',
          'aria-label': 'Warning: recorded URL may be stale — another process may own this port',
          title: 'Recorded URL may be stale — another process may own this port',
        }, icon('warn'))
      : h('span', { 'aria-hidden': 'true' });

    const stoppable = ['running', 'starting', 'unhealthy'].includes(s.status);
    const restartable = stoppable || s.status === 'stopped';
    const supervised = !!s.supervision;
    const genericLifecycle = serverSupportsGenericLifecycle(s);
    const actions = h('span', { class: 'cell actions srv-actions' },
      supervised ? workerControlButtons(s, busy) : h('button', {
        class: `btn small act-restart${busy ? ' is-busy' : ''}`, type: 'button',
        'data-fk': `srv-restart:${id}`,
        disabled: (busy || inventoryProblem || s.missing_command || !restartable) || undefined,
        title: inventoryProblem
          ? 'Restart is disabled only for this server until its ownership problem is resolved'
          : !restartable
          ? 'No observed server instance is available to restart'
          : s.missing_command
          ? 'Registered without a start command — cannot be restarted from here'
          : `Restart ${s.name} on the same port`,
        onclick: () => runAction(`server:${id}`,
          () => api('/api/servers/action', { method: 'POST', body: { id, action: 'restart' } }),
          { inventoryTargets: [{ target_kind: 'server', target_id: id }] }),
      }, icon('refresh'), busy ? 'Working…' : 'Restart'),
      supervised ? null : h('button', {
        class: `btn small act-stop${busy ? ' is-busy' : ''}`, type: 'button',
        'data-fk': `srv-stop:${id}`,
        disabled: (busy || inventoryProblem || !stoppable) || undefined,
        title: inventoryProblem
          ? 'Stop is disabled only for this server until its ownership problem is resolved'
          : (stoppable ? `Stop ${s.name}` : 'Server is not running'),
        onclick: () => runAction(`server:${id}`,
          () => api('/api/servers/action', { method: 'POST', body: { id, action: 'stop' } }),
          { inventoryTargets: [{ target_kind: 'server', target_id: id }] }),
      }, icon('stop'), busy ? 'Working…' : 'Stop'),
      hiddenRow
        ? unhideButton('servers', s.key, s.name || 'server')
        : (s.status === 'stopped' ? hideButton('servers', s.key, s.name || 'server') : ghostIconSlot()),
      supervised
        ? workerRemoveButton(s, { compact: true })
        : (genericLifecycle
            ? archiveButton(archiveTarget, { compact: true })
            : ghostIconSlot()));

    const row = h('div', {
      class: `row srv-grid expandable${hiddenRow ? ' is-hidden' : ''}`,
      tabindex: '-1',
      'data-lifecycle-target': genericLifecycle
        ? `${archiveTarget.target_kind}:${archiveTarget.target_id}`
        : null,
      onclick: (e) => {
        if (e.target.closest('button, a, input, select')) return;
        toggleServer(s);
      },
    },
      chev,
      h('span', { class: 'cell c-primary', 'data-label': 'Server' },
        h('span', { class: 'srv-name' },
          h('strong', null, s.name || '—'),
          ' ',
          h('span', { class: 'dim', title: s.project || '' }, projectTail(s.project))),
        subdomainControl(o, s)),
      h('span', { class: 'cell mono srv-port', 'data-label': 'Port' }, serverPortCell(o, s)),
      usageCellNode({
        key: `srv:${id}`,
        title: s.name || 'Server',
        cpu: s.process_usage?.cpu_percent ?? null,
        mem: s.process_usage?.memory_bytes ?? null,
        running: !!s.process_usage,
      }),
      h('span', { class: 'cell srv-status', 'data-label': 'Status' }, badge),
      h('span', { class: 'srv-warning' }, warnFlag),
      actions);

    return h('div', { class: 'item' }, row, open ? serverPanel(s, panelId) : null);
  }

  // The port cell only claims "pinned" when the pin actually points at the
  // record's port; a moved pin is flagged as taking effect on the next start.
  function serverPortCell(o, s) {
    if (s.port == null) return '—';
    const pin = (o.inventory?.port_assignments || []).find((a) => a.key === s.key);
    if (!pin) return `:${s.port}`;
    if (Number(pin.port) === Number(s.port)) {
      return h('span', {
        class: 'pinned-port',
        title: `Port ${s.port} is permanently pinned to this server — manage pins on the Port leases page`,
      }, `:${s.port}`);
    }
    return h('span', {
      class: 'pinned-port pin-moved',
      title: `Pinned to :${pin.port} — takes effect the next time this server starts`,
    }, `:${s.port} → :${pin.port}`);
  }

  // ---- per-server subdomain mapping -------------------------------------

  const normProj = (p) => {
    let v = String(p ?? '');
    while (v.length > 1 && v.endsWith('/')) v = v.slice(0, -1);
    return v;
  };

  // The route (if any) that publishes this coordinator server at a subdomain.
  function serverRouteFor(o, s) {
    const proj = normProj(s.project);
    return (o.routes || []).find(
      (r) => r.kind === 'server' && normProj(r.project) === proj && r.serverName === s.name,
    ) || null;
  }

  // Like slugProblem, but the server's own current slug is allowed (edit case).
  function subdomainSlugProblem(v, allowSlug) {
    if (!SLUG_RE.test(v)) return 'Use lowercase letters, digits and hyphens; start and end with a letter or digit.';
    const consoleLabel = state.overview?.console?.consoleHost?.split('.')[0];
    if (RESERVED_SLUGS.has(v) || v === consoleLabel) return `"${v}" is a reserved name.`;
    if (v !== allowSlug && (state.overview?.routes || []).some((r) => r.slug === v)) {
      return `"${v}" is already routed.`;
    }
    return null;
  }

  // (Saving goes through each spec's save() below — one endpoint per kind.)

  // Both server rows and docker-container rows carry the same subdomain
  // control; a spec abstracts what differs — where the route lives, which
  // endpoint saves it, and (docker only) the container-port choice.
  function subdomainSpecForServer(s) {
    return {
      key: `srv-sub:${s.id}`,
      busyKey: `subdomain:${s.id}`,
      name: s.name,
      routeOf: (ov) => serverRouteFor(ov, s),
      save: (slug, auth, opts) => runAction(`subdomain:${s.id}`,
        () => api('/api/servers/subdomain', { method: 'POST', body: { id: s.id, slug, auth } }),
        { ...opts, inventoryTargets: [{ target_kind: 'server', target_id: s.id }] }),
      portOptions: null,
    };
  }

  function subdomainSpecForDocker(c, scope) {
    return {
      key: `${scope}-dock-sub:${c.name}`,
      busyKey: `subdomain:dock:${c.name}`,
      name: c.name,
      routeOf: (ov) => dockerRouteFor(ov, c),
      save: (slug, auth, opts, port) => runAction(`subdomain:dock:${c.name}`,
        () => api('/api/docker/subdomain', {
          method: 'POST',
          body: { name: c.name, slug, auth, ...(slug && port ? { port } : {}) },
        }),
        { ...opts, inventoryTargets: [{ target_kind: 'container', target_id: c.host_resource_id }] }),
      portOptions: publishedContainerPorts(c.ports),
    };
  }

  // Compact row control: a linked subdomain (with copy + edit) or an assign button.
  function subdomainControl(o, s) {
    return subdomainControlFor(o, subdomainSpecForServer(s));
  }

  function dockerSubdomainControl(o, c, scope) {
    return subdomainControlFor(o, subdomainSpecForDocker(c, scope));
  }

  function subdomainControlFor(o, spec) {
    const domain = o.console?.domain || 'vr.ae';
    const route = spec.routeOf(o);
    const busy = ui.busy.has(spec.busyKey);
    const key = spec.key;
    const openEditor = (e) => popover.toggle(key, e.currentTarget, () => subdomainEditor(o, spec, spec.routeOf(o)));

    if (route) {
      const host = `${route.slug}.${domain}`;
      const url = route.url || `https://${host}`;
      const isPublic = route.auth === 'public';
      return h('span', { class: 'srv-sub' },
        h('span', { class: 'i-tag', 'aria-hidden': 'true' }, icon('link')),
        h('a', {
          class: 'sub-url', href: url, target: '_blank', rel: 'noopener noreferrer',
          title: `Open ${url} in a new tab`,
        }, host),
        h('span', {
          class: `sub-access ${isPublic ? 'pub' : 'auth'}`,
          title: isPublic ? 'Public — anyone can open it' : 'Google sign-in required',
        }, isPublic ? 'public' : 'login'),
        h('button', {
          class: 'iconbtn copybtn', type: 'button', 'data-fk': `${key}-copy`,
          'aria-label': `Copy ${url}`, title: 'Copy URL',
          onclick: (e) => copyText(url, e.currentTarget),
        }, icon('copy')),
        h('button', {
          class: 'linklike sub-edit', type: 'button', 'data-fk': key,
          'aria-haspopup': 'dialog', 'aria-expanded': popover.key === key ? 'true' : 'false',
          disabled: busy || undefined,
          'aria-label': `Change or remove the ${host} subdomain for ${spec.name}`,
          title: 'Change or remove subdomain',
          onclick: openEditor,
        }, icon('edit'), busy ? 'Saving…' : 'Edit'));
    }

    return h('button', {
      class: 'linklike assign-sub', type: 'button', 'data-fk': key,
      'aria-haspopup': 'dialog', 'aria-expanded': popover.key === key ? 'true' : 'false',
      disabled: busy || undefined,
      'aria-label': `Assign a subdomain to ${spec.name}`,
      title: `Publish ${spec.name} at a <name>.${domain} subdomain`,
      onclick: openEditor,
    }, icon('plus'), busy ? 'Saving…' : 'Assign subdomain');
  }

  // Popover editor for assigning / changing / removing a subdomain.
  function subdomainEditor(o, spec, route) {
    const domain = o.console?.domain || 'vr.ae';
    let access = route ? route.auth : 'google';

    const input = h('input', {
      type: 'text', class: 'sub-input', maxlength: '63', spellcheck: 'false',
      autocapitalize: 'none', autocomplete: 'off', 'aria-label': 'Subdomain name',
      placeholder: 'myapp', value: route ? route.slug : '',
    });
    const preview = h('p', { class: 'preview sub-preview', 'aria-live': 'polite' });
    const publicationError = h('div', { class: 'form-error', hidden: true });
    const save = h('button', { class: 'btn primary small', type: 'button' }, route ? 'Update' : 'Assign');

    const handlePublicationFailure = (error) => {
      if (!isEdgePublicationError(error)) return;
      renderLocalPublicationError(publicationError, error, {
        onActivated: async () => {
          popover.close();
          await refreshOverview({ force: true, fresh: true });
        },
      });
    };

    function currentProblem() {
      const v = input.value.trim();
      if (!v) return 'empty';
      return subdomainSlugProblem(v, route ? route.slug : null);
    }
    function refresh() {
      const v = input.value.trim();
      if (!v) {
        preview.className = 'preview sub-preview';
        preview.textContent = `Becomes https://<name>.${domain}`;
        save.disabled = true;
        return;
      }
      const problem = subdomainSlugProblem(v, route ? route.slug : null);
      if (problem) {
        preview.className = 'preview sub-preview bad';
        preview.textContent = problem;
        save.disabled = true;
      } else {
        preview.className = 'preview sub-preview ok';
        preview.textContent = `→ https://${v}.${domain}`;
        save.disabled = false;
      }
    }
    input.addEventListener('input', refresh);

    // Access choice (defaults to login-required, matching route-create).
    const mkAccess = (val, label, hint) => h('button', {
      class: `segopt-btn${access === val ? ' on' : ''}`, type: 'button',
      role: 'radio', 'aria-checked': String(access === val), title: hint,
      onclick: () => {
        access = val;
        for (const b of seg.children) {
          const on = b.dataset.val === val;
          b.classList.toggle('on', on);
          b.setAttribute('aria-checked', String(on));
        }
      },
      'data-val': val,
    }, label);
    const seg = h('div', { class: 'sub-seg', role: 'radiogroup', 'aria-label': 'Access level' },
      mkAccess('google', 'Login required', 'Only approved Google accounts can open it'),
      mkAccess('public', 'Public', 'Anyone on the internet can open it'));

    // Container-port choice (docker specs only): needed when the container
    // publishes several ports; otherwise it is picked automatically.
    let portSelect = null;
    let portNote = null;
    if (spec.portOptions) {
      const options = spec.portOptions.slice();
      const current = route?.containerPort;
      if (Number.isInteger(current) && !options.some((op) => op.containerPort === current)) {
        options.unshift({ containerPort: current, hostPort: null });
      }
      if (options.length > 1) {
        portSelect = h('select', { class: 'sub-input', 'aria-label': 'Container port to publish' },
          ...options.map((op) => h('option', {
            value: String(op.containerPort),
            selected: op.containerPort === (current ?? options[0].containerPort) || undefined,
          }, op.hostPort === null
            ? `HTTP container port ${op.containerPort} (not published right now)`
            : `HTTP container port ${op.containerPort} → host :${op.hostPort}`)));
      } else if (options.length === 1) {
        portNote = h('p', { class: 'pop-hint' },
          `Forwards HTTP to container port ${options[0].containerPort}`
          + (options[0].hostPort === null ? ' (not published right now).' : ` (host :${options[0].hostPort}).`));
      }
    }
    const chosenPort = () => {
      if (!spec.portOptions) return undefined;
      if (portSelect) return Number(portSelect.value);
      const only = spec.portOptions[0]?.containerPort ?? route?.containerPort;
      return Number.isInteger(only) ? only : undefined;
    };

    save.onclick = () => {
      const v = input.value.trim();
      if (currentProblem()) return;
      const makingPublic = access === 'public' && (!route || route.auth !== 'public');
      spec.save(v, access, {
        confirmText: makingPublic
          ? `Make https://${v}.${domain} public?\n\nAnyone on the internet will reach this dev server without signing in.`
          : undefined,
        onError: handlePublicationFailure,
      }, chosenPort());
    };

    const remove = route
      ? h('button', {
          class: 'btn small danger', type: 'button',
          'aria-label': `Remove the ${route.slug}.${domain} subdomain`, title: 'Remove subdomain (server keeps running)',
          onclick: () => spec.save('', access, {
            confirmText: `Remove https://${route.slug}.${domain}?\n\nThe dev server keeps running — only this public URL stops working.`,
            onError: handlePublicationFailure,
          }),
        }, icon('trash'), 'Remove')
      : null;

    refresh();
    return h('div', { class: 'sub-editor' },
      popHead(route ? `Subdomain · ${spec.name}` : `Assign subdomain · ${spec.name}`),
      h('label', { class: 'sub-lab' }, 'Subdomain'),
      input,
      preview,
      portSelect ? h('div', { class: 'sub-lab' }, 'Container port') : null,
      portSelect,
      portNote,
      spec.portOptions ? h('p', { class: 'pop-hint protocol-note' },
        "The Console terminates public HTTPS and forwards plain HTTP. Choose the app's HTTP listener, not its HTTPS/TLS listener.") : null,
      h('div', { class: 'sub-lab' }, 'Access'),
      seg,
      publicationError,
      h('div', { class: 'sub-actions' }, save, remove));
  }

  function serverPop(s, meta) {
    const check = s.health?.check;
    const checkText = check
      ? (check.ok ? `ok${check.status ? ` (HTTP ${check.status})` : ''}`
        : (check.error || check.reason || check.skipped || 'failing'))
      : '—';
    return h('div', null,
      popHead(s.name || 'Server'),
      kv('Health', `${meta.label} (${s.health?.classification || s.status || 'unknown'})`),
      s.process_usage ? kv('CPU now', fmtCpu(s.process_usage.cpu_percent)) : null,
      s.process_usage ? kv('Memory now', fmtBytes(Number(s.process_usage.memory_bytes) || 0)) : null,
      kv('PID', s.pid != null ? String(s.pid) : '—', { mono: true }),
      kv('URL', s.url || '—', { mono: true }),
      kv('Health check', checkText, { mono: true }),
      kv('Command', s.cmd || s.cmd_template || '—', { mono: true }),
      kv('Project', s.project || '—', { mono: true }),
      s.supervision ? kv('Keep alive', s.supervision.keep_alive ? 'On' : 'Off') : null,
      s.supervision ? kv('Desired state', s.supervision.desired_state || '—') : null,
      s.supervision ? kv('Supervisor', s.supervision.state || '—') : null,
      kv('Started', fmtWhen(s.created_at)),
      kv('Updated', fmtWhen(s.updated_at)),
      s.stopped_at ? kv('Stopped', fmtWhen(s.stopped_at)) : null,
      s.stopped_reason ? kv('Stop reason', s.stopped_reason) : null,
      s.url_is_current === false
        ? h('p', { class: 'pop-hint' }, 'Warning: the recorded URL may be stale — another process may be listening on this port.')
        : null,
      s.supervision?.breaker?.state === 'tripped'
        ? h('p', { class: 'pop-hint err' }, workerCrashLoopMessage(s.supervision))
        : null);
  }

  function toggleServer(server) {
    const id = server.id;
    if (ui.expanded.has(id)) {
      ui.expanded.delete(id);
    } else {
      ui.expanded.add(id);
      const cached = ui.logs.get(`srv:${id}`);
      if (serverHasAuthoritativeLog(server)
          && (!cached || (cached.text == null && !cached.loading))) {
        loadServerLogs(id);
      }
    }
    bump();
    renderAll(true);
  }

  function restoreAsyncActionFocus(focusKey) {
    if (!focusKey) return;
    const active = document.activeElement;
    // A loading render temporarily replaces the triggering button with its
    // disabled copy, which moves focus to <body>. Restore that exact logical
    // control when the request settles, but never steal focus if the user
    // moved elsewhere while the request was in flight.
    if (active && active !== document.body && active !== document.documentElement) return;
    document.querySelector(`[data-fk="${CSS.escape(focusKey)}"]`)
      ?.focus({ preventScroll: true });
  }

  async function loadServerLogs(id) {
    const key = `srv:${id}`;
    const refreshFocusKey = `srv-logs-refresh:${id}`;
    const restoreFocus = document.activeElement?.dataset?.fk === refreshFocusKey
      ? refreshFocusKey : null;
    ui.logs.set(key, { ...(ui.logs.get(key) || {}), loading: true, error: null });
    bump();
    renderAll(true);
    try {
      const resp = await api('/api/servers/logs', { method: 'POST', body: { id } });
      ui.logs.set(key, { loading: false, text: resp?.text ?? '', error: null, at: Date.now() });
    } catch (err) {
      if (err.status === 401) return;
      ui.logs.set(key, { loading: false, text: null, error: err.message, at: Date.now() });
    }
    bump();
    renderAll(true);
    restoreAsyncActionFocus(restoreFocus);
  }

  function workerSupervisionPanel(s) {
    const supervision = s.supervision;
    if (!supervision) return null;
    const busy = ui.busy.has(`server:${s.id}`);
    const tripped = supervision.breaker?.state === 'tripped' || supervision.state === 'tripped';
    const crashes = Array.isArray(supervision.recent_crashes) ? supervision.recent_crashes : [];
    const keepAlive = supervision.keep_alive === true;
    const policyHelp = keepAlive
      ? 'Starts with the coordinator supervisor and restarts after an unexpected crash.'
      : 'Automatic restart is off. Turning this off does not stop a worker that is already running.';
    return h('section', { class: `worker-supervision${tripped ? ' is-tripped' : ''}` },
      h('div', { class: 'worker-supervision-head' },
        h('div', null,
          h('h3', null, 'Worker supervision'),
          h('p', { class: 'meta-passive' }, policyHelp)),
        h('button', {
          class: 'switch', type: 'button', role: 'switch',
          'aria-checked': String(keepAlive),
          'aria-label': `Keep alive ${s.name}`,
          disabled: busy || undefined,
          title: keepAlive
            ? 'Turn off automatic restart; the current process keeps running'
            : 'Turn on desired-running supervision; starts this worker if stopped',
          onclick: () => runWorkerAction(s, 'start', {
            keepAlive: !keepAlive,
            rearmCrashLoop: false,
          }),
        }, h('span', { class: 'knob', 'aria-hidden': 'true' }),
        h('span', { class: 'sw-label' }, busy ? 'Updating…' : 'Keep alive'))),
      h('div', { class: 'worker-state-grid' },
        kv('Desired state', supervision.desired_state || '—'),
        kv('Supervisor', supervision.state || '—'),
        kv('Crash policy', `${supervision.breaker?.crash_limit ?? '—'} in ${workerDurationLabel(supervision.breaker?.window_seconds)}`)),
      tripped ? h('div', { class: 'worker-crash-loop', role: 'alert' },
        h('strong', null, workerCrashLoopMessage(supervision)),
        h('p', null, 'Automatic restart is permanently paused for this incident. Fix the cause, then explicitly start and re-arm the worker.'),
        h('div', { class: 'worker-actions' },
          workerControlButtons(s, busy, 'panel')))
        : null,
      crashes.length ? h('div', { class: 'worker-crash-history' },
        h('h4', null, 'Retained crash traces'),
        h('ul', null, crashes.map((attempt) => {
          const artifactId = attempt?.log?.artifact_id;
          const exit = attempt?.exit_code != null
            ? `exit ${attempt.exit_code}`
            : attempt?.exit_signal != null ? `signal ${attempt.exit_signal}` : 'exit unknown';
          return h('li', null,
            h('span', null,
              `${fmtWhen(attempt?.exited_at)} · ${exit}`,
              attempt?.classification ? ` · ${attempt.classification}` : ''),
            typeof artifactId === 'string' && artifactId
              ? h('a', {
                  href: `/api/runtime/artifacts/worker_attempt/${encodeURIComponent(artifactId)}`,
                  target: '_blank', rel: 'noopener',
                }, 'Open crash log')
              : h('span', { class: 'meta-passive' }, 'Crash log unavailable'));
        })))
        : null,
      h('div', { class: 'worker-actions' },
        tripped ? null : workerControlButtons(s, busy, 'panel'),
        workerRemoveButton(s)));
  }

  function serverPanel(s, panelId) {
    const key = `srv:${s.id}`;
    const lg = ui.logs.get(key);
    const hasAuthoritativeLog = serverHasAuthoritativeLog(s);
    return h('div', { class: 'panel', id: panelId },
      workerSupervisionPanel(s),
      h('div', { class: 'panel-meta' },
        kv('PID', s.pid != null ? String(s.pid) : '—', { mono: true }),
        kv('Working dir', s.cwd || '—', { mono: true }),
        kv('Command', s.cmd || s.cmd_template || '—', { mono: true }),
        kv('Log file', s.log_path || '—', { mono: true })),
      hasAuthoritativeLog
        ? h('div', { class: 'panel-toolbar' },
          h('span', { class: 'panel-title' }, 'Recent log'),
          lg?.at ? h('span', { class: 'meta-passive' }, `fetched ${fmtClock(lg.at)}`) : null,
          h('button', {
            class: 'btn small', type: 'button',
            'data-fk': `srv-logs-refresh:${s.id}`,
            disabled: lg?.loading || undefined,
            title: 'Fetch the latest 200 log lines',
            onclick: () => loadServerLogs(s.id),
          }, icon('refresh'), lg?.loading ? 'Loading…' : 'Refresh'))
        : h('p', { class: 'inline-note panel-log-unavailable' },
          'No authoritative log source is registered for this server.'),
      hasAuthoritativeLog ? logboxNode(key, lg) : null);
  }

  // Leading ISO timestamp or [bracketed] prefix rendered as passive metadata.
  const LOG_TS_RE = /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\[[^\]]{1,40}\])\s?/;

  function logboxNode(key, lg) {
    const box = h('div', {
      class: 'logbox', 'data-scrollkey': key, tabindex: '0',
      role: 'region', 'aria-label': 'Log output',
    });
    if (!lg || (lg.loading && lg.text == null)) {
      box.append(h('p', { class: 'log-empty' }, 'Loading log…'));
      return box;
    }
    if (lg.error) {
      box.append(h('p', { class: 'log-empty err' }, `Could not load logs: ${lg.error}`));
      return box;
    }
    const text = String(lg.text ?? '').replace(/\n+$/, '');
    if (!text) {
      box.append(h('p', { class: 'log-empty' }, 'Log is empty.'));
      return box;
    }
    const frag = document.createDocumentFragment();
    for (const line of text.split('\n').slice(-400)) {
      const m = line.match(LOG_TS_RE);
      const row = h('div', { class: 'logline' });
      if (m) {
        row.append(
          h('span', { class: 'log-ts' }, m[1]),
          h('span', { class: 'log-msg' }, line.slice(m[0].length)));
      } else {
        row.append(h('span', { class: 'log-msg' }, line));
      }
      frag.append(row);
    }
    box.append(frag);
    return box;
  }

  // ---------------------------------------------------------------- docker

  function buildDocker(o) {
    if (!o.inventory) return [degradedPanel(o)];
    const inventoryError = authoritativeInventoryErrorPanel(o);
    if (inventoryError) return [inventoryError];
    const inventoryDiagnostics = authoritativeInventoryDiagnosticPanel(o);
    const docker = o.inventory.docker;
    if (!docker || docker.available === false) {
      return [h('div', { class: 'degraded' },
        icon('warn'),
        h('div', null,
          h('p', { class: 'deg-title' }, 'Docker unavailable'),
          h('p', { class: 'deg-msg' }, docker?.error ? String(docker.error) : 'Docker did not respond on this machine.')))];
    }
    const hidden = hiddenSet('docker');
    const focus = ui.lifecycleFocus?.view === 'active' && ui.lifecycleFocus.page === 'docker'
      ? ui.lifecycleFocus : null;
    if (focus) ui.reveal.add('docker');
    const revealing = ui.reveal.has('docker');
    const sortContainers = (list) => list.slice().sort((a, b) =>
      (isContainerRunning(b) ? 1 : 0) - (isContainerRunning(a) ? 1 : 0)
      || String(a.name).localeCompare(String(b.name)));
    let total = 0;
    let hiddenCount = 0;
    const groups = [];

    const out = [
      inventoryDiagnostics,
      h('div', { class: 'grid-head dock-grid', 'aria-hidden': 'true' },
        h('span', null, ''), h('span', null, 'Container'), h('span', null, 'Image'),
        h('span', null, 'CPU / Mem'), h('span', null, 'Ports'), h('span', null, 'Actions')),
    ];

    for (const group of projectGroupsOf(o)) {
      const containers = sortContainers(group.members.containers);
      if (!containers.length) continue;
      total += containers.length;
      const up = containers.filter(isContainerRunning).length;
      const extraText = `${up} of ${containers.length} up`;
      const entries = [];
      for (const c of containers) {
        const isHidden = hidden.has(c.name);
        if (isHidden) hiddenCount += 1;
        if (isHidden && !revealing) continue;
        entries.push({
          group,
          extraText,
          item: c,
          isHidden,
          webish: isWebServerContainer(o, group, c),
        });
      }
      groups.push({ group, extraText, memberCount: containers.length, entries });
    }

    if (focus) {
      for (const entry of groups) {
        const index = entry.entries.findIndex((member) => lifecycleIdentityMatches(
          focus, 'container', member.item.host_resource_id,
        ));
        if (index < 0) continue;
        ui.dockerGroupsExpanded.clear();
        ui.dockerGroupsExpanded.add(entry.group.key);
        ui.resourcePages.docker = Math.floor(index / RESOURCE_PAGE_SIZE);
        break;
      }
    }

    if (total === 0) {
      return [inventoryDiagnostics,
        emptyState('No containers found — anything started with docker run or compose shows up here.')].filter(Boolean);
    }
    for (const entry of groups) out.push(dockerProjectBlock(o, entry));
    if (docker.stats_error) {
      out.push(h('p', { class: 'inline-note' }, `Stats unavailable: ${docker.stats_error}`));
    }
    const toggle = revealToggle('docker', hiddenCount);
    if (toggle) out.push(toggle);
    return out;
  }

  // Docker mirrors the Servers accordion: every project header stays visible,
  // while only one bounded project-local member page is mounted at a time.
  function dockerProjectBlock(o, entry) {
    const expanded = ui.dockerGroupsExpanded.has(entry.group.key);
    const panelId = `dock-group-panel-${encodeURIComponent(entry.group.key)}`;
    const usage = entry.group.row
      ? h('span', { class: 'proj-usage mono' },
          h('span', { class: 'u-cpu' }, fmtCpu(entry.group.row.cpu_percent)),
          ' · ',
          h('span', { class: 'u-mem' }, fmtBytes(entry.group.row.memory_bytes || 0)))
      : null;
    const usageLabel = entry.group.row
      ? `, CPU ${fmtCpu(entry.group.row.cpu_percent)}, memory ${fmtBytes(entry.group.row.memory_bytes || 0)}`
      : '';
    const toggle = h('button', {
      class: 'server-project-toggle', type: 'button',
      'data-fk': `dock-group:${entry.group.key}`,
      'aria-expanded': String(expanded),
      'aria-controls': panelId,
      'aria-label': `${expanded ? 'Collapse' : 'Expand'} ${entry.group.name}, ${entry.extraText}${usageLabel}`,
      title: expanded ? 'Collapse container group' : 'Expand container group',
      onclick: () => {
        setExclusiveExpansion(ui.dockerGroupsExpanded, entry.group.key);
        ui.resourcePages.docker = 0;
        bump();
        renderAll(true);
      },
    },
      h('span', { class: `chev${expanded ? ' open' : ''}`, 'aria-hidden': 'true' }, icon('chevron')),
      h('strong', { class: 'proj-name' }, entry.group.name),
      h('span', { class: 'meta-passive server-group-count' }, entry.extraText),
      entry.group.metricsKey ? sparkline(metricsEntity(entry.group.metricsKey)) : null,
      usage);

    const children = [];
    if (expanded) {
      if (entry.entries.length) {
        const paged = pageSlice(entry.entries, ui.resourcePages.docker);
        ui.resourcePages.docker = paged.page;
        for (const member of paged.items) {
          children.push(dockerItem(o, member.item, member.isHidden, member.webish));
        }
        const pager = resourcePager('docker', 'Project containers', paged);
        if (pager) children.push(pager);
      } else if (entry.memberCount > 0) {
        children.push(h('p', { class: 'inline-note' },
          'All containers in this resource group are hidden. Use the control below to reveal them.'));
      }
    }

    return h('div', { class: 'server-project-block docker-project-block' },
      h('h3', { class: `proj-head${expanded ? ' is-open' : ''}`, title: entry.group.project || '' }, toggle),
      h('div', {
        class: 'docker-group-items', id: panelId,
        hidden: expanded ? undefined : true,
      }, children));
  }

  function dockerItem(o, c, hiddenRow = false, webish = false) {
    const name = c.name;
    const running = isContainerRunning(c);
    const open = ui.dockerOpen.has(name);
    const busy = ui.busy.has(`docker:${name}`);
    const panelId = `dock-panel-${name}`;
    const ownership = containerOwnershipState(c);
    const inventoryProblem = inventoryMutationProblemOf(o, {
      target_kind: 'container', target_id: c.host_resource_id,
    });
    const archiveTarget = ownership.genericLifecycle
      ? lifecycleTarget('container', c.host_resource_id, name, 'docker', {
          projectId: c.repo_id || null,
        })
      : null;

    const dotKey = `dock-dot:${name}`;
    const dot = h('button', {
      class: `dotbtn ${running ? 'ok' : ''}`, type: 'button',
      'data-fk': dotKey, 'aria-haspopup': 'dialog',
      'aria-expanded': popover.key === dotKey ? 'true' : 'false',
      'aria-label': `Container ${name} is ${running ? 'running' : 'stopped'} — show details`,
      title: String(c.status || ''),
      onclick: (e) => popover.toggle(dotKey, e.currentTarget, () => (
        h('div', null,
          popHead(name),
          kv('Status', c.status || '—', { mono: true }),
          kv('Image', c.image || '—', { mono: true }),
          kv('Ports', c.ports || '—', { mono: true }),
          kv('Project', c.project || c.compose_project || '—', { mono: true }),
          kv('Metadata', c.metadata_source || 'none'),
          c.stats ? kv('CPU', c.stats.cpu_percent != null ? `${c.stats.cpu_percent.toFixed(1)}%` : '—') : null,
          c.stats ? kv('Memory', c.stats.memory_usage_bytes != null ? fmtBytes(c.stats.memory_usage_bytes) : '—') : null)
      )),
    }, h('span', { class: 'dot', 'aria-hidden': 'true' }),
      h('span', { class: 'visually-hidden' }, running ? 'running' : 'stopped'));

    const act = (action, label, iconName, confirmText) => h('button', {
      class: `btn small ${ACTION_CLS[action]}${busy ? ' is-busy' : ''}`, type: 'button',
      'data-fk': `dock-${action}:${name}`,
      disabled: (busy || inventoryProblem) || undefined,
      title: inventoryProblem
        ? `${label} is disabled only for this container until its ownership problem is resolved`
        : `${label} ${name}`,
      onclick: () => runAction(`docker:${name}`,
        () => api('/api/docker/action', { method: 'POST', body: { name, action } }),
        {
          ...(confirmText ? { confirmText } : {}),
          inventoryTargets: [{ target_kind: 'container', target_id: c.host_resource_id }],
        }),
    }, icon(iconName), busy ? 'Working…' : label);

    const row = h('div', {
      class: `row dock-grid expandable${hiddenRow ? ' is-hidden' : ''}${ownership.verified ? '' : ' ownership-unverified'}`,
      tabindex: '-1',
      'data-ownership': ownership.ephemeral
        ? 'coordinator-ephemeral' : (ownership.verified ? 'verified' : 'unverified'),
      'data-lifecycle-target': archiveTarget
        ? `${archiveTarget.target_kind}:${archiveTarget.target_id}` : null,
      onclick: (e) => {
        if (e.target.closest('button, a, input, select')) return;
        toggleDocker(c);
      },
    },
      h('span', { class: 'cell c-dot' }, dot),
      h('span', { class: 'cell c-primary', 'data-label': 'Container' },
        h('strong', null, name),
        ' ',
        h('span', { class: 'dim' }, running ? 'up' : 'stopped'),
        webish && ownership.genericLifecycle ? dockerSubdomainControl(o, c, 'dock') : null,
        unverifiedOwnershipNote(ownership)),
      h('span', { class: 'cell dim mono', 'data-label': 'Image' }, c.image || '—'),
      usageCellNode({
        key: `dock:${name}`,
        title: name,
        cpu: c.stats?.cpu_percent ?? null,
        mem: c.stats?.memory_usage_bytes ?? null,
        running: running && !!c.stats,
      }),
      h('span', { class: 'cell dim mono', 'data-label': 'Ports' }, c.ports || '—'),
      h('span', { class: 'cell actions' },
        ownership.genericLifecycle && running
          ? [act('restart', 'Restart', 'refresh'),
             act('stop', 'Stop', 'stop', `Stop container ${name}?\n\nAnything depending on it (like a database) loses its service.`)]
          : (ownership.genericLifecycle
              ? act('start', 'Start', 'play')
              : (running
                  ? [blockedContainerAction(`dock-restart:${name}`, 'Restart', 'refresh', { ephemeral: ownership.ephemeral }),
                     blockedContainerAction(`dock-stop:${name}`, 'Stop', 'stop', { ephemeral: ownership.ephemeral })]
                  : blockedContainerAction(`dock-start:${name}`, 'Start', 'play', { ephemeral: ownership.ephemeral }))),
        h('button', {
          class: 'btn small', type: 'button',
          'data-fk': `dock-logs:${name}`,
          'aria-expanded': String(open),
          'aria-controls': panelId,
          title: open ? 'Hide logs' : `Show logs for ${name}`,
          onclick: () => toggleDocker(c),
        }, icon('chevron'), 'Logs'),
        hiddenRow
          ? unhideButton('docker', name, name)
          : (!isContainerActive(c) ? hideButton('docker', name, name) : ghostIconSlot()),
        ownership.genericLifecycle
          ? archiveButton(archiveTarget, { compact: true })
          : (lifecycleAvailable()
              ? blockedContainerAction(`blocked-archive:${name}`, 'Archive', 'archive', {
                  compact: true, ephemeral: ownership.ephemeral,
                })
              : ghostIconSlot())));

    return h('div', { class: 'item' }, row, open ? dockerPanel(c, panelId) : null);
  }

  function toggleDocker(container) {
    const name = container?.name;
    if (typeof name !== 'string' || !name) return;
    if (ui.dockerOpen.has(name)) {
      ui.dockerOpen.delete(name);
    } else {
      ui.dockerOpen.add(name);
      const cached = ui.logs.get(`dock:${name}`);
      if (!cached || (cached.text == null && !cached.loading)) loadDockerLogs(container);
    }
    bump();
    renderAll(true);
  }

  async function loadDockerLogs(container) {
    const name = container?.name;
    const resourceId = container?.host_resource_id ?? container?.docker_resource_id ?? null;
    const key = `dock:${name}`;
    const refreshFocusKey = `dock-logs-refresh:${name}`;
    const restoreFocus = document.activeElement?.dataset?.fk === refreshFocusKey
      ? refreshFocusKey : null;
    if (typeof name !== 'string' || !name || typeof resourceId !== 'string' || !resourceId) {
      if (typeof name === 'string' && name) {
        ui.logs.set(key, {
          loading: false,
          text: null,
          error: 'Container logs require an immutable Coordinator resource ID.',
          at: Date.now(),
        });
        bump();
        renderAll(true);
        restoreAsyncActionFocus(restoreFocus);
      }
      return;
    }
    ui.logs.set(key, { ...(ui.logs.get(key) || {}), loading: true, error: null });
    bump();
    renderAll(true);
    try {
      const resp = await api('/api/docker/logs', {
        method: 'POST', body: { resource_id: resourceId },
      });
      const text = typeof resp?.text === 'string'
        ? resp.text
        : [resp?.stdout, resp?.stderr].filter(Boolean).join('\n');
      ui.logs.set(key, { loading: false, text: text ?? '', error: null, at: Date.now() });
    } catch (err) {
      if (err.status === 401) return;
      ui.logs.set(key, { loading: false, text: null, error: err.message, at: Date.now() });
    }
    bump();
    renderAll(true);
    restoreAsyncActionFocus(restoreFocus);
  }

  function dockerPanel(c, panelId) {
    const key = `dock:${c.name}`;
    const lg = ui.logs.get(key);
    return h('div', { class: 'panel', id: panelId },
      h('div', { class: 'panel-toolbar' },
        h('span', { class: 'panel-title' }, 'Container log'),
        lg?.at ? h('span', { class: 'meta-passive' }, `fetched ${fmtClock(lg.at)}`) : null,
        h('button', {
          class: 'btn small', type: 'button',
          'data-fk': `dock-logs-refresh:${c.name}`,
          disabled: lg?.loading || undefined,
          title: 'Fetch the latest 120 log lines',
          onclick: () => loadDockerLogs(c),
        }, icon('refresh'), lg?.loading ? 'Loading…' : 'Refresh')),
      logboxNode(key, lg));
  }

  // ---------------------------------------------------------------- leases

  // Order items by repo and put a small project header before each repo's
  // rows. Items without a project path sort last under "other".
  function groupedByProjectPath(o, items, projectOf) {
    const names = groupsByProjectPath(o);
    const buckets = new Map();
    for (const item of items) {
      const project = projectOf(item) || '';
      if (!buckets.has(project)) buckets.set(project, []);
      buckets.get(project).push(item);
    }
    const labeled = [...buckets.entries()].map(([project, list]) => ({
      project,
      label: project ? (names.get(project)?.name || projectTail(project)) : 'other',
      list,
    }));
    labeled.sort((a, b) => (a.project === '' ? 1 : 0) - (b.project === '' ? 1 : 0)
      || a.label.localeCompare(b.label));
    return labeled;
  }

  function projectSubheader(label, project) {
    return h('div', { class: 'proj-head', title: project || '' },
      h('strong', { class: 'proj-name' }, label));
  }

  function buildLeases(o) {
    if (!o.inventory) return [degradedPanel(o)];
    const leases = (o.inventory.leases || []).slice().sort((a, b) => (a.port || 0) - (b.port || 0));
    if (!leases.length) {
      return [emptyState('No active port leases — use Lease port or the coordinator CLI to reserve one.')];
    }
    const out = [
      h('div', { class: 'grid-head lease-grid', 'aria-hidden': 'true' },
        h('span', null, 'Port'), h('span', null, 'Purpose'), h('span', null, 'Project'),
        h('span', null, 'Expires'), h('span', null, '')),
    ];
    for (const groupOf of groupedByProjectPath(o, leases, (l) => l.project)) {
      out.push(projectSubheader(groupOf.label, groupOf.project));
      out.push(...groupOf.list.map((l) => leaseRow(o, l)));
    }
    return out;
  }

  function leaseRow(o, l) {
      const busy = ui.busy.has(`lease:${l.id}`);
      return (h('div', {
        class: 'item',
        tabindex: '-1',
        'data-lease-id': l.id,
        'data-lease-port': l.port,
      },
        h('div', { class: 'row lease-grid' },
          h('span', { class: 'cell mono', 'data-label': 'Port' }, h('strong', null, String(l.port ?? '—'))),
          h('span', { class: 'cell', 'data-label': 'Purpose', title: l.agent ? `Leased by ${l.agent}` : '' },
            l.purpose || 'manual'),
          h('span', { class: 'cell dim', 'data-label': 'Project', title: l.project || '' }, projectTail(l.project)),
          h('span', { class: 'cell', 'data-label': 'Expires' },
            l.expires_at == null
              ? h('span', { class: 'meta-passive' }, 'never expires')
              : h('span', {
                  class: 'countdown', 'data-expires': String(l.expires_at),
                  title: l.expires_at_iso || '',
                }, countdownText(l.expires_at))),
          h('span', { class: 'cell actions' },
            h('button', {
              class: `btn small danger${busy ? ' is-busy' : ''}`, type: 'button',
              'data-fk': `lease-del:${l.id}`,
              disabled: busy || undefined,
              title: `Release port ${l.port}`,
              onclick: () => runAction(`lease:${l.id}`,
                () => api('/api/ports/release', { method: 'POST', body: { lease_id: l.id } }),
                {
                  confirmText: `Release the lease on port ${l.port}?\n\nAnything already listening keeps running, but the reservation disappears and another tool may claim this port.`,
                }),
            }, icon('trash'), busy ? 'Working…' : 'Release')))));
  }

  // ---------------------------------------------------------------- pinned ports

  function assignmentStatusMeta(status) {
    switch (status) {
      case 'running': return { css: 'ok', label: 'running' };
      case 'starting': return { css: 'warn', label: 'starting' };
      case 'unhealthy': return { css: 'err', label: 'unhealthy' };
      case 'stopped': return { css: 'dim', label: 'stopped' };
      default: return { css: 'dim', label: 'not registered' };
    }
  }

  function buildAssignments(o) {
    if (!o.inventory) return [degradedPanel(o)];
    const assignments = (o.inventory.port_assignments || []).slice().sort((a, b) => (a.port || 0) - (b.port || 0));
    if (!assignments.length) {
      return [emptyState('No pinned ports yet — starting or registering a dev server through the coordinator pins its port here permanently.')];
    }
    const out = [
      h('div', { class: 'grid-head assign-grid', 'aria-hidden': 'true' },
        h('span', null, 'Port'), h('span', null, 'Server'), h('span', null, 'Project'),
        h('span', null, 'Server status'), h('span', null, '')),
    ];
    for (const groupOf of groupedByProjectPath(o, assignments, (a) => a.project)) {
      out.push(projectSubheader(groupOf.label, groupOf.project));
      out.push(...groupOf.list.map((a) => assignmentRow(a)));
    }
    return out;
  }

  function assignmentRow(a) {
      const busy = ui.busy.has(`assign:${a.key}`);
      const meta = assignmentStatusMeta(a.server_status);
      return (h('div', { class: 'item' },
        h('div', { class: 'row assign-grid' },
          h('span', { class: 'cell mono', 'data-label': 'Port' }, h('strong', null, String(a.port ?? '—'))),
          h('span', { class: 'cell', 'data-label': 'Server', title: `Pinned ${fmtWhen(a.created_at)} by ${a.agent || 'unknown'}` },
            h('strong', null, a.name || '—')),
          h('span', { class: 'cell dim', 'data-label': 'Project', title: a.project || '' }, projectTail(a.project)),
          h('span', { class: 'cell', 'data-label': 'Server status' },
            h('span', { class: `badge ${meta.css} static-badge` },
              h('span', { class: 'dot', 'aria-hidden': 'true' }), meta.label)),
          h('span', { class: 'cell actions' },
            h('button', {
              class: `btn small danger${busy ? ' is-busy' : ''}`, type: 'button',
              'data-fk': `assign-del:${a.key}`,
              disabled: busy || undefined,
              title: `Unassign port ${a.port} from ${a.name}`,
              onclick: () => runAction(`assign:${a.key}`,
                () => api('/api/ports/unassign', { method: 'POST', body: { name: a.name, project: a.project } }),
                {
                  confirmText: `Unassign port ${a.port} from server "${a.name}"?\n\nThe server keeps running if it is up, but on its next start it may land on a different port, and other projects can claim ${a.port}.`,
                }),
            }, icon('trash'), busy ? 'Working…' : 'Unassign')))));
  }

  // ---------------------------------------------------------------- lease form

  let leaseDialogReturnFocus = null;
  let pendingCreatedLeaseFocus = null;

  function createdLeaseRow(lease) {
    return [...document.querySelectorAll('#leases-body [data-lease-id]')]
      .find((candidate) => (
        lease?.id != null
          ? candidate.dataset.leaseId === String(lease.id)
          : candidate.dataset.leasePort === String(lease?.port ?? '')
      )) || null;
  }

  function restorePendingCreatedLeaseFocus() {
    const pending = pendingCreatedLeaseFocus;
    if (!pending || currentPage() !== 'ports' || $('#lease-dialog').open) return;
    const active = document.activeElement;
    const mayRestore = active === document.body
      || active === $('#lease-add')
      || active?.dataset?.leaseId === String(pending.lease?.id ?? '');
    if (!mayRestore) return;
    setTimeout(() => {
      if (pendingCreatedLeaseFocus !== pending) return;
      const row = createdLeaseRow(pending.lease);
      if (!row) return;
      row.focus({ preventScroll: true });
      row.scrollIntoView({ block: 'center' });
    }, 0);
  }

  function requestCreatedLeaseFocus(lease) {
    const pending = { lease };
    pendingCreatedLeaseFocus = pending;
    restorePendingCreatedLeaseFocus();
    setTimeout(() => {
      if (pendingCreatedLeaseFocus === pending) pendingCreatedLeaseFocus = null;
    }, 2_000);
  }

  function openLeaseDialog() {
    const dialog = $('#lease-dialog');
    leaseDialogReturnFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement : $('#lease-add');
    $('#lease-form').reset();
    $('#lf-error').hidden = true;
    $('#lf-error').textContent = '';
    dialog.showModal();
    queueMicrotask(() => $('#lf-purpose').focus());
  }

  function focusAfterLeaseDialog(target) {
    leaseDialogReturnFocus = null;
    setTimeout(() => {
      if (!target?.isConnected) return;
      target.focus({ preventScroll: true });
      target.scrollIntoView({ block: 'nearest' });
    }, 0);
  }

  function closeLeaseDialog(focusTarget = null) {
    const dialog = $('#lease-dialog');
    const target = focusTarget || leaseDialogReturnFocus || $('#lease-add');
    if (dialog.open) dialog.close();
    focusAfterLeaseDialog(target);
  }

  async function waitForCreatedLeaseRow(lease, timeoutMs = 5_000) {
    const deadline = Date.now() + timeoutMs;
    do {
      const row = createdLeaseRow(lease);
      if (row && !fetching && !refetchQueued) {
        await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        if (row.isConnected && !fetching && !refetchQueued) return row;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    } while (Date.now() < deadline);
    return null;
  }

  function wireLeaseForm() {
    $('#lease-add').addEventListener('click', openLeaseDialog);
    $('#lease-dialog-close').append(icon('x'));
    $('#lease-dialog-close').addEventListener('click', () => closeLeaseDialog());
    $('#lease-cancel').addEventListener('click', () => closeLeaseDialog());
    $('#lease-dialog').addEventListener('cancel', (event) => {
      event.preventDefault();
      closeLeaseDialog();
    });
    $('#lease-form').addEventListener('submit', onLeasePort);
  }

  async function onLeasePort(e) {
    e.preventDefault();
    const errEl = $('#lf-error');
    errEl.hidden = true;
    errEl.textContent = '';
    const fail = (msg) => { errEl.textContent = msg; errEl.hidden = false; };

    const body = { ttl: Number($('#lf-ttl').value) };
    const purpose = $('#lf-purpose').value.trim();
    if (purpose) body.purpose = purpose;
    const preferredRaw = $('#lf-preferred').value.trim();
    if (preferredRaw) {
      const preferred = Number(preferredRaw);
      if (!Number.isInteger(preferred) || preferred < 1 || preferred > 65535) {
        fail('Preferred port must be between 1 and 65535.');
        $('#lf-preferred').focus();
        return;
      }
      body.preferred = preferred;
    }
    const project = $('#lf-project').value.trim();
    if (project) body.project = project;

    const btn = $('#lf-submit');
    btn.disabled = true;
    const oldText = btn.textContent;
    btn.textContent = 'Leasing…';
    try {
      const resp = await api('/api/ports/lease', { method: 'POST', body });
      const lease = resp?.lease || null;
      $('#lf-purpose').value = '';
      $('#lf-preferred').value = '';
      $('#lf-project').value = '';
      announce(`Port ${lease?.port ?? ''} leased`);
      await refreshOverview({ force: true, fresh: true });
      const createdRow = await waitForCreatedLeaseRow(lease);
      closeLeaseDialog(createdRow || $('#lease-add'));
      requestCreatedLeaseFocus(lease);
    } catch (err) {
      if (err.status !== 401) {
        fail(err.message);
        showBanner(err, () => $('#lease-form').requestSubmit());
      }
    } finally {
      btn.disabled = false;
      btn.textContent = oldText;
    }
  }

 // ---------------------------------------------------------------- projects tree

  function projectAction(group, action) {
    // Wording matches what the coordinator actually does: it acts on the
    // repo's DECLARED runtime (dev-runtime config or its registered servers),
    // which may be narrower than everything listed under this group.
    const confirms = {
      stop: `Stop root repository "${group.name}"?\n\nThe coordinator stops only the runtime declared by this root checkout. Temporary repository runs remain separate.`,
      restart: `Restart root repository "${group.name}"?\n\nThe coordinator restarts only the runtime declared by this root checkout. Temporary repository runs remain separate.`,
    };
    const operationId = crypto.randomUUID();
    runAction(`project:${group.key}`,
      () => api('/api/projects/action', {
        method: 'POST',
        body: { project: group.project, action, operation_id: operationId },
      }),
      {
        ...(confirms[action] ? { confirmText: confirms[action] } : {}),
        inventoryTargets: [{ target_kind: 'project', target_id: group.rootScope.repoId }],
      });
  }

  // Color code shared by every action button in the console: green starts,
  // blue restarts, red stops — same meaning on every page.
  const ACTION_CLS = { start: 'act-start', restart: 'act-restart', stop: 'act-stop' };

  // Every tree actions cell renders the SAME three fixed-width slots
  // (Start | Restart | Stop); inapplicable actions are disabled, never
  // hidden, so buttons line up into clean columns across project headers,
  // server rows and container rows alike.
  function treeActionSlots(slots) {
    return ['start', 'restart', 'stop'].map((name) => {
      const def = slots[name];
      return h('button', {
        class: `btn small tree-act ${ACTION_CLS[name]}${def.busy ? ' is-busy' : ''}`, type: 'button',
        'data-fk': def.fk,
        disabled: (def.busy || def.disabled) || undefined,
        title: def.title,
        onclick: def.onclick,
      }, icon(def.icon), def.busy ? 'Working…' : def.label);
    });
  }

  function projectActionButtons(group) {
    const busy = ui.busy.has(`project:${group.key}`);
    const noPath = !group.project;
    const inventoryProblem = inventoryMutationProblemOf(state.overview, {
      target_kind: 'project', target_id: group.rootScope.repoId,
    });
    const slot = (action, label, iconName) => ({
      fk: `proj-${action}:${group.key}`,
      label,
      icon: iconName,
      busy,
      disabled: noPath || !!inventoryProblem,
      title: inventoryProblem
        ? `${label} is disabled only for this repository until its affected resource is repaired`
        : noPath
        ? 'No repo path known for this group — control its items individually'
        : `${label} the root repository runtime only (temporary repository runs stay separate)`,
      onclick: () => projectAction(group, action),
    });
    return treeActionSlots({
      start: slot('start', 'Start', 'play'),
      restart: slot('restart', 'Restart', 'refresh'),
      stop: slot('stop', 'Stop', 'stop'),
    });
  }

  function treeStatusBadge(css, label) {
    return h('span', { class: `badge ${css} static-badge` },
      h('span', { class: 'dot', 'aria-hidden': 'true' }), label);
  }

  // Invisible stand-in for the hide/unhide icon so action groups keep the
  // same width on every row and buttons align into a clean column.
  const ghostIconSlot = () => h('span', { class: 'iconbtn ghost', 'aria-hidden': 'true' });

  function treeServerRow(o, s, hiddenRow) {
    const busy = ui.busy.has(`server:${s.id}`);
    const meta = serverStatusMeta(s);
    const stopped = s.status === 'stopped';
    const running = isServerRunning(s);
    const supervised = !!s.supervision;
    const genericLifecycle = serverSupportsGenericLifecycle(s);
    const detail = supervised
      ? `${s.supervision.keep_alive === true ? 'Keep alive on' : 'Keep alive off'}${s.url ? ` · ${s.url}` : ''}`
      : (s.url || '');
    const archiveTarget = lifecycleTarget('server', s.id, s.name || 'Unnamed server', 'servers');
    const inventoryProblem = inventoryMutationProblemOf(o, {
      target_kind: 'server', target_id: s.id,
    });
    const slot = (action, label, iconName, disabled, title) => ({
      fk: `tree-srv-${action}-${label}:${s.id}`,
      label,
      icon: iconName,
      busy,
      disabled: !!inventoryProblem || disabled,
      title: inventoryProblem
        ? `${label} is disabled only for this server until its ownership problem is resolved`
        : title,
      onclick: () => runAction(`server:${s.id}`,
        () => api('/api/servers/action', { method: 'POST', body: { id: s.id, action } }),
        { inventoryTargets: [{ target_kind: 'server', target_id: s.id }] }),
    });
    return h('div', {
      class: `row tree-grid tree-item${hiddenRow ? ' is-hidden' : ''}`,
      tabindex: '-1',
      'data-lifecycle-target': genericLifecycle
        ? `${archiveTarget.target_kind}:${archiveTarget.target_id}`
        : null,
    },
      h('span', { class: 'cell c-kind' },
        projectResourceKindTrigger(supervised ? 'worker' : 'server', s.id || s.key || s.name)),
      h('span', { class: 'cell c-primary' },
        h('strong', null, s.name || '—'),
        h('span', { class: 'dim mono' }, s.port != null ? ` :${s.port}` : ''),
        h('span', { class: 'tree-detail dim mono', title: detail }, detail)),
      usageCellNode({
        key: `srv:${s.id}`,
        title: s.name || 'Server',
        cpu: s.process_usage?.cpu_percent ?? null,
        mem: s.process_usage?.memory_bytes ?? null,
        running: !!s.process_usage,
        scope: 'tree',
      }),
      h('span', { class: 'cell c-status' }, treeStatusBadge(meta.css, meta.label)),
      h('span', { class: 'cell actions' },
        // A stopped coordinator server starts through the restart action.
        supervised ? treeWorkerActionSlots(s, busy) : treeActionSlots({
          start: slot('restart', 'Start', 'play', !stopped || s.missing_command,
            !stopped ? 'Already running'
              : (s.missing_command ? 'Registered without a start command' : `Start ${s.name} on its pinned port`)),
          restart: slot('restart', 'Restart', 'refresh', !running || s.missing_command,
            !running ? 'Not running — use Start'
              : (s.missing_command ? 'Registered without a start command' : `Restart ${s.name} on the same port`)),
          stop: slot('stop', 'Stop', 'stop', !running,
            !running ? 'Server is not running' : `Stop ${s.name}`),
        }),
        hiddenRow
          ? unhideButton('servers', s.key, s.name || 'server')
          : (stopped ? hideButton('servers', s.key, s.name || 'server') : ghostIconSlot()),
        supervised
          ? workerRemoveButton(s, { compact: true })
          : (genericLifecycle
              ? archiveButton(archiveTarget, { compact: true })
              : ghostIconSlot())));
  }

  function treeContainerRow(o, c, isDb, hiddenRow, webish = false) {
    const busy = ui.busy.has(`docker:${c.name}`);
    const running = isContainerRunning(c);
    const ownership = containerOwnershipState(c);
    const inventoryProblem = inventoryMutationProblemOf(o, {
      target_kind: 'container', target_id: c.host_resource_id,
    });
    const archiveTarget = ownership.genericLifecycle
      ? lifecycleTarget('container', c.host_resource_id, c.name, 'docker')
      : null;
    const slot = (action, label, iconName, disabled, title, confirmText) => ({
      fk: `tree-dock-${action}:${c.name}`,
      label,
      icon: iconName,
      busy,
      disabled: !ownership.genericLifecycle || !!inventoryProblem || disabled,
      title: inventoryProblem
        ? `${label} is disabled only for this container until its ownership problem is resolved`
        : ownership.genericLifecycle
        ? title
        : (ownership.ephemeral
            ? `${label} is unavailable here; use coordinator ephemeral renew or finish`
            : `${label} is unavailable until the coordinator proves one repository owner`),
      onclick: ownership.genericLifecycle
        ? () => runAction(`docker:${c.name}`,
            () => api('/api/docker/action', { method: 'POST', body: { name: c.name, action } }),
            {
              ...(confirmText ? { confirmText } : {}),
              inventoryTargets: [{ target_kind: 'container', target_id: c.host_resource_id }],
            })
        : undefined,
    });
    return h('div', {
      class: `row tree-grid tree-item${hiddenRow ? ' is-hidden' : ''}${ownership.verified ? '' : ' ownership-unverified'}`,
      tabindex: '-1',
      'data-ownership': ownership.ephemeral
        ? 'coordinator-ephemeral' : (ownership.verified ? 'verified' : 'unverified'),
      'data-lifecycle-target': archiveTarget
        ? `${archiveTarget.target_kind}:${archiveTarget.target_id}` : null,
    },
      h('span', { class: 'cell c-kind' },
        projectResourceKindTrigger(isDb ? 'database' : 'container', c.host_resource_id || c.name)),
      h('span', { class: 'cell c-primary' },
        h('strong', null, c.name),
        h('span', { class: 'tree-detail dim mono', title: c.image || '' }, c.image || ''),
        // Own wrapping block: the name line is nowrap+ellipsis and would
        // otherwise clip the chip invisible.
        webish && ownership.genericLifecycle
          ? h('span', { class: 'tree-sub' }, dockerSubdomainControl(o, c, 'tree')) : null,
        unverifiedOwnershipNote(ownership)),
      usageCellNode({
        key: `dock:${c.name}`,
        title: c.name,
        cpu: c.stats?.cpu_percent ?? null,
        mem: c.stats?.memory_usage_bytes ?? null,
        running: running && !!c.stats,
        scope: 'tree',
      }),
      h('span', { class: 'cell c-status' },
        running
          ? treeStatusBadge('ok', 'up')
          : (isContainerActive(c) ? treeStatusBadge('err', 'restarting') : treeStatusBadge('dim', 'stopped'))),
      h('span', { class: 'cell actions' },
        treeActionSlots({
          start: slot('start', 'Start', 'play', running,
            running ? 'Already running' : `Start container ${c.name}`),
          restart: slot('restart', 'Restart', 'refresh', !running,
            !running ? 'Not running — use Start' : `Restart container ${c.name}`),
          stop: slot('stop', 'Stop', 'stop', !running,
            !running ? 'Already stopped' : `Stop container ${c.name}`,
            `Stop container ${c.name}?\n\nAnything depending on it (like a database) loses its service.`),
        }),
        hiddenRow
          ? unhideButton('docker', c.name, c.name)
          : (!isContainerActive(c) ? hideButton('docker', c.name, c.name) : ghostIconSlot()),
        ownership.genericLifecycle
          ? archiveButton(archiveTarget, { compact: true })
          : (lifecycleAvailable()
              ? blockedContainerAction(`blocked-archive:${c.name}`, 'Archive', 'archive', {
                  compact: true, ephemeral: ownership.ephemeral,
                })
              : ghostIconSlot())));
  }

  function projectScopeRows(o, group, scope, revealing, hiddenServers, hiddenDocker, label) {
    const entries = [];
    for (const server of scope.members.servers.slice()
      .sort((a, b) => String(a.name).localeCompare(String(b.name)))) {
      const isHidden = hiddenServers.has(server.key);
      if (isHidden && !revealing) continue;
      entries.push({ kind: 'server', item: server, isHidden });
    }
    for (const container of scope.members.containers.slice()
      .sort((a, b) => String(a.name).localeCompare(String(b.name)))) {
      const isHidden = hiddenDocker.has(container.name);
      if (isHidden && !revealing) continue;
      entries.push({ kind: 'docker', item: container, isHidden });
    }
    if (!entries.length) {
      const memberCount = scope.members.servers.length + scope.members.containers.length;
      return [h('p', { class: 'inline-note' }, memberCount
        ? 'All services in this repository are hidden.'
        : `No services registered ${scope.kind === 'temporary' ? 'for this temporary repo' : 'directly under this root repo'}.`)];
    }
    const requestedPage = ui.projectScopePages.get(scope.key) || 0;
    const paged = pageSlice(entries, requestedPage);
    ui.projectScopePages.set(scope.key, paged.page);
    const rows = paged.items.map((entry) => entry.kind === 'server'
      ? treeServerRow(o, entry.item, entry.isHidden)
      : treeContainerRow(o, entry.item, scope.dbNames.has(entry.item.name), entry.isHidden,
          isWebServerContainer(o, { ...group, dbNames: scope.dbNames }, entry.item)));
    const pager = projectScopePager(scope.key, label, paged);
    if (pager) rows.push(pager);
    return rows;
  }

  function temporaryScopeBlock(o, group, scope, revealing, hiddenServers, hiddenDocker) {
    const expanded = ui.temporaryScopesExpanded.has(scope.key);
    const memberCount = scope.members.servers.length + scope.members.containers.length;
    const panelId = `temporary-scope-${encodeURIComponent(scope.key)}`;
    const expiresAt = scope.expiresAt == null ? 'no expiry provided' : (() => {
      const epoch = Date.parse(String(scope.expiresAt));
      return Number.isFinite(epoch) ? `expires ${new Date(epoch).toLocaleString()}` : `expires ${scope.expiresAt}`;
    })();
    const usage = scope.usage || {};
    const toggle = h('button', {
      class: 'temporary-scope-toggle', type: 'button',
      'data-fk': `temporary-scope:${scope.key}`,
      'aria-expanded': String(expanded),
      'aria-controls': panelId,
      'aria-label': `${expanded ? 'Collapse' : 'Expand'} temporary repo ${scope.name}, ${memberCount} service${sfx(memberCount)}`,
      onclick: () => {
        setExclusiveExpansion(ui.temporaryScopesExpanded, scope.key);
        ui.projectScopePages.set(scope.key, 0);
        bump();
        renderAll(true);
      },
    },
      h('span', { class: `chev${expanded ? ' open' : ''}`, 'aria-hidden': 'true' }, icon('chevron')),
      h('strong', { class: 'proj-name' }, scope.name),
      h('span', { class: 'meta-passive temporary-scope-count' },
        `${scope.runningCount} of ${memberCount} running`),
      h('span', { class: 'proj-usage mono' },
        `${fmtCpu(usage.cpu_percent)} · ${fmtBytes(usage.memory_bytes || 0)}`),
      h('span', { class: 'meta-passive temporary-scope-policy' },
        `${expiresAt} · ${scope.killAfterRun === true ? 'cleanup after run'
          : scope.killAfterRun === false ? 'retained after run' : 'cleanup policy unavailable'}`));
    const children = expanded
      ? projectScopeRows(o, group, scope, revealing, hiddenServers, hiddenDocker, 'Temporary repo items')
      : [];
    return h('section', { class: 'temporary-scope-block' },
      h('h4', { class: `temporary-scope-head${expanded ? ' is-open' : ''}` },
        projectResourceKindTrigger('temporary', scope.key), toggle),
      h('div', {
        class: 'temporary-scope-items', id: panelId,
        hidden: expanded ? undefined : true,
      }, children));
  }

  function projectNode(o, group, hiddenProject, revealing, hiddenServers, hiddenDocker) {
    const collapsed = !ui.treeExpanded.has(group.key);
    const rootMemberCount = group.rootScope.members.servers.length
      + group.rootScope.members.containers.length;
    const rootRunningCount = group.rootScope.runningCount || 0;
    const archiveTarget = lifecycleTarget('project', group.repoId, group.name, 'projects');
    const toggleProject = () => {
      if (collapsed) {
        ui.treeExpanded.clear();
        ui.treeExpanded.add(group.key);
      } else {
        ui.treeExpanded.delete(group.key);
      }
      ui.temporaryScopesExpanded.clear();
      ui.projectScopePages.clear();
      ui.resourcePages.projects = 0;
      bump();
      renderAll(true);
    };
    const chev = h('button', {
      class: `chev${collapsed ? '' : ' open'}`, type: 'button',
      'data-fk': `tree-x:${group.key}`,
      'aria-expanded': String(!collapsed),
      'aria-label': `${collapsed ? 'Expand' : 'Collapse'} project ${group.name}`,
      title: collapsed ? 'Expand project' : 'Collapse project',
      onclick: toggleProject,
    }, icon('chevron'));

    const header = h('div', {
      class: `row tree-grid tree-head${hiddenProject ? ' is-hidden' : ''}`,
      title: group.project || '',
      tabindex: '-1',
      'data-lifecycle-target': archiveTarget
        ? `${archiveTarget.target_kind}:${archiveTarget.target_id}` : null,
      onclick: (event) => {
        if (event.target.closest?.('button, a, input, select, textarea, [role="button"]')) return;
        toggleProject();
      },
      },
      h('span', { class: 'cell c-kind' }, chev),
      h('span', { class: 'cell c-primary' },
        h('strong', { class: 'proj-name', title: group.name }, group.name)),
      group.metricsKey
        ? usageCellNode({
            key: group.authoritative
              ? `repo:${group.rootScope.repoId ?? group.key}`
              : group.metricsKey,
            title: group.authoritative ? `Root repository ${group.name}` : `Project ${group.name}`,
            cpu: group.rootScope.usage?.cpu_percent ?? null,
            mem: group.rootScope.usage?.memory_bytes ?? null,
            running: rootRunningCount > 0,
            scope: 'proj',
          })
        : h('span', { class: 'cell usage-cell dim' }, '—'),
      h('span', { class: 'cell c-status meta-passive tree-count' },
        `${rootRunningCount} of ${rootMemberCount} root services running`),
      h('span', { class: 'cell actions project-actions' },
        projectActionButtons(group),
        hiddenProject
          ? unhideButton('projects', group.key, group.name)
          : (group.runningCount === 0 ? hideButton('projects', group.key, group.name) : ghostIconSlot()),
        archiveButton(archiveTarget, { compact: true })));

    const familySummary = group.temporaryScopes.length
      ? h('div', { class: 'repository-family-summary' },
          h('strong', null, 'Family total'),
          h('span', { class: 'meta-passive' },
            `root + ${group.temporaryScopes.length} temporary repo${sfx(group.temporaryScopes.length)} · `
            + `${group.runningCount} of ${group.members.servers.length + group.members.containers.length} services running`),
          h('span', { class: 'proj-usage mono' },
            `${fmtCpu(group.row?.cpu_percent)} · ${fmtBytes(group.row?.memory_bytes || 0)}`))
      : null;

    const children = [];
    if (!collapsed) {
      children.push(...projectScopeRows(
        o, group, group.rootScope, revealing, hiddenServers, hiddenDocker, 'Root repo items',
      ));
      for (const scope of group.temporaryScopes) {
        children.push(temporaryScopeBlock(
          o, group, scope, revealing, hiddenServers, hiddenDocker,
        ));
      }
    }
    return h('div', { class: 'item tree-node' }, header, familySummary,
      h('div', { class: 'tree-children' }, children));
  }

  function buildProjects(o) {
    if (!o.inventory) return [degradedPanel(o)];
    const inventoryError = authoritativeInventoryErrorPanel(o);
    if (inventoryError) return [inventoryError];
    const inventoryDiagnostics = authoritativeInventoryDiagnosticPanel(o);
    const groups = projectGroupsOf(o);
    if (!groups.length) {
      return [inventoryDiagnostics,
        emptyState('No projects yet — anything an agent starts or registers through the coordinator appears here, grouped by repo.')].filter(Boolean);
    }
    const hiddenProjects = hiddenSet('projects');
    const hiddenServers = hiddenSet('servers');
    const hiddenDocker = hiddenSet('docker');
    const focus = ui.lifecycleFocus?.view === 'active' && ui.lifecycleFocus.page === 'projects'
      ? ui.lifecycleFocus : null;
    if (focus) ui.reveal.add('projects');
    const revealing = ui.reveal.has('projects');

    let hiddenCount = 0;
    const out = inventoryDiagnostics ? [inventoryDiagnostics] : [];
    for (const group of groups) {
      const isHidden = hiddenProjects.has(group.key);
      const hiddenItems = group.members.servers.filter((s) => hiddenServers.has(s.key)).length
        + group.members.containers.filter((c) => hiddenDocker.has(c.name)).length;
      // Count hidden items even inside a concealed project, so the reveal
      // toggle's number matches what actually appears.
      hiddenCount += hiddenItems;
      if (isHidden) {
        hiddenCount += 1;
        if (!revealing) continue;
      }
      out.push(projectNode(o, group, isHidden, revealing, hiddenServers, hiddenDocker));
    }
    if (!out.length) {
      out.push(emptyState('Every project is hidden right now — they come back automatically when something in them runs.'));
    }
    const toggle = revealToggle('projects', hiddenCount);
    if (toggle) out.push(toggle);
    return out;
  }

  // ---------------------------------------------------------------- performance

  function fmtUptime(sec) {
    const s = Math.max(0, Math.floor(Number(sec) || 0));
    const d = Math.floor(s / 86_400);
    const hs = Math.floor((s % 86_400) / 3600);
    const min = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d}d ${hs}h`;
    if (hs > 0) return `${hs}h ${min}m`;
    return `${min}m`;
  }

  const PERFORMANCE_PROJECT_COLORS = [
    '#f17074', '#ffaa75', '#d29000', '#c9cb61',
    '#63b650', '#5bdfb7', '#00bac5', '#5ad3ff',
    '#619dff', '#c3b5ff', '#c97adb', '#ffa0d0',
  ];
  const PERFORMANCE_CATEGORY_COLORS = Object.freeze({
    'project-runtimes': '#16d39a',
    'coordinator-control': '#2f81f7',
    'coordinator-background': '#b56cff',
    'active-test-attempts': '#ff8a2a',
    'developer-sessions': '#e8eef6',
    'agent-browsers': '#8bd5ff',
    'control-other': '#8056b3',
    'system-unclassified': '#68717d',
    available: '#27313d',
  });

  function perfFinite(...values) {
    for (const value of values) {
      if (value === null || value === undefined || value === '') continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return null;
  }

  function perfEpochMs(value) {
    if (value === null || value === undefined || value === '') return null;
    const parsed = typeof value === 'string' ? Date.parse(value) : Number(value);
    if (!Number.isFinite(parsed)) return null;
    return parsed > 0 && parsed < 100_000_000_000 ? parsed * 1000 : parsed;
  }

  function perfBound(value, min, max) {
    return Math.min(max, Math.max(min, Number(value) || 0));
  }

  function perfCoveragePercent(value) {
    const number = perfFinite(value);
    if (number === null) return null;
    return perfBound(number <= 1 ? number * 100 : number, 0, 100);
  }

  function perfPercent(value, digits = 1) {
    const number = perfFinite(value);
    return number === null ? '—' : number.toFixed(digits) + '%';
  }

  function perfSkewText(value) {
    const ms = Math.max(0, perfFinite(value) || 0);
    if (ms < 1000) return Math.round(ms) + ' ms';
    if (ms < 60_000) return (ms / 1000).toFixed(ms < 10_000 ? 1 : 0) + ' s';
    return (ms / 60_000).toFixed(1) + ' min';
  }

  function perfLocalTime(value) {
    const at = perfEpochMs(value);
    if (at === null) return '—';
    return new Date(at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function perfProjectColorIndex(key) {
    let hash = 0;
    for (const char of String(key || 'project')) {
      hash = ((hash << 5) - hash + char.charCodeAt(0)) | 0;
    }
    return Math.abs(hash) % PERFORMANCE_PROJECT_COLORS.length;
  }

  function assignPerformanceProjectColors(segments) {
    const projects = segments.filter((segment) => segment.project)
      .slice()
      .sort((left, right) => String(left.key).localeCompare(String(right.key)));
    const used = new Set();
    for (const project of projects) {
      const preferred = perfProjectColorIndex(project.key);
      let offset = 0;
      while (offset < PERFORMANCE_PROJECT_COLORS.length
        && used.has(PERFORMANCE_PROJECT_COLORS[(preferred + offset)
          % PERFORMANCE_PROJECT_COLORS.length])) {
        offset += 1;
      }
      const color = PERFORMANCE_PROJECT_COLORS[(preferred + offset)
        % PERFORMANCE_PROJECT_COLORS.length];
      project.color = color;
      used.add(color);
    }
  }

  function perfSegmentKind(value) {
    const kind = String(value || '').toLowerCase().replaceAll('_', '-');
    if (kind === 'project-family' || kind === 'family' || kind === 'repository-family') {
      return 'project-family';
    }
    if (kind === 'project' || kind === 'repository') return 'project';
    if (kind === 'project-runtimes' || kind === 'project-runtime') return 'project-runtimes';
    if (kind === 'coordinator-control' || kind === 'control-plane') return 'coordinator-control';
    if (kind === 'coordinator-background' || kind === 'background-scheduler') {
      return 'coordinator-background';
    }
    if (kind === 'active-test-attempts' || kind === 'test-attempts') {
      return 'active-test-attempts';
    }
    if (kind === 'developer-sessions' || kind === 'developer-account-sessions') {
      return 'developer-sessions';
    }
    if (kind === 'agent-browsers' || kind === 'agent-browser') return 'agent-browsers';
    if (kind === 'control-other' || kind === 'control' || kind === 'other') return 'control-other';
    if (kind === 'available' || kind === 'idle') return 'available';
    return 'system-unclassified';
  }

  function perfSegmentName(segment, kind) {
    if (kind === 'system-unclassified') return 'Estimated System & unattributed';
    if (kind === 'available') return 'Available';
    if (kind === 'project-runtimes') return 'Project runtimes';
    if (kind === 'coordinator-control') return 'Coordinator control plane';
    if (kind === 'coordinator-background') return 'Coordinator background / scheduler';
    if (kind === 'active-test-attempts') return 'Active test attempts';
    if (kind === 'developer-sessions') return 'Developer-account sessions';
    if (kind === 'agent-browsers') return 'Agent browsers';
    if (kind === 'control-other') {
      return segment?.name || 'Measured control-plane / other workloads';
    }
    return segment?.name || projectTail(segment?.project) || segment?.key || 'Project';
  }

  function perfContributor(raw, cores) {
    const current = raw?.current || {};
    return {
      key: String(raw?.key ?? raw?.id ?? raw?.name ?? 'contributor'),
      kind: raw?.kind === 'docker' ? 'container' : (raw?.kind || 'service'),
      name: raw?.name || raw?.key || 'Unnamed workload',
      memoryBytes: Math.max(0, perfFinite(raw?.memoryBytes, raw?.memory_bytes,
        current.memoryBytes, current.memory_bytes) || 0),
      cpuPercent: Math.max(0, perfFinite(raw?.cpuPercent, raw?.cpu_percent,
        current.cpuPercent, current.cpu_percent,
        (perfFinite(raw?.cpuRawPercent, raw?.cpu_raw_percent) || 0) / Math.max(1, cores)) || 0),
      cpuRawPercent: Math.max(0, perfFinite(raw?.cpuRawPercent, raw?.cpu_raw_percent,
        current.cpuRawPercent, current.cpu_raw_percent) || 0),
      sampledAt: perfEpochMs(raw?.sampledAt ?? raw?.sampled_at),
      exact: raw?.exact === true,
      fresh: raw?.fresh !== false,
    };
  }

  function perfAgentBrowserInventory(segment) {
    const source = segment?.agentBrowsers ?? segment?.agent_browsers;
    if (!source || typeof source !== 'object') return null;
    const totals = source.totals || {};
    const policy = source.policy || {};
    const sessions = (Array.isArray(source.sessions) ? source.sessions : []).map((session) => ({
      sessionId: String(session?.sessionId ?? session?.session_id ?? 'browser session'),
      state: String(session?.state || 'unknown'),
      agent: session?.agent || null,
      repositoryName: session?.repositoryName ?? session?.repository_name ?? null,
      firstSeenAt: perfEpochMs(session?.firstSeenAt ?? session?.first_seen_at),
      lastObservedAt: perfEpochMs(session?.lastObservedAt ?? session?.last_observed_at),
      lastObservedWorkAt: perfEpochMs(
        session?.lastObservedWorkAt ?? session?.last_observed_work_at,
      ),
      idleSeconds: Math.max(0, perfFinite(session?.idleSeconds, session?.idle_seconds) || 0),
      processCount: Math.max(0, perfFinite(session?.processCount, session?.process_count) || 0),
      memoryBytes: Math.max(0, perfFinite(session?.memoryBytes, session?.memory_bytes) || 0),
      cpuPercent: Math.max(0, perfFinite(session?.cpuPercent, session?.cpu_percent) || 0),
      reapEligible: session?.reapEligible === true || session?.reap_eligible === true,
    }));
    const recentReaps = (Array.isArray(source.recentReaps)
      ? source.recentReaps : (Array.isArray(source.recent_reaps) ? source.recent_reaps : []))
      .map((reap) => ({
        sessionId: String(reap?.sessionId ?? reap?.session_id ?? 'browser session'),
        agent: reap?.agent || null,
        repositoryName: reap?.repositoryName ?? reap?.repository_name ?? null,
        reapedAt: perfEpochMs(reap?.reapedAt ?? reap?.reaped_at ?? reap?.at),
        reason: reap?.reason || null,
        processCount: Math.max(0, perfFinite(reap?.processCount, reap?.process_count) || 0),
        reclaimedMemoryBytes: Math.max(0, perfFinite(
          reap?.reclaimedMemoryBytes,
          reap?.reclaimed_memory_bytes,
          reap?.memory_bytes,
        ) || 0),
      }));
    return {
      sampledAt: perfEpochMs(source.sampledAt ?? source.sampled_at),
      policy: {
        idleTimeoutSeconds: Math.max(0, perfFinite(
          policy.idleTimeoutSeconds,
          policy.idle_timeout_seconds,
        ) || 0),
        terminationGraceSeconds: Math.max(0, perfFinite(
          policy.terminationGraceSeconds,
          policy.termination_grace_seconds,
        ) || 0),
      },
      totals: {
        sessionCount: Math.max(0, perfFinite(totals.sessionCount, totals.session_count) || 0),
        processCount: Math.max(0, perfFinite(totals.processCount, totals.process_count) || 0),
        idleSessionCount: Math.max(0, perfFinite(
          totals.idleSessionCount,
          totals.idle_session_count,
        ) || 0),
        protectedSessionCount: Math.max(0, perfFinite(
          totals.protectedSessionCount,
          totals.protected_session_count,
        ) || 0),
        reapedTotal: Math.max(0, perfFinite(totals.reapedTotal, totals.reaped_total) || 0),
        reclaimedMemoryBytes: Math.max(0, perfFinite(
          totals.reclaimedMemoryBytes,
          totals.reclaimed_memory_bytes,
        ) || 0),
      },
      sessions,
      recentReaps,
    };
  }

  function perfValues(rawSegments) {
    const values = new Map();
    for (const raw of Array.isArray(rawSegments) ? rawSegments : []) {
      if (raw?.key === null || raw?.key === undefined) continue;
      values.set(String(raw.key), {
        value: Math.max(0, perfFinite(raw.value, raw.stackValue, raw.stack_value) || 0),
        observedValue: Math.max(0, perfFinite(raw.observedValue, raw.observed_value,
          raw.value, raw.stackValue, raw.stack_value) || 0),
        exact: raw.exact === true,
      });
    }
    return values;
  }

  function coherentPerformanceModel(performance) {
    const host = state.metrics?.host || {};
    const memory = performance.memory || {};
    const cpu = performance.cpu || {};
    const cores = Math.max(1, perfFinite(cpu.cores, host.cores) || 1);
    const rawSegments = Array.isArray(performance.segments) ? performance.segments : [];
    const segments = rawSegments
      .filter((segment) => segment?.key !== null && segment?.key !== undefined)
      .map((segment) => {
        const kind = perfSegmentKind(segment.kind);
        const project = kind === 'project-family' || kind === 'project';
        const current = segment.current || {};
        const peak = segment.peak || {};
        const key = String(segment.key);
        let memoryObserved = perfFinite(current.memoryBytes, current.memory_bytes);
        let memoryStack = perfFinite(current.stackMemoryBytes, current.stack_memory_bytes,
          memoryObserved);
        let cpuObserved = perfFinite(current.cpuPercent, current.cpu_percent);
        let cpuStack = perfFinite(current.stackCpuPercent, current.stack_cpu_percent,
          cpuObserved);
        if (kind === 'system-unclassified') {
          memoryObserved = perfFinite(memoryObserved, memory.residualBytes, memory.residual_bytes);
          memoryStack = perfFinite(memoryStack, memory.residualBytes, memory.residual_bytes);
          cpuObserved = perfFinite(cpuObserved, cpu.residualPercent, cpu.residual_percent);
          cpuStack = perfFinite(cpuStack, cpu.residualPercent, cpu.residual_percent);
        } else if (kind === 'available') {
          memoryObserved = perfFinite(memoryObserved, memory.availableBytes, memory.available_bytes);
          memoryStack = perfFinite(memoryStack, memory.availableBytes, memory.available_bytes);
          cpuObserved = perfFinite(cpuObserved, cpu.availablePercent, cpu.available_percent);
          cpuStack = perfFinite(cpuStack, cpu.availablePercent, cpu.available_percent);
        }
        return {
          key,
          kind,
          project,
          familyId: segment.familyId ?? segment.family_id ?? null,
          repoId: segment.repoId ?? segment.repo_id ?? null,
          name: perfSegmentName(segment, kind),
          path: segment.project || null,
          active: segment.active !== false,
          additive: segment.additive !== false,
          exact: segment.exact === true,
          fresh: segment.fresh !== false,
          sampledAt: perfEpochMs(segment.sampledAt ?? segment.sampled_at),
          color: project ? null : PERFORMANCE_CATEGORY_COLORS[kind],
          memoryObserved: Math.max(0, memoryObserved || 0),
          memoryStack: Math.max(0, memoryStack || 0),
          cpuObserved: Math.max(0, cpuObserved || 0),
          cpuStack: Math.max(0, cpuStack || 0),
          cpuRaw: Math.max(0, perfFinite(current.cpuRawPercent, current.cpu_raw_percent) || 0),
          memoryPeak: Math.max(0, perfFinite(peak.memoryBytes, peak.memory_bytes,
            memoryObserved) || 0),
          cpuPeak: Math.max(0, perfFinite(peak.cpuPercent, peak.cpu_percent,
            cpuObserved) || 0),
          agentBrowsers: kind === 'agent-browsers'
            ? perfAgentBrowserInventory(segment) : null,
          accounting: segment.accounting && typeof segment.accounting === 'object'
            ? segment.accounting : null,
          contributors: (Array.isArray(segment.contributors) ? segment.contributors : [])
            .map((item) => perfContributor(item, cores)),
        };
      });
    assignPerformanceProjectColors(segments);
    const samples = (Array.isArray(performance.samples) ? performance.samples : [])
      .map((sample) => ({
        at: perfEpochMs(sample?.at ?? sample?.sampledAt ?? sample?.sampled_at),
        sampleSkewMs: Math.max(0, perfFinite(sample?.sampleSkewMs, sample?.sample_skew_ms) || 0),
        exact: sample?.exact === true,
        memory: {
          total: Math.max(0, perfFinite(sample?.memory?.totalBytes,
            sample?.memory?.total_bytes, memory.totalBytes, memory.total_bytes) || 0),
          used: Math.max(0, perfFinite(sample?.memory?.usedBytes,
            sample?.memory?.used_bytes, memory.usedBytes, memory.used_bytes) || 0),
          values: perfValues(sample?.memory?.segments),
        },
        cpu: {
          total: Math.max(0, perfFinite(sample?.cpu?.capacityPercent,
            sample?.cpu?.capacity_percent, cpu.capacityPercent, cpu.capacity_percent, 100) || 100),
          used: Math.max(0, perfFinite(sample?.cpu?.usedPercent,
            sample?.cpu?.used_percent, cpu.usedPercent, cpu.used_percent) || 0),
          values: perfValues(sample?.cpu?.segments),
        },
      }))
      .filter((sample) => sample.at !== null)
      .sort((a, b) => a.at - b.at);
    if (!samples.length) {
      const at = perfEpochMs(performance.sampledAt ?? performance.sampled_at) || Date.now();
      samples.push({
        at,
        sampleSkewMs: Math.max(0, perfFinite(performance.sampleSkewMs,
          performance.sample_skew_ms) || 0),
        exact: performance.exact === true,
        memory: {
          total: Math.max(0, perfFinite(memory.totalBytes, memory.total_bytes) || 0),
          used: Math.max(0, perfFinite(memory.usedBytes, memory.used_bytes) || 0),
          values: new Map(segments.map((segment) => [segment.key, {
            value: segment.memoryStack, observedValue: segment.memoryObserved, exact: segment.exact,
          }])),
        },
        cpu: {
          total: Math.max(0, perfFinite(cpu.capacityPercent, cpu.capacity_percent, 100) || 100),
          used: Math.max(0, perfFinite(cpu.usedPercent, cpu.used_percent) || 0),
          values: new Map(segments.map((segment) => [segment.key, {
            value: segment.cpuStack, observedValue: segment.cpuObserved, exact: segment.exact,
          }])),
        },
      });
    }
    const latestSample = samples.at(-1);
    for (const segment of segments) {
      const memoryValue = latestSample.memory.values.get(segment.key);
      const cpuValue = latestSample.cpu.values.get(segment.key);
      if (memoryValue) {
        segment.memoryStack = memoryValue.value;
        segment.memoryObserved = memoryValue.observedValue;
      } else if (segment.active === false) {
        segment.memoryStack = 0;
        segment.memoryObserved = 0;
      }
      if (cpuValue) {
        segment.cpuStack = cpuValue.value;
        segment.cpuObserved = cpuValue.observedValue;
      } else if (segment.active === false) {
        segment.cpuStack = 0;
        segment.cpuObserved = 0;
      }
      if (segment.active === false) segment.fresh = false;
    }
    const projects = segments.filter((segment) => segment.project);
    for (const segment of segments.filter((item) => (
      item.project || item.kind === 'agent-browsers'
    ))) {
      segment.history = samples.map((sample) => ({
        at: sample.at,
        cpu: sample.cpu.values.get(segment.key)?.observedValue ?? 0,
        memory: sample.memory.values.get(segment.key)?.observedValue ?? 0,
      }));
    }
    const coverage = performance.coverage || {};
    const sampledAt = perfEpochMs(performance.sampledAt ?? performance.sampled_at)
      || samples.at(-1)?.at || null;
    return {
      source: 'coherent',
      exact: performance.exact === true,
      issues: Array.isArray(performance.issues) ? performance.issues : [],
      semantics: performance.semantics || {},
      sampledAt,
      sampleSkewMs: Math.max(0, perfFinite(performance.sampleSkewMs,
        performance.sample_skew_ms) || 0),
      window: performance.window || {},
      diagnostics: performance.residual?.diagnostics || host.mem?.diagnostics || null,
      memoryBasis: memory.basis || null,
      host: {
        cores,
        cpuUsed: Math.max(0, perfFinite(cpu.usedPercent, cpu.used_percent,
          host.cpuPercent) || 0),
        cpuAvailable: Math.max(0, perfFinite(cpu.availablePercent, cpu.available_percent,
          100 - (perfFinite(cpu.usedPercent, cpu.used_percent, host.cpuPercent) || 0)) || 0),
        load: Array.isArray(host.load) ? host.load : [],
        memoryTotal: Math.max(0, perfFinite(memory.totalBytes, memory.total_bytes,
          host.mem?.totalBytes) || 0),
        memoryUsed: Math.max(0, perfFinite(memory.usedBytes, memory.used_bytes,
          host.mem?.usedBytes) || 0),
        memoryAvailable: Math.max(0, perfFinite(memory.availableBytes, memory.available_bytes,
          host.mem?.availableBytes) || 0),
        disks: Array.isArray(host.disks) ? host.disks : [],
        uptimeSec: perfFinite(host.uptimeSec),
      },
      attributed: {
        memory: Math.max(0, perfFinite(performance.attributed?.memoryBytes,
          performance.attributed?.memory_bytes, memory.attributedBytes,
          memory.attributed_bytes) || 0),
        cpu: Math.max(0, perfFinite(performance.attributed?.cpuPercent,
          performance.attributed?.cpu_percent, cpu.attributedPercent,
          cpu.attributed_percent) || 0),
      },
      coverage: {
        memory: perfCoveragePercent(coverage.memoryRatio ?? coverage.memory_ratio
          ?? memory.coverageRatio ?? memory.coverage_ratio),
        cpu: perfCoveragePercent(coverage.cpuRatio ?? coverage.cpu_ratio
          ?? cpu.coverageRatio ?? cpu.coverage_ratio),
        measured: perfFinite(coverage.measuredResources, coverage.measured_resources),
        expected: perfFinite(coverage.expectedResources, coverage.expected_resources),
        missing: perfFinite(coverage.missingResources, coverage.missing_resources),
        stale: perfFinite(coverage.staleResources, coverage.stale_resources),
      },
      segments,
      projects,
      samples,
    };
  }

  function legacyPerfPointAt(points, at) {
    if (!points?.length) return null;
    let low = 0;
    let high = points.length - 1;
    let found = -1;
    while (low <= high) {
      const middle = Math.floor((low + high) / 2);
      if ((perfEpochMs(points[middle]?.[0]) || 0) <= at) {
        found = middle;
        low = middle + 1;
      } else {
        high = middle - 1;
      }
    }
    return found >= 0 ? points[found] : points[0];
  }

  function legacyPerfContributors(group, cores) {
    if (!group) return [];
    const contributors = [];
    for (const server of group.members?.servers || []) {
      if (!server?.process_usage) continue;
      contributors.push(perfContributor({
        key: 'srv:' + server.id,
        kind: 'server',
        id: server.id,
        name: server.name || server.id,
        memoryBytes: server.process_usage.memory_bytes ?? server.process_usage.rss_bytes,
        cpuRawPercent: server.process_usage.cpu_percent,
        cpuPercent: (Number(server.process_usage.cpu_percent) || 0) / Math.max(1, cores),
        exact: false,
      }, cores));
    }
    for (const container of group.members?.containers || []) {
      if (!container?.stats) continue;
      contributors.push(perfContributor({
        key: 'dock:' + container.name,
        kind: 'docker',
        id: container.id,
        name: container.name,
        memoryBytes: container.stats.memory_usage_bytes,
        cpuRawPercent: container.stats.cpu_percent,
        cpuPercent: (Number(container.stats.cpu_percent) || 0) / Math.max(1, cores),
        exact: false,
      }, cores));
    }
    return contributors;
  }

  function legacyPerformanceModel(o) {
    const metrics = state.metrics || {};
    const host = metrics.host || {};
    const hostEntity = metricsEntity('host');
    const cores = Math.max(1, perfFinite(host.cores) || 1);
    const authoritativeGroups = Array.isArray(o?.inventory?.repository_trees)
      ? projectGroupsOf(o).filter((group) => group.row) : [];
    let projectDefs = authoritativeGroups.map((group) => ({
      key: group.metricsKey,
      name: group.name,
      path: group.project,
      active: group.runningCount > 0,
      row: group.row,
      group,
      entity: metricsEntity(group.metricsKey),
    }));
    if (!projectDefs.length) {
      const entities = Array.isArray(metrics.entities) ? metrics.entities : [];
      let candidates = entities.filter((entity) => entity.kind === 'project-family');
      if (!candidates.length) candidates = entities.filter((entity) => entity.kind === 'project');
      projectDefs = candidates.map((entity) => ({
        key: entity.key,
        name: entity.name || projectTail(entity.project) || entity.key,
        path: entity.project,
        active: true,
        row: null,
        group: null,
        entity,
      }));
    }
    const projects = projectDefs.map((definition) => {
      const points = Array.isArray(definition.entity?.points) ? definition.entity.points : [];
      const last = points.at(-1);
      const currentCpuRaw = Math.max(0, perfFinite(definition.row?.cpu_percent, last?.[1]) || 0);
      const currentMemory = Math.max(0, perfFinite(definition.row?.memory_bytes, last?.[2]) || 0);
      const history = points.map((point) => ({
        at: perfEpochMs(point[0]) || 0,
        cpu: Math.max(0, (Number(point[1]) || 0) / cores),
        memory: Math.max(0, Number(point[2]) || 0),
      })).filter((point) => point.at > 0);
      return {
        key: String(definition.key),
        kind: definition.key.startsWith('family:') ? 'project-family' : 'project',
        project: true,
        familyId: definition.key.startsWith('family:') ? definition.key.slice(7) : null,
        repoId: definition.group?.repoId ?? null,
        name: definition.name,
        path: definition.path || null,
        active: definition.active,
        exact: false,
        fresh: true,
        sampledAt: perfEpochMs(last?.[0]),
        color: null,
        memoryObserved: currentMemory,
        memoryStack: currentMemory,
        cpuObserved: currentCpuRaw / cores,
        cpuStack: currentCpuRaw / cores,
        cpuRaw: currentCpuRaw,
        memoryPeak: Math.max(currentMemory, ...history.map((point) => point.memory)),
        cpuPeak: Math.max(currentCpuRaw / cores, ...history.map((point) => point.cpu)),
        contributors: legacyPerfContributors(definition.group, cores),
        history,
        rawPoints: points,
      };
    });
    assignPerformanceProjectColors(projects);
    const memoryTotal = Math.max(0, perfFinite(host.mem?.totalBytes) || 0);
    const hostPoints = Array.isArray(hostEntity?.points) ? hostEntity.points : [];
    const samplePoints = hostPoints.length ? hostPoints : [[
      perfEpochMs(host.at) || Date.now(),
      perfFinite(host.cpuPercent) || 0,
      perfFinite(host.mem?.usedBytes) || 0,
    ]];
    let sampleSkewMs = 0;
    const samples = samplePoints.map((hostPoint) => {
      const at = perfEpochMs(hostPoint[0]) || Date.now();
      const memoryUsed = perfBound(hostPoint[2], 0, memoryTotal || Number.MAX_SAFE_INTEGER);
      const cpuUsed = perfBound(hostPoint[1], 0, 100);
      const projectValues = projects.map((project) => {
        const point = legacyPerfPointAt(project.rawPoints, at);
        const pointAt = perfEpochMs(point?.[0]);
        if (pointAt !== null) sampleSkewMs = Math.max(sampleSkewMs, Math.abs(at - pointAt));
        return {
          project,
          memory: Math.max(0, Number(point?.[2]) || 0),
          cpu: Math.max(0, (Number(point?.[1]) || 0) / cores),
        };
      });
      const observedMemory = projectValues.reduce((sum, item) => sum + item.memory, 0);
      const observedCpu = projectValues.reduce((sum, item) => sum + item.cpu, 0);
      const memoryScale = observedMemory > memoryUsed && observedMemory > 0
        ? memoryUsed / observedMemory : 1;
      const cpuScale = observedCpu > cpuUsed && observedCpu > 0 ? cpuUsed / observedCpu : 1;
      const memoryValues = new Map();
      const cpuValues = new Map();
      for (const item of projectValues) {
        memoryValues.set(item.project.key, {
          value: item.memory * memoryScale, observedValue: item.memory, exact: false,
        });
        cpuValues.set(item.project.key, {
          value: item.cpu * cpuScale, observedValue: item.cpu, exact: false,
        });
      }
      memoryValues.set('system-unclassified', {
        value: Math.max(0, memoryUsed - observedMemory * memoryScale),
        observedValue: Math.max(0, memoryUsed - observedMemory),
        exact: false,
      });
      memoryValues.set('available', {
        value: Math.max(0, memoryTotal - memoryUsed),
        observedValue: Math.max(0, memoryTotal - memoryUsed),
        exact: true,
      });
      cpuValues.set('system-unclassified', {
        value: Math.max(0, cpuUsed - observedCpu * cpuScale),
        observedValue: Math.max(0, cpuUsed - observedCpu),
        exact: false,
      });
      cpuValues.set('available', {
        value: Math.max(0, 100 - cpuUsed),
        observedValue: Math.max(0, 100 - cpuUsed),
        exact: true,
      });
      return {
        at,
        sampleSkewMs,
        exact: false,
        memory: { total: memoryTotal, used: memoryUsed, values: memoryValues },
        cpu: { total: 100, used: cpuUsed, values: cpuValues },
      };
    });
    const latest = samples.at(-1);
    for (const project of projects) {
      project.memoryStack = latest?.memory.values.get(project.key)?.value ?? project.memoryObserved;
      project.cpuStack = latest?.cpu.values.get(project.key)?.value ?? project.cpuObserved;
      delete project.rawPoints;
    }
    const system = {
      key: 'system-unclassified',
      kind: 'system-unclassified',
      project: false,
      name: 'Estimated System & unattributed',
      color: PERFORMANCE_CATEGORY_COLORS['system-unclassified'],
      exact: false,
      fresh: true,
      memoryObserved: latest?.memory.values.get('system-unclassified')?.observedValue || 0,
      memoryStack: latest?.memory.values.get('system-unclassified')?.value || 0,
      cpuObserved: latest?.cpu.values.get('system-unclassified')?.observedValue || 0,
      cpuStack: latest?.cpu.values.get('system-unclassified')?.value || 0,
      memoryPeak: Math.max(0, ...samples.map((sample) =>
        sample.memory.values.get('system-unclassified')?.value || 0)),
      cpuPeak: Math.max(0, ...samples.map((sample) =>
        sample.cpu.values.get('system-unclassified')?.value || 0)),
      contributors: [],
    };
    const available = {
      key: 'available',
      kind: 'available',
      project: false,
      name: 'Available',
      color: PERFORMANCE_CATEGORY_COLORS.available,
      exact: true,
      fresh: true,
      memoryObserved: latest?.memory.values.get('available')?.value || 0,
      memoryStack: latest?.memory.values.get('available')?.value || 0,
      cpuObserved: latest?.cpu.values.get('available')?.value || 0,
      cpuStack: latest?.cpu.values.get('available')?.value || 0,
      memoryPeak: Math.max(0, ...samples.map((sample) =>
        sample.memory.values.get('available')?.value || 0)),
      cpuPeak: Math.max(0, ...samples.map((sample) =>
        sample.cpu.values.get('available')?.value || 0)),
      contributors: [],
    };
    const attributedMemory = projects.reduce((sum, project) => sum + project.memoryObserved, 0);
    const attributedCpu = projects.reduce((sum, project) => sum + project.cpuObserved, 0);
    const memoryUsed = latest?.memory.used || 0;
    const cpuUsed = latest?.cpu.used || 0;
    return {
      source: 'legacy',
      exact: false,
      issues: ['Host and project readings do not share a proven sample boundary.'],
      semantics: {},
      sampledAt: perfEpochMs(metrics.sampler?.lastSampleAt ?? host.at) || latest?.at || null,
      sampleSkewMs,
      window: {
        startAt: samples[0]?.at || null,
        endAt: latest?.at || null,
        intervalMs: metrics.intervalMs || METRICS_POLL_MS,
      },
      diagnostics: host.mem?.diagnostics || null,
      memoryBasis: host.mem?.basis || null,
      host: {
        cores,
        cpuUsed,
        cpuAvailable: Math.max(0, 100 - cpuUsed),
        load: Array.isArray(host.load) ? host.load : [],
        memoryTotal,
        memoryUsed,
        memoryAvailable: Math.max(0, memoryTotal - memoryUsed),
        disks: Array.isArray(host.disks) ? host.disks : [],
        uptimeSec: perfFinite(host.uptimeSec),
      },
      attributed: { memory: attributedMemory, cpu: attributedCpu },
      coverage: {
        memory: memoryUsed > 0 ? perfBound(attributedMemory / memoryUsed * 100, 0, 100) : 0,
        cpu: cpuUsed > 0 ? perfBound(attributedCpu / cpuUsed * 100, 0, 100) : 0,
        measured: projects.length,
        expected: projects.length,
        missing: 0,
        stale: 0,
      },
      segments: [...projects, system, available],
      projects,
      samples,
    };
  }

  function performanceModel(o = state.overview) {
    const performance = state.metrics?.performance;
    if (performance && Array.isArray(performance.segments)) {
      return coherentPerformanceModel(performance);
    }
    if (!state.metrics) return null;
    return legacyPerformanceModel(o);
  }

  function performanceProjectCount(o = state.overview) {
    if (!state.metrics) return null;
    return performanceModel(o)?.projects.length ?? 0;
  }

  function perfDownsample(samples, limit = 72) {
    if (samples.length <= limit) return samples;
    const selected = [];
    for (let index = 0; index < limit; index += 1) {
      const sourceIndex = Math.round(index * (samples.length - 1) / (limit - 1));
      selected.push(samples[sourceIndex]);
    }
    return selected;
  }

  function perfSegmentValue(segment, metric, stack = true) {
    if (metric === 'memory') {
      return stack ? segment.memoryStack : segment.memoryObserved;
    }
    return stack ? segment.cpuStack : segment.cpuObserved;
  }

  function perfSegmentPeak(model, segment, metric) {
    if (segment.project) {
      return metric === 'memory' ? segment.memoryPeak : segment.cpuPeak;
    }
    const values = model.samples.map((sample) => {
      const value = sample[metric].values.get(segment.key);
      return segment.additive === false ? value?.observedValue || 0 : value?.value || 0;
    });
    return Math.max(perfSegmentValue(segment, metric, segment.additive !== false), ...values);
  }

  function perfMetricText(metric, value) {
    return metric === 'memory' ? fmtBytes(value || 0) : perfPercent(value || 0);
  }

  function performanceStackedChart(model, metric, id) {
    const width = 1000;
    const height = 220;
    const samples = perfDownsample(model.samples);
    const segments = model.segments.filter((segment) => segment.additive !== false
      && (metric === 'memory' || segment.kind !== 'available'));
    const svg = svgEl('svg', {
      id,
      class: 'perf-stacked-chart',
      viewBox: '0 0 ' + width + ' ' + height,
      preserveAspectRatio: 'none',
      role: 'img',
      'data-performance-metric': metric,
    });
    const title = svgEl('title');
    title.textContent = metric === 'memory'
      ? 'Whole-host memory composition for the last 60 minutes'
      : 'Whole-host CPU composition normalized to host capacity for the last 60 minutes';
    const description = svgEl('desc');
    description.textContent = metric === 'memory'
      ? 'Each bar adds disjoint project, Coordinator, test, developer-session, residual, and available host categories exactly once. Focusing a non-additive drilldown draws only its exact observed history as a temporary overlay.'
      : 'Each bar adds disjoint measured or residual host work against one hundred percent of total host CPU capacity. Focusing a non-additive drilldown draws only its exact observed history as a temporary overlay.';
    svg.append(title, description);
    for (const ratio of [0, .25, .5, .75, 1]) {
      const y = height - ratio * height;
      svg.append(svgEl('line', {
        class: 'perf-chart-grid', x1: 0, y1: y, x2: width, y2: y,
      }));
    }
    const drilldownLayer = svgEl('g', {
      class: 'perf-drilldown-layer',
      'aria-hidden': 'true',
      'data-performance-drilldown-layer': metric,
    });
    if (!samples.length) {
      svg.append(drilldownLayer);
      return svg;
    }
    const slot = width / samples.length;
    const barWidth = Math.max(1.4, slot - Math.min(4, slot * .28));
    samples.forEach((sample, index) => {
      const total = Math.max(1, Number(sample[metric].total) || (metric === 'cpu' ? 100 : 1));
      let stack = 0;
      for (const segment of segments) {
        const raw = Math.max(0, sample[metric].values.get(segment.key)?.value || 0);
        const value = Math.min(raw, Math.max(0, total - stack));
        if (value <= 0) continue;
        const rectHeight = value / total * height;
        const rect = svgEl('rect', {
          class: 'perf-stack-segment perf-stack-' + segment.kind,
          x: (index * slot + (slot - barWidth) / 2).toFixed(2),
          y: (height - (stack + value) / total * height).toFixed(2),
          width: barWidth.toFixed(2),
          height: Math.max(.7, rectHeight).toFixed(2),
          'data-performance-segment': segment.key,
          'data-performance-series-role': 'stack',
          'data-performance-value': String(value),
          'data-performance-total': String(total),
          'data-performance-sampled-at': String(sample.at),
          'data-performance-key': segment.project ? segment.key : null,
        });
        rect.style.fill = segment.color;
        svg.append(rect);
        stack += value;
      }
    });
    svg.append(drilldownLayer);
    return svg;
  }

  function renderPerformanceDrilldownOverlay(chart, model, metric, key) {
    const layer = chart?.querySelector('[data-performance-drilldown-layer]');
    if (!layer) return false;
    layer.replaceChildren();
    const segment = model?.segments?.find((candidate) => (
      candidate.key === key && candidate.additive === false
    ));
    if (!segment) return false;
    const samples = Array.isArray(model.samples) ? model.samples : [];
    if (!samples.length) return false;
    const width = 1000;
    const height = 220;
    const slot = width / samples.length;
    const barWidth = Math.max(.8, slot - Math.min(1.2, slot * .18));
    let rendered = 0;
    samples.forEach((sample, index) => {
      const total = Math.max(1, Number(sample?.[metric]?.total)
        || (metric === 'cpu' ? 100 : 1));
      const observed = Math.max(0,
        Number(sample?.[metric]?.values?.get(key)?.observedValue) || 0);
      if (observed <= 0) return;
      const visibleValue = Math.min(observed, total);
      const rectHeight = visibleValue / total * height;
      if (rectHeight <= 0) return;
      const rect = svgEl('rect', {
        class: 'perf-drilldown-segment',
        x: (index * slot + (slot - barWidth) / 2).toFixed(4),
        y: (height - rectHeight).toFixed(4),
        width: barWidth.toFixed(4),
        height: rectHeight.toFixed(4),
        'data-performance-segment': segment.key,
        'data-performance-series-role': 'drilldown',
        'data-performance-value': String(observed),
        'data-performance-visible-value': String(visibleValue),
        'data-performance-total': String(total),
        'data-performance-sampled-at': String(sample.at),
      });
      rect.style.fill = segment.color;
      rect.style.stroke = segment.color;
      layer.append(rect);
      rendered += 1;
    });
    return rendered > 0;
  }

  function performanceSampleTable(model, metric) {
    const segments = model.segments.filter((segment) => segment.additive !== false
      && (metric === 'memory' || segment.kind !== 'available'));
    const table = h('table', { class: 'perf-chart-data-table' },
      h('caption', { class: 'visually-hidden' },
        'Exact ' + metric + ' values for every retained performance sample'),
      h('thead', null,
        h('tr', null,
          h('th', { scope: 'col' }, 'Sample time'),
          segments.map((segment) =>
            h('th', { scope: 'col' }, segment.name)),
          h('th', { scope: 'col' }, 'Host used'),
          h('th', { scope: 'col' }, metric === 'memory' ? 'Host total' : 'Host capacity'))),
      h('tbody', null, model.samples.map((sample) => {
        const date = new Date(sample.at);
        const validTime = Number.isFinite(date.getTime());
        const exactTime = validTime ? date.toISOString() : String(sample.at);
        const localTime = validTime ? date.toLocaleString([], {
          year: 'numeric',
          month: 'short',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          fractionalSecondDigits: 3,
          timeZoneName: 'short',
        }) : 'Unavailable';
        return h('tr', {
          'data-performance-sample': String(sample.at),
          'data-performance-exact': String(sample.exact === true),
        },
          h('th', { scope: 'row' },
            h('time', { datetime: exactTime }, localTime)),
          segments.map((segment) => h('td', {
            class: 'mono',
            'data-performance-table-segment': segment.key,
          }, perfMetricText(metric, sample[metric].values.get(segment.key)?.value || 0))),
          h('td', { class: 'mono' }, perfMetricText(metric, sample[metric].used)),
          h('td', { class: 'mono' }, perfMetricText(metric, sample[metric].total)));
      })));
    return table;
  }

  function performanceSampleDisclosure(model, metric) {
    const summaryText = metric === 'memory'
      ? 'Exact memory sample data'
      : 'Exact CPU sample data';
    const regionLabel = metric === 'memory'
      ? 'Exact memory sample values'
      : 'Exact CPU sample values';
    const disclosureKey = 'performance-' + metric + '-sample-data';
    const scroll = h('div', {
      class: 'perf-chart-data-scroll',
      role: 'region',
      tabindex: '0',
      'aria-label': regionLabel,
    });
    let populated = false;
    const details = h('details', {
      class: 'perf-chart-data',
      'data-performance-data-table': metric,
      'data-section-disclosure': disclosureKey,
    },
      h('summary', null, summaryText),
      scroll);
    details.addEventListener('toggle', () => {
      if (!details.open || populated) return;
      scroll.replaceChildren(performanceSampleTable(model, metric));
      populated = true;
    });
    if (ui.sectionDisclosures.get('perf-body\u0000' + disclosureKey) === true) {
      scroll.replaceChildren(performanceSampleTable(model, metric));
      populated = true;
    }
    return details;
  }

  function performanceLegendRow(model, segment, metric) {
    const current = perfSegmentValue(segment, metric, segment.additive !== false);
    const peak = perfSegmentPeak(model, segment, metric);
    const actionable = segment.project || segment.kind === 'agent-browsers';
    const emphasisKey = segment.key;
    const common = [
      h('span', { class: 'perf-legend-swatch', 'aria-hidden': 'true' }),
      h('span', { class: 'perf-legend-name', title: segment.name }, segment.name),
      h('span', { class: 'perf-legend-value mono' }, perfMetricText(metric, current)),
      h('span', { class: 'perf-legend-value mono perf-legend-peak' },
        h('span', { class: 'perf-legend-mobile-label' }, 'Peak '),
        perfMetricText(metric, peak)),
    ];
    common[0].style.backgroundColor = segment.color;
    const attrs = {
      class: (actionable ? 'perf-legend-button' : 'perf-legend-item')
        + (segment.exact ? '' : ' is-estimated')
        + (segment.fresh === false ? ' is-stale' : '')
        + (segment.additive === false ? ' is-nonadditive' : ''),
      'data-performance-segment': segment.key,
      'data-performance-kind': segment.kind,
      'data-performance-additive': String(segment.additive !== false),
    };
    if (!actionable) return h('div', attrs, common);
    return h('button', {
      ...attrs,
      type: 'button',
      'data-performance-key': segment.key,
      'data-performance-emphasis-key': emphasisKey,
      'data-performance-metric': metric,
      'data-fk': 'performance:' + metric + ':' + segment.key,
      'aria-haspopup': 'dialog',
      'aria-controls': 'perf-project-dialog',
      'aria-label': segment.name + ', current ' + perfMetricText(metric, current)
        + ', peak ' + perfMetricText(metric, peak)
        + (segment.additive === false ? '. Drilldown only; already represented in the host stack.' : '')
        + '. Open performance details.',
      onpointerenter: (event) => {
        if (event.pointerType !== 'touch') {
          setPerformanceSeriesEmphasis(model, metric, emphasisKey, 'hover', true);
        }
      },
      onpointerleave: (event) => {
        if (event.pointerType !== 'touch') {
          setPerformanceSeriesEmphasis(model, metric, emphasisKey, 'hover', false);
        }
      },
      onfocus: () => setPerformanceSeriesEmphasis(model, metric, emphasisKey, 'focus', true),
      onblur: () => setPerformanceSeriesEmphasis(model, metric, emphasisKey, 'focus', false),
      onclick: (event) => {
        clearPerformanceSeriesEmphasis(model, metric);
        openPerformanceProject(segment.key, event.currentTarget);
      },
    }, common);
  }

  const performanceSeriesEmphasis = new Map();

  function renderPerformanceSeriesEmphasis(model, metric) {
    const chart = document.getElementById('perf-' + metric + '-chart');
    if (!chart) return;
    const state = performanceSeriesEmphasis.get(metric);
    const requestedKey = state?.hover || state?.focus || null;
    const selected = model?.segments?.find((segment) => segment.key === requestedKey);
    const drilldown = selected?.additive === false;
    const hasDrilldownSeries = requestedKey && drilldown
      ? renderPerformanceDrilldownOverlay(chart, model, metric, requestedKey)
      : false;
    if (!drilldown) {
      chart.querySelector('[data-performance-drilldown-layer]')?.replaceChildren();
    }
    const key = drilldown && !hasDrilldownSeries ? null : requestedKey;
    const segments = chart.querySelectorAll('[data-performance-segment]');
    if (key) chart.dataset.highlightedSegment = key;
    else delete chart.dataset.highlightedSegment;
    for (const segment of segments) {
      const matching = Boolean(key) && segment.dataset.performanceSegment === key;
      segment.classList.toggle('is-series-highlighted', matching);
      segment.classList.toggle('is-series-dimmed', Boolean(key) && !matching);
    }
  }

  function setPerformanceSeriesEmphasis(model, metric, key, source, active) {
    const emphasis = performanceSeriesEmphasis.get(metric) || { hover: null, focus: null };
    if (active) emphasis[source] = key;
    else if (emphasis[source] === key) emphasis[source] = null;
    if (emphasis.hover || emphasis.focus) performanceSeriesEmphasis.set(metric, emphasis);
    else performanceSeriesEmphasis.delete(metric);
    renderPerformanceSeriesEmphasis(model, metric);
  }

  function clearPerformanceSeriesEmphasis(model, metric) {
    performanceSeriesEmphasis.delete(metric);
    renderPerformanceSeriesEmphasis(model, metric);
  }

  function performanceLegend(model, metric, id) {
    const projects = model.segments.filter((segment) => segment.project);
    const categories = model.segments.filter((segment) => !segment.project
      && segment.additive !== false
      && (metric === 'memory' || segment.kind !== 'available'));
    const drilldowns = model.segments.filter((segment) => !segment.project
      && segment.additive === false
      && (segment.kind === 'agent-browsers' || segment.kind === 'control-other'));
    const body = [
      h('div', { class: 'perf-legend-columns', 'aria-hidden': 'true' },
        h('span', null),
        h('span', null),
        h('span', null, 'Current'),
        h('span', null, 'Peak (60 min)')),
      h('p', { class: 'perf-legend-group' }, 'Host stack · disjoint categories'),
    ];
    if (categories.length) {
      body.push(...categories.map((segment) => performanceLegendRow(model, segment, metric)));
    }
    if (projects.length) {
      body.push(h('p', { class: 'perf-legend-group perf-legend-reconcile' },
        'Repository drilldown · included in Project runtimes'));
      body.push(...projects.map((segment) => performanceLegendRow(model, segment, metric)));
    }
    if (drilldowns.length) {
      body.push(h('p', { class: 'perf-legend-group perf-legend-reconcile' },
        'Measured drilldowns · included above'));
      body.push(...drilldowns.map((segment) => performanceLegendRow(model, segment, metric)));
    }
    return h('div', {
      id,
      class: 'perf-legend',
      'aria-label': (metric === 'memory' ? 'Memory' : 'CPU') + ' project and accounting legend',
    }, body);
  }

  function perfAxisValue(metric, total, ratio) {
    return metric === 'memory' ? fmtBytes(total * ratio) : perfPercent(total * ratio, 0);
  }

  function performanceCompositionPanel(model, metric) {
    const memory = metric === 'memory';
    const latest = model.samples.at(-1);
    const total = latest?.[metric].total || (memory ? model.host.memoryTotal : 100);
    const current = latest?.[metric].used || (memory ? model.host.memoryUsed : model.host.cpuUsed);
    const peak = Math.max(current || 0, ...model.samples.map((sample) => sample[metric].used || 0));
    const firstAt = model.samples[0]?.at;
    const middleAt = model.samples[Math.floor(model.samples.length / 2)]?.at;
    const lastAt = latest?.at;
    const chartId = memory ? 'perf-memory-chart' : 'perf-cpu-chart';
    const legendId = memory ? 'perf-legend' : 'perf-cpu-legend';
    return h('section', {
      id: memory ? 'perf-memory-panel' : 'perf-cpu-panel',
      class: 'perf-composition-panel',
      'aria-labelledby': (memory ? 'perf-memory-title' : 'perf-cpu-title'),
    },
      h('div', { class: 'perf-panel-head' },
        h('div', null,
          h('h3', { id: memory ? 'perf-memory-title' : 'perf-cpu-title' },
            memory
              ? 'Memory composition — Host used (not immediately available)'
              : 'CPU load — normalized to host capacity'),
          h('p', null, memory
            ? 'Disjoint host workload roots + estimated residual + available = host total.'
            : 'Disjoint workload CPU is normalized to host capacity; unused capacity remains visible as headroom.')),
        h('div', { class: 'perf-panel-totals' },
          h('span', null, 'Current ', h('strong', { class: 'mono' }, perfMetricText(metric, current))),
          h('span', null, 'Peak ', h('strong', { class: 'mono' }, perfMetricText(metric, peak))))),
      h('div', { class: 'perf-panel-body' },
        h('div', { class: 'perf-chart-region' },
          h('div', { class: 'perf-chart-y', 'aria-hidden': 'true' },
            h('span', null, perfAxisValue(metric, total, 1)),
            h('span', null, perfAxisValue(metric, total, .75)),
            h('span', null, perfAxisValue(metric, total, .5)),
            h('span', null, perfAxisValue(metric, total, .25)),
            h('span', null, perfAxisValue(metric, total, 0))),
          h('div', { class: 'perf-chart-column' },
            performanceStackedChart(model, metric, chartId),
            h('div', { class: 'perf-chart-x', 'aria-hidden': 'true' },
              h('span', null, perfLocalTime(firstAt)),
              h('span', null, perfLocalTime(middleAt)),
              h('span', null, perfLocalTime(lastAt))),
            performanceSampleDisclosure(model, metric))),
        performanceLegend(model, metric, legendId)),
      memory ? performanceResidualDiagnostics(model) : null);
  }

  function perfSummaryTile(label, value, ...sub) {
    return h('div', { class: 'perf-summary-tile' },
      h('dt', null, label),
      h('dd', null,
        h('strong', { class: 'mono' }, value),
        sub.filter(Boolean).map((line) => h('span', null, line))));
  }

  function performanceSummary(model) {
    const host = model.host;
    const cpuCores = host.cpuUsed / 100 * host.cores;
    const load = host.load.map((value) => Number(value).toFixed(2)).join(' · ');
    const disk = host.disks[0] || null;
    const diskUsed = Math.max(0, perfFinite(disk?.usedBytes) || 0);
    const diskTotal = Math.max(0, perfFinite(disk?.totalBytes) || 0);
    const memoryCoverage = model.coverage.memory;
    const cpuCoverage = model.coverage.cpu;
    const sampled = model.sampledAt ? timeAgo(model.sampledAt) : 'sample unavailable';
    return h('dl', { id: 'perf-summary', class: 'perf-summary' },
      perfSummaryTile('CPU', perfPercent(host.cpuUsed, 0),
        cpuCores.toFixed(1) + ' of ' + host.cores + ' cores',
        load ? 'Load ' + load : null),
      perfSummaryTile('Memory', fmtBytes(host.memoryUsed),
        'Host used · not immediately available',
        fmtBytes(host.memoryAvailable) + ' available of ' + fmtBytes(host.memoryTotal)),
      perfSummaryTile('Storage', disk
        ? fmtBytes(diskUsed) + ' / ' + fmtBytes(diskTotal) : 'Unavailable',
        disk ? (disk.mount || '/') + ' · ' + perfPercent(diskTotal ? diskUsed / diskTotal * 100 : 0, 0) + ' used' : null),
      perfSummaryTile('Uptime', host.uptimeSec === null ? 'Unavailable' : fmtUptime(host.uptimeSec),
        host.uptimeSec === null ? null : 'since last boot'),
      perfSummaryTile('Accounting coverage',
        memoryCoverage === null ? 'Unavailable' : perfPercent(memoryCoverage, 0) + ' memory',
        cpuCoverage === null ? null : perfPercent(cpuCoverage, 0) + ' CPU',
        'Attributed working set'),
      perfSummaryTile('Sample skew', perfSkewText(model.sampleSkewMs),
        sampled === 'now' ? 'sampled now' : 'sampled ' + sampled));
  }

  function perfDiagnosticCgroupName(group) {
    const role = String(group?.role || group?.key || '');
    if (role === 'project-runtimes') return 'Project runtimes';
    if (role === 'coordinator-control') return 'Coordinator control plane';
    if (role === 'coordinator-background') return 'Coordinator background / scheduler';
    if (role === 'active-test-attempts') return 'Active test attempts';
    if (role === 'developer-sessions') return 'Developer-account sessions';
    if (role === 'system-services') return 'System services';
    return group?.label || role || 'Host cgroup';
  }

  function perfDiagnosticValues(group) {
    const values = [
      ['Working', perfFinite(group?.workingBytes, group?.working_bytes), 'memory'],
      ['Current', perfFinite(group?.workingBytes, group?.working_bytes) === null
        ? perfFinite(group?.currentBytes, group?.current_bytes) : null, 'memory'],
      ['Anonymous', perfFinite(group?.anonBytes, group?.anon_bytes), 'memory'],
      ['Shared', perfFinite(group?.shmemBytes, group?.shmem_bytes), 'memory'],
      ['Kernel', perfFinite(group?.kernelBytes, group?.kernel_bytes), 'memory'],
      ['CPU', perfFinite(group?.cpuRawPercent, group?.cpu_raw_percent), 'cpu'],
      ['Processes', perfFinite(group?.processCount, group?.process_count), 'count'],
    ].filter((entry) => entry[1] !== null);
    return h('span', { class: 'perf-residual-diagnostic-values' }, values.map(([label, value, kind]) =>
      h('span', null,
        h('small', null, label),
        h('strong', { class: 'mono' }, kind === 'memory' ? fmtBytes(value)
          : kind === 'cpu' ? perfPercent(value) + ' raw' : String(Math.round(value))))));
  }

  function perfDiagnosticChild(child) {
    const active = Math.max(0, perfFinite(child?.activeChildCount, child?.active_child_count) || 0);
    const detail = child?.accountUid !== null && child?.accountUid !== undefined
      ? (active ? active + ' active session' + (active === 1 ? '' : 's') : 'account session tree')
      : (child?.populated === true ? 'active' : 'idle');
    return h('div', {
      class: 'perf-residual-child',
      'data-performance-diagnostic-child': String(child?.key || 'child'),
    },
      h('span', { class: 'perf-residual-child-name' },
        h('strong', null, child?.accountName || child?.label || 'Workload'),
        h('span', null, detail)),
      perfDiagnosticValues(child));
  }

  function performanceCgroupDiagnostic(group, crosscheck) {
    const role = String(group?.role || group?.key || 'unknown');
    const children = (Array.isArray(group?.children) ? group.children : []).slice(0, 12);
    const active = Math.max(0, perfFinite(group?.activeChildCount, group?.active_child_count) || 0);
    const relationship = group?.additive === true
      ? 'In host stack'
      : 'Drilldown only' + (group?.overlap ? ' · overlaps ' + group.overlap : '');
    const heading = h('span', { class: 'perf-residual-diagnostic-head' },
      h('span', { class: 'perf-residual-diagnostic-name' },
        h('strong', null, perfDiagnosticCgroupName(group)),
        h('span', { class: group?.additive === true ? 'is-additive' : 'is-overlap' }, relationship),
        role === 'active-test-attempts' && active
          ? h('span', { class: 'is-count' }, active + ' active') : null),
      perfDiagnosticValues(group));
    const crosscheckNode = role === 'project-runtimes' && crosscheck
      ? h('p', { class: 'perf-residual-crosscheck' },
          fmtBytes(perfFinite(crosscheck.repositoryMemoryBytes,
            crosscheck.repository_memory_bytes) || 0)
          + ' reported across ' + Math.max(0, perfFinite(crosscheck.repositoryCount,
            crosscheck.repository_count) || 0)
          + ' repositories · already included above'
          + (perfFinite(crosscheck.differenceBytes, crosscheck.difference_bytes) === null
            ? ' · cgroup comparison unavailable'
            : ' · difference ' + fmtBytes(Math.abs(perfFinite(
              crosscheck.differenceBytes, crosscheck.difference_bytes) || 0))))
      : null;
    const childrenNode = children.length
      ? h('div', { class: 'perf-residual-children' }, children.map(perfDiagnosticChild),
          group?.childrenTruncated === true
            ? h('p', { class: 'perf-residual-truncated' }, 'Additional cgroups omitted from this bounded view.')
            : null)
      : h('p', { class: 'perf-residual-diagnostics-empty' },
          group?.childrenAvailable === false
            ? 'Child cgroups are unavailable for this sample.' : 'No active child cgroups.');
    if (!children.length && !crosscheckNode) {
      return h('div', {
        class: 'perf-residual-diagnostic',
        'data-performance-diagnostic': 'cgroup:' + role,
      }, heading);
    }
    return h('details', {
      class: 'perf-residual-diagnostic perf-residual-diagnostic-group',
      'data-performance-diagnostic': 'cgroup:' + role,
      'data-section-disclosure': 'performance-diagnostic:' + role,
    }, h('summary', null, heading), crosscheckNode, childrenNode);
  }

  function performanceResidualDiagnostics(model) {
    const diagnostics = model.diagnostics;
    const cgroups = (Array.isArray(diagnostics?.cgroups) ? diagnostics.cgroups : [])
      .filter((group) => group?.available !== false)
      .slice()
      .sort((left, right) => (perfFinite(right.workingBytes, right.working_bytes) || 0)
        - (perfFinite(left.workingBytes, left.working_bytes) || 0));
    const rows = cgroups.map((group) => performanceCgroupDiagnostic(
      group,
      diagnostics?.projectRuntimeCrosscheck || diagnostics?.project_runtime_crosscheck,
    ));
    const meminfo = diagnostics?.meminfo || null;
    if (meminfo?.available !== false && meminfo) {
      const meminfoRows = [
        ['meminfo:shmem', 'Host shared memory (Shmem)',
          perfFinite(meminfo.shmemBytes, meminfo.shmem_bytes)],
        ['meminfo:anon', 'Host anonymous pages (AnonPages)',
          perfFinite(meminfo.anonPagesBytes, meminfo.anon_pages_bytes)],
        ['meminfo:sunreclaim', 'Host unreclaimable slab (SUnreclaim)',
          perfFinite(meminfo.sUnreclaimBytes, meminfo.s_unreclaim_bytes)],
        ['meminfo:slab', 'Host slab memory (Slab)',
          perfFinite(meminfo.slabBytes, meminfo.slab_bytes)],
        ['meminfo:pagetables', 'Host page tables (PageTables)',
          perfFinite(meminfo.pageTablesBytes, meminfo.page_tables_bytes)],
        ['meminfo:kernelstack', 'Host kernel stacks (KernelStack)',
          perfFinite(meminfo.kernelStackBytes, meminfo.kernel_stack_bytes)],
      ].filter((row) => row[2] !== null);
      rows.push(h('details', {
        class: 'perf-residual-diagnostic perf-residual-diagnostic-group',
        'data-performance-diagnostic': 'meminfo',
        'data-section-disclosure': 'performance-diagnostic:meminfo',
      },
      h('summary', null, h('span', { class: 'perf-residual-diagnostic-head' },
        h('span', { class: 'perf-residual-diagnostic-name' },
          h('strong', null, 'Host kernel & shared-memory counters'),
          h('span', { class: 'is-overlap' }, 'Drilldown only · overlaps host used')))),
      h('div', { class: 'perf-residual-children' }, meminfoRows.map(([key, label, value]) =>
        h('div', {
          class: 'perf-residual-child',
          'data-performance-diagnostic-child': key,
        },
        h('span', { class: 'perf-residual-child-name' }, h('strong', null, label)),
        h('span', { class: 'perf-residual-diagnostic-values' },
          h('span', null, h('strong', { class: 'mono' }, fmtBytes(value || 0)))))))));
    }
    return h('details', {
      id: 'perf-residual-diagnostics',
      'data-section-disclosure': 'performance-residual-diagnostics',
    },
      h('summary', null, 'Host accounting detail'),
      h('p', { class: 'perf-residual-diagnostics-note' },
        'Stack categories are added once. Repository, child-cgroup and host-counter drilldowns overlap a parent total and add nothing. Working memory is memory.current minus inactive file; anonymous, shared and kernel are exact cgroup-v2 counters. PSS is not inferred.'),
      rows.length
        ? h('div', { class: 'perf-residual-diagnostics-list' }, rows)
        : h('p', { class: 'perf-residual-diagnostics-empty' },
            'No overlapping host diagnostics are available for this sample.'));
  }

  function performanceContributorList(project, metric) {
    const sorted = project.contributors.slice().sort((left, right) =>
      (metric === 'memory' ? right.memoryBytes - left.memoryBytes
        : right.cpuPercent - left.cpuPercent)
      || left.name.localeCompare(right.name)).slice(0, 3);
    return h('section', { class: 'perf-contributor-group' },
      h('h4', null, metric === 'memory' ? 'By memory' : 'By CPU'),
      sorted.length
        ? h('ol', null, sorted.map((contributor) =>
            h('li', null,
              h('span', { class: 'perf-contributor-name' },
                h('strong', null, contributor.name),
                h('span', { class: 'kind-tag ' + (contributor.kind === 'container' ? 'k-dock' : 'k-srv') },
                  contributor.kind)),
              h('span', { class: 'mono' }, metric === 'memory'
                ? fmtBytes(contributor.memoryBytes)
                : perfPercent(contributor.cpuPercent)
                  + (contributor.cpuRawPercent
                    ? ' (' + (contributor.cpuRawPercent / 100).toFixed(1) + ' cores)' : '')))))
        : h('p', { class: 'perf-dialog-empty' }, 'No contributor breakdown is available for this sample.'));
  }

  function performanceProjectMetric(project, model, metric) {
    const current = metric === 'memory' ? project.memoryObserved : project.cpuObserved;
    const peak = metric === 'memory' ? project.memoryPeak : project.cpuPeak;
    const currentExtra = metric === 'cpu'
      ? (current / 100 * model.host.cores).toFixed(1) + ' cores'
      : (project.kind === 'agent-browsers'
          ? 'measured non-project working set' : 'attributed working set');
    const peakExtra = metric === 'cpu'
      ? (peak / 100 * model.host.cores).toFixed(1) + ' cores'
      : 'last 60 minutes';
    return h('section', { class: 'perf-dialog-metric' },
      h('h3', null, metric === 'memory' ? 'Memory usage' : 'CPU load'),
      h('dl', null,
        h('div', null, h('dt', null, 'Current'),
          h('dd', { class: 'mono ' + (metric === 'memory' ? 'u-mem' : 'u-cpu') },
            perfMetricText(metric, current),
            h('span', null, currentExtra))),
        h('div', null, h('dt', null, 'Peak (60 min)'),
          h('dd', { class: 'mono ' + (metric === 'memory' ? 'u-mem' : 'u-cpu') },
            perfMetricText(metric, peak),
            h('span', null, peakExtra)))));
  }

  function performanceAgentBrowserState(session, policy) {
    const state = String(session.state || '').toLowerCase();
    if (state.includes('protected')) return { label: 'Protected', tone: 'is-protected' };
    if (session.reapEligible) return { label: 'Cleanup eligible', tone: 'is-eligible' };
    if (state.includes('idle') || session.idleSeconds >= policy.idleTimeoutSeconds) {
      return { label: 'Idle', tone: 'is-idle' };
    }
    return { label: state === 'unknown' ? 'Observed' : session.state, tone: 'is-active' };
  }

  function performanceAgentBrowserDetail(segment) {
    const browser = segment.agentBrowsers;
    if (!browser) {
      return h('p', { class: 'perf-dialog-empty' },
        'Session-level browser telemetry is unavailable for this sample.');
    }
    const totals = browser.totals;
    const sessions = browser.sessions.slice().sort((left, right) =>
      right.memoryBytes - left.memoryBytes
      || right.cpuPercent - left.cpuPercent
      || left.sessionId.localeCompare(right.sessionId));
    const visibleSessions = sessions.slice(0, 8);
    const recentReaps = browser.recentReaps.slice(0, 4);
    const sessionRows = visibleSessions.map((session) => {
      const state = performanceAgentBrowserState(session, browser.policy);
      const identity = [session.agent, session.repositoryName].filter(Boolean).join(' · ')
        || 'Agent browser session';
      const lastWork = session.lastObservedWorkAt;
      return h('li', { class: 'perf-agent-session' },
        h('div', { class: 'perf-agent-session-head' },
          h('strong', { title: identity }, identity),
          h('span', { class: 'perf-agent-state ' + state.tone }, state.label)),
        h('dl', { class: 'perf-agent-session-stats' },
          h('div', null, h('dt', null, 'Memory'),
            h('dd', { class: 'mono u-mem' }, fmtBytes(session.memoryBytes))),
          h('div', null, h('dt', null, 'CPU'),
            h('dd', { class: 'mono u-cpu' }, perfPercent(session.cpuPercent) + ' raw')),
          h('div', null, h('dt', null, 'Processes'),
            h('dd', { class: 'mono' }, String(session.processCount))),
          h('div', null, h('dt', null, 'Idle'),
            h('dd', { class: 'mono' }, fmtSeconds(session.idleSeconds))),
          h('div', { class: 'perf-agent-last-work' }, h('dt', null, 'Last observed work'),
            h('dd', null, lastWork
              ? h('time', { datetime: new Date(lastWork).toISOString(), title: fmtWhen(lastWork) },
                  timeAgo(lastWork))
              : 'Unavailable'))));
    });
    const cleanupRows = recentReaps.map((reap) => {
      const identity = [reap.agent, reap.repositoryName].filter(Boolean).join(' · ')
        || 'Agent browser session';
      return h('li', null,
        h('span', null, h('strong', null, identity),
          reap.reason ? h('small', null, reap.reason) : null),
        h('span', { class: 'mono' }, fmtBytes(reap.reclaimedMemoryBytes)
          + (reap.reapedAt ? ' · ' + timeAgo(reap.reapedAt) : '')));
    });
    return h('div', { class: 'perf-agent-browser-detail' },
      h('section', { class: 'perf-agent-summary', 'aria-labelledby': 'perf-agent-summary-title' },
        h('h3', { id: 'perf-agent-summary-title' }, 'Worker sessions'),
        h('dl', null,
          h('div', null, h('dt', null, 'Sessions'), h('dd', { class: 'mono' }, String(totals.sessionCount))),
          h('div', null, h('dt', null, 'Processes'), h('dd', { class: 'mono' }, String(totals.processCount))),
          h('div', null, h('dt', null, 'Idle'), h('dd', { class: 'mono' }, String(totals.idleSessionCount))),
          h('div', null, h('dt', null, 'Protected'), h('dd', { class: 'mono' }, String(totals.protectedSessionCount)))),
        h('p', null, 'Idle cleanup after ' + fmtSeconds(browser.policy.idleTimeoutSeconds)
          + ' · ' + fmtSeconds(browser.policy.terminationGraceSeconds) + ' grace')),
      h('section', { class: 'perf-agent-sessions', 'aria-labelledby': 'perf-agent-sessions-title' },
        h('div', { class: 'perf-agent-section-head' },
          h('h3', { id: 'perf-agent-sessions-title' }, 'Current sessions'),
          sessions.length > visibleSessions.length
            ? h('span', null, 'Showing ' + visibleSessions.length + ' of ' + sessions.length)
            : null),
        sessionRows.length
          ? h('ol', null, sessionRows)
          : h('p', { class: 'perf-dialog-empty' }, 'No non-project browser sessions are active.')),
      h('section', { class: 'perf-agent-cleanup', 'aria-labelledby': 'perf-agent-cleanup-title' },
        h('div', { class: 'perf-agent-section-head' },
          h('h3', { id: 'perf-agent-cleanup-title' }, 'Recent cleanup'),
          h('span', null, totals.reapedTotal + ' reaped · '
            + fmtBytes(totals.reclaimedMemoryBytes) + ' reclaimed')),
        cleanupRows.length ? h('ol', null, cleanupRows)
          : h('p', { class: 'perf-dialog-empty' }, 'No recent browser cleanup events.')));
  }

  function renderPerformanceProjectDialog() {
    const dialog = $('#perf-project-dialog');
    if (!dialog || !ui.performanceProjectKey) return;
    const model = performanceModel();
    const latest = model?.segments.find((segment) =>
      segment.key === ui.performanceProjectKey) || null;
    if (latest) ui.performanceProjectRecord = latest;
    const project = latest || ui.performanceProjectRecord;
    const inCurrentComposition = Boolean(latest && latest.active !== false);
    if (!project || !model) return;
    const body = $('#perf-project-dialog-body');
    const priorScroll = body.scrollTop;
    $('#perf-project-dialog-title').textContent = project.name;
    const history = Array.isArray(project.history) ? project.history : [];
    const historyPoints = history.map((point) => [point.at, point.cpu, point.memory]);
    const sampledAt = project.sampledAt || model.sampledAt;
    $('#perf-project-dialog-subtitle').textContent = (project.kind === 'agent-browsers'
      ? 'Measured non-project browser workers · ' : 'History for the last 60 minutes · ')
      + history.length + ' sample' + (history.length === 1 ? '' : 's')
      + (sampledAt ? ' · sampled ' + timeAgo(sampledAt) : '');
    const content = [
      inCurrentComposition ? null : h('p', { class: 'perf-dialog-retained' },
        'This item is absent from the newest composition. Showing its retained history and last available detail.'),
      h('div', { class: 'perf-dialog-metrics' },
        performanceProjectMetric(project, model, 'cpu'),
        performanceProjectMetric(project, model, 'memory')),
      h('section', { class: 'perf-dialog-history', 'aria-label': 'Performance history' },
        chartBlock('CPU history', historyPoints, (point) => point[1], fmtCpu, 'c-cpu'),
        chartBlock('Memory history', historyPoints, (point) => point[2], fmtBytes, 'c-mem')),
      project.kind === 'agent-browsers' ? performanceAgentBrowserDetail(project)
        : h('section', { class: 'perf-dialog-contributors' },
        h('h3', null, 'Top contributors'),
        h('div', null,
          performanceContributorList(project, 'cpu'),
          performanceContributorList(project, 'memory'))),
    ].filter(Boolean);
    body.replaceChildren(...content);
    body.scrollTop = priorScroll;
  }

  function openPerformanceProject(key, trigger) {
    const model = performanceModel();
    const project = model?.segments.find((candidate) => (
      candidate.key === String(key)
      && (candidate.project || candidate.kind === 'agent-browsers')
    ));
    if (!project) return;
    ui.performanceProjectKey = project.key;
    ui.performanceProjectRecord = project;
    ui.performanceReturnFocus = trigger || document.activeElement;
    ui.performanceReturnFocusMetric = trigger?.dataset.performanceMetric || 'memory';
    renderPerformanceProjectDialog();
    const dialog = $('#perf-project-dialog');
    if (!dialog.open) dialog.showModal();
    requestAnimationFrame(() => $('#perf-project-dialog-close')?.focus({ preventScroll: true }));
  }

  function closePerformanceProject({ restoreFocus = true } = {}) {
    const dialog = $('#perf-project-dialog');
    const key = ui.performanceProjectKey;
    const metric = ui.performanceReturnFocusMetric;
    const original = ui.performanceReturnFocus;
    if (dialog?.open) dialog.close();
    ui.performanceProjectKey = null;
    ui.performanceProjectRecord = null;
    ui.performanceReturnFocus = null;
    ui.performanceReturnFocusMetric = null;
    if (!restoreFocus) return;
    // Escape dispatches the dialog cancel event while the browser is still
    // completing its own modal-focus steps. Resolve the current keyed control
    // on the next frame, so both an unchanged render and a refresh-replaced
    // legend return focus to the same logical item without a delayed retry
    // stealing focus after the user has already moved on.
    const restore = () => {
      if (dialog?.open || ui.performanceProjectKey !== null) return;
      const buttons = [...document.querySelectorAll('.perf-legend-button')];
      const current = key
        ? buttons.find((button) => button.dataset.performanceKey === key
          && button.dataset.performanceMetric === metric)
          || buttons.find((button) => button.dataset.performanceKey === key)
        : null;
      const target = current || (original?.isConnected ? original : null);
      target?.focus({ preventScroll: true });
    };
    requestAnimationFrame(restore);
  }

  function buildPerf(o) {
    // Section replacement can remove a hovered legend row without dispatching
    // pointerleave. Drop transient DOM state before rebuilding; setSection's
    // focus restoration will reapply the surviving keyboard focus explicitly.
    performanceSeriesEmphasis.clear();
    const model = performanceModel(o);
    if (!model) {
      return [emptyState('Collecting metrics — the whole-host composition appears after the first coherent sample.')];
    }
    const retained = state.metrics?.sampler?.lastError
      ? h('p', { class: 'perf-retained-warning' },
          'Latest sampling failed — showing retained performance history. '
          + String(state.metrics.sampler.lastError))
      : null;
    const footerAt = model.sampledAt ? new Date(model.sampledAt).toLocaleString() : 'unavailable';
    return [h('div', { class: 'performance-dashboard' },
      retained,
      performanceSummary(model),
      performanceCompositionPanel(model, 'memory'),
      performanceCompositionPanel(model, 'cpu'),
      h('p', { class: 'perf-footnote' },
        'Last coherent sample ' + footerAt + ' local · '
        + model.samples.length + ' retained sample' + (model.samples.length === 1 ? '' : 's')
        + ' · CPU normalized to ' + model.host.cores + ' logical cores.'))];
  }

  // ---------------------------------------------------------------- timers

  function startPolling() {
    setInterval(() => {
      if (!document.hidden) {
        refreshOverview();
        if (currentPage() === 'invites' && state.session?.accessAdmin === true) {
          loadInvites({ force: true });
        }
        if (currentPage() === 'telegram' && state.session?.email) {
          loadTelegram({ force: true });
        }
        loadBugs({ force: true });
        if (efficiencyAvailable()) loadEfficiency({ force: true });
      }
    }, POLL_MS);
    setInterval(() => {
      if (!document.hidden) refreshMetrics();
    }, METRICS_POLL_MS);
    setInterval(refreshTestsInPlace, TESTS_POLL_MS);
    window.addEventListener('focus', refreshTestsInPlace);
    window.addEventListener('online', refreshTestsInPlace);
    window.addEventListener('focus', () => loadBugs({ force: true }));
    window.addEventListener('online', () => loadBugs({ force: true }));
    window.addEventListener('focus', () => {
      if (currentPage() === 'efficiency') loadEfficiency({ force: true });
    });
    window.addEventListener('online', () => {
      if (currentPage() === 'efficiency') loadEfficiency({ force: true });
    });
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        refreshOverview();
        refreshMetrics();
        refreshTestsInPlace();
        // Pick up hides made on another device while this tab slept.
        loadPrefs();
        if (state.session?.accessAdmin === true) loadAccess({ force: true });
        if (state.session?.accessAdmin === true) loadInvites({ force: true });
        if (state.session?.email) loadTelegram({ force: true });
        loadBugs({ force: true });
        if (efficiencyAvailable()) loadEfficiency({ force: true });
        if (lifecycleAvailable()) loadArchives({ force: true });
      }
    });
  }

  function startCountdowns() {
    setInterval(() => {
      if (document.hidden) return;
      for (const el of document.querySelectorAll('[data-expires]')) {
        const t = Number(el.dataset.expires);
        if (!Number.isFinite(t)) continue;
        const remaining = t - Date.now() / 1000;
        el.textContent = countdownText(t);
        el.classList.toggle('warn', remaining > 0 && remaining < 900);
        el.classList.toggle('expired', remaining <= 0);
      }
    }, 1000);
  }

  // ---------------------------------------------------------------- boot

  async function boot() {
    wireForm();
    wireLeaseForm();
    wireNav();
    wireAccessDialog();
    wireTelegramDialog();
    wireLifecycle();
    $('#invites-refresh').addEventListener('click', () => loadInvites({ force: true }));
    applyPage();

    loadPrefs();

    api('/api/session')
      .then((s) => {
        state.session = s;
        syncAccessVisibility();
        renderHeader();
        if (currentPage() === 'bugs') renderBugs(true);
        if (s.accessAdmin === true) {
          loadAccess();
          loadInvites();
        }
        if (lifecycleAvailable()) {
          loadArchives();
        }
        if (s.efficiencyAvailable === true) loadEfficiency();
        loadTelegram();
      })
      .catch((err) => {
        if (err.status !== 401) {
          showBanner(err, () => api('/api/session').then((s) => {
            state.session = s;
            syncAccessVisibility();
            renderHeader();
            if (currentPage() === 'bugs') renderBugs(true);
            if (s.accessAdmin === true) {
              loadAccess();
              loadInvites();
            }
            if (lifecycleAvailable()) {
              loadArchives();
            }
            if (s.efficiencyAvailable === true) loadEfficiency();
            loadTelegram();
          }).catch(() => {}));
        }
      });

    const initialBugs = loadBugs();
    const initialOverview = refreshOverview({ force: true });
    const initialMetrics = refreshMetrics();
    startPolling();
    startCountdowns();
    await Promise.allSettled([initialBugs, initialOverview, initialMetrics]);
  }

  boot();
})();
