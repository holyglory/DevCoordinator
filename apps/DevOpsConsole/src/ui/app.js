/* DevOps Console control panel.
 * Vanilla JS, no dependencies. Talks only to same-origin /api/*.
 * Hash-routed pages (#/projects, #/tests, #/servers, #/routes, #/docker, #/ports,
 * #/performance, #/access, #/invites, #/telegram)
 * share one sticky status bar. Polls GET /api/overview every 6s and
 * GET /api/metrics/history every 10s (both paused while the tab is hidden),
 * and refetches immediately after every mutation. All user data goes through
 * textContent — never innerHTML; charts are built with createElementNS. */
(() => {
  'use strict';

  const POLL_MS = 6000;
  const METRICS_POLL_MS = 10_000;
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
    archives: null,      // owner-only GET /api/lifecycle/list ({ archives })
    tests: null,         // selected repository's Coordinator-owned test statistics
    testsRepositories: null, // lightweight enrolled repository catalog
    testsProject: null,
    testsDays: 30,
    testsLoading: false,
    testsRepositoriesLoading: false,
    testsQueryKey: null,
    testsLoadedAt: 0,
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
    lifecycleDialog: null, // { action, target, stage, plan, returnFocusKey }
    lifecycleFocus: null,  // target revealed after a successful archive/restore/purge
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
    eyeoff: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M2 8s2.2-3.8 6-3.8S14 8 14 8s-2.2 3.8-6 3.8S2 8 2 8Z" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="8" cy="8" r="1.7" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M3 13 13 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>',
    eye: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M2 8s2.2-3.8 6-3.8S14 8 14 8s-2.2 3.8-6 3.8S2 8 2 8Z" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="8" cy="8" r="1.7" fill="none" stroke="currentColor" stroke-width="1.3"/></svg>',
    archive: '<svg viewBox="0 0 16 16" width="13" height="13"><path d="M2.5 4.5h11v8.2a.8.8 0 0 1-.8.8H3.3a.8.8 0 0 1-.8-.8Z" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M2 2.5h12v2H2zM6 7.5h4" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>',
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

  function showBanner(value, retry, key = 'action') {
    const maintenance = isMaintenanceError(value);
    const message = maintenance
      ? 'Controls are updating. No action needed — running services stay online and live data reconnects automatically.'
      : value?.message ?? String(value);
    bannerKey = maintenance ? 'maintenance' : key;
    $('#banner-slot').replaceChildren(
      h('div', {
        class: `banner${maintenance ? ' maintenance' : ''}`,
        role: maintenance ? 'status' : 'alert',
        'aria-live': maintenance ? 'polite' : null,
      },
        icon(maintenance ? 'refresh' : 'warn'),
        h('span', { class: 'banner-msg' }, String(message)),
        retry && !maintenance ? h('button', {
          class: 'btn small', type: 'button',
          onclick: () => { clearBanner(); retry(); },
        }, 'Retry') : null,
        h('button', {
          class: 'iconbtn', type: 'button',
          'aria-label': maintenance ? 'Dismiss maintenance status' : 'Dismiss error', title: 'Dismiss',
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
    if (state.overview) renderAll(true);
    // The performance page charts use a longer history window than sparklines.
    if (page === 'performance') refreshMetrics();
    if (page === 'tests') {
      loadTestRepositories();
      loadTests();
    }
    if (page === 'access' && state.session?.accessAdmin === true) loadAccess();
    if (page === 'invites' && state.session?.accessAdmin === true) loadInvites();
    if (page === 'telegram' && state.session?.email) loadTelegram();
  }

  function wireNav() {
    $('#nav-toggle').addEventListener('click', () => setNavOpen(!navOpen()));
    $('#tests-project').addEventListener('change', (event) => {
      state.testsProject = event.currentTarget.value;
      state.tests = null;
      state.testsQueryKey = null;
      loadTests({ force: true });
    });
    $('#tests-days').addEventListener('change', (event) => {
      state.testsDays = Number(event.currentTarget.value);
      state.tests = null;
      state.testsQueryKey = null;
      loadTests({ force: true });
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
      input.checked = !allowed;
      input.disabled = false;
      if (err.status !== 401) {
        showBanner(err, () => changeAccessGrant(email, resource, input, allowed));
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
      if (err.status !== 401) showBanner(err, () => removeAccessUser(email));
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
        error.textContent = err.message;
        error.hidden = false;
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
      if (err.status !== 401) showBanner(err, () => decideInvite(request, decision), 'invites');
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

  function renderTelegram() {
    if (!state.session?.email) return;
    setNavCount('telegram', state.telegram ? telegramBots().length : null);
    if (currentPage() !== 'telegram') return;
    setSection('telegram-body', sig(state.telegram), buildTelegram, true);
    setCount('telegram-count', state.telegram ? telegramBots().length : null);
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
        closeTelegramDialog();
        renderTelegram();
        announce('Telegram bot registered');
        const row = registered ? document.querySelector(
          `[data-telegram-bot="${CSS.escape(telegramBotId(registered))}"]`,
        ) : null;
        row?.scrollIntoView({ block: 'nearest' });
        row?.focus({ preventScroll: true });
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
    return h('button', {
      class: compact ? 'iconbtn' : 'btn small', type: 'button',
      'data-fk': `archive:${target.target_kind}:${target.target_id}`,
      'aria-label': `Archive ${target.display_name}`,
      title: 'Archive — stop and fence this resource while retaining its data and history',
      onclick: (event) => openLifecycleDialog('archive', target, event.currentTarget),
    }, icon('archive'), compact ? null : 'Archive');
  }

  function workerRemoveButton(server, { compact = false } = {}) {
    if (state.session?.accessAdmin !== true || !server?.supervision) {
      return compact ? ghostIconSlot() : null;
    }
    return h('button', {
      class: compact ? 'iconbtn' : 'btn small', type: 'button',
      'data-fk': `worker-remove:${server.id}`,
      'aria-label': `Remove worker ${server.name || server.id}`,
      title: 'Remove worker — first stop, archive and hide it; permanent deletion is a separate reviewed step',
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
    const inventoryProblems = authoritativeInventoryProblemsOf(state.overview);
    if (inventoryProblems.length) {
      showBanner('Worker removal is disabled until every active resource belongs to an authoritative repository scope.');
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
    const inventoryProblems = authoritativeInventoryProblemsOf(state.overview);
    if (inventoryProblems.length) {
      showBanner('Lifecycle controls are disabled until every active resource belongs to an authoritative repository scope.');
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
    if (authoritativeInventoryProblemsOf(state.overview).length) {
      error.textContent = 'Inventory changed: every active resource must belong to a repository scope before this action can continue.';
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

    const containers = o.inventory.docker?.available ? (o.inventory.docker.containers || []) : [];
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
  // never manufacture project membership.
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
        || !records(inv.memberships)
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
    const containerMembershipsById = new Map();
    for (const membership of inv.memberships) {
      if (membership.resource_kind !== 'container') continue;
      const id = membership.host_resource_id;
      if (typeof id !== 'string' || !id) return invalid('a container membership has no immutable ID');
      const matches = containerMembershipsById.get(id) || [];
      matches.push(membership);
      containerMembershipsById.set(id, matches);
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
          const matches = containerMembershipsById.get(containerId);
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
    const containers = inv.docker?.available ? (inv.docker.containers || []) : [];
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
        // row; neither names nor paths are used to establish membership.
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
      const kind = item.resource_kind || fallbackKind;
      const resourceId = item.resource_id || item.host_resource_id || '';
      const reasonCode = item.reason_code || '';
      const key = `${kind}|${resourceId}|${reasonCode}`;
      if (reportedKeys.has(key)) return;
      reportedKeys.add(key);
      if (resourceId) reportedResourceKeys.add(`${kind}|${resourceId}`);
      problems.push({
        kind,
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
          kind: 'server', name: server.name || 'Unnamed server',
          reason: 'The running server is absent from both the repository tree and the coordinator ownership-problem list.',
          nextStep: 'Rerun Coordinator installation for the original root repository, or attach or retire this exact server, then refresh.',
        });
      }
    }
    const containers = inv.docker?.available ? (inv.docker.containers || []) : [];
    const activeContainerIds = new Set();
    for (const container of containers) {
      const resourceId = container.host_resource_id ?? container.docker_resource_id ?? null;
      const status = String(container.status || '').trim();
      const active = isContainerActive(container) && !/^stopped\b/i.test(status);
      if (active && resourceId != null) activeContainerIds.add(String(resourceId));
      if (active && (resourceId == null || !claimedContainers.has(String(resourceId)))
          && !reportedResourceKeys.has(`container|${resourceId}`)) {
        problems.push({
          kind: 'container', name: container.name || 'Unnamed container',
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
          kind: 'database', name: database.database_name || 'Unnamed database',
          reason: 'The active database binding is absent from both the repository tree and the coordinator ownership-problem list.',
          nextStep: 'Rerun Coordinator installation for the original root repository, or bind this exact database stack, then refresh.',
        });
      }
    }
    return problems;
  }

  function authoritativeInventoryErrorPanel(o) {
    const problems = authoritativeInventoryProblemsOf(o);
    if (!problems.length) return null;
    const structural = problems.some((problem) => problem.kind === 'inventory');
    return h('div', { class: 'degraded repository-inventory-error', role: 'alert' },
      icon('warn'),
      h('div', null,
        h('p', { class: 'deg-title' }, structural
          ? 'Repository inventory contract is invalid'
          : 'Repository assignment is incomplete'),
        h('p', { class: 'deg-msg' },
          structural
            ? 'The coordinator returned a malformed or contradictory repository tree. Lifecycle controls are disabled; refresh after correcting the producer.'
            : `${problems.length} resource ownership problem${sfx(problems.length)} ${problems.length === 1 ? 'blocks' : 'block'} lifecycle controls. Follow the exact next step below, then refresh.`),
        h('ul', { class: 'inventory-problem-list' },
          problems.map((problem) => h('li', null,
            h('strong', null, `${problem.kind}: ${problem.name}`),
            problem.reason ? h('span', null, problem.reason) : null,
            problem.nextStep ? h('span', { class: 'inventory-problem-next-step' }, problem.nextStep) : null)))));
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
      if (data.coordinator?.failureKind === 'maintenance') {
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
      showBanner(err, () => refreshOverview({ force: true, fresh: true }), 'overview');
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
      if (ownerPage !== page || id === 'access-body') continue;
      document.getElementById(id).replaceChildren(
        h('p', { class: 'empty err' }, 'Could not load — use Retry in the error banner above.'));
    }
  }

  // ---------------------------------------------------------------- mutations

  async function runAction(busyKey, fn, { confirmText, onError } = {}) {
    if (authoritativeInventoryProblemsOf(state.overview).length) {
      showBanner('Coordinator mutation is disabled until every active resource belongs to an authoritative repository scope.');
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
        showBanner(err, () => runAction(busyKey, fn, { onError }));
        onError?.(err);
      }
      return false;
    }
  }

  // ---------------------------------------------------------------- test statistics

  function metricTestRepositories() {
    const repositories = new Map();
    for (const entity of state.metrics?.entities || []) {
      if (entity?.kind !== 'project' || typeof entity.project !== 'string' || !entity.project) continue;
      const project = entity.project;
      if (!repositories.has(project)) {
        repositories.set(project, {
          project,
          repo_id: null,
          canonical_root: project,
          display_name: entity.name || projectTail(project),
        });
      }
    }
    return [...repositories.values()];
  }

  function testRepositories() {
    let repositories;
    if (state.testsRepositories) {
      repositories = state.testsRepositories.repositories || [];
    } else if (state.overview?.inventory?.repositories) {
      repositories = state.overview.inventory.repositories;
    } else {
      repositories = metricTestRepositories();
    }
    return repositories
      .filter((repository) => repository && (repository.canonical_root || repository.repo_id || repository.project))
      .map((repository) => ({
        ...repository,
        project: repository.canonical_root || repository.project || repository.repo_id,
      }))
      .slice()
      .sort((a, b) => String(a.display_name || a.canonical_root || a.repo_id)
        .localeCompare(String(b.display_name || b.canonical_root || b.repo_id)));
  }

  async function loadTestRepositories({ force = false } = {}) {
    if (state.testsRepositoriesLoading) return;
    if (!force && state.testsRepositories) return;
    state.testsRepositoriesLoading = true;
    try {
      const catalog = await api('/api/tests/repositories');
      if (!catalog || catalog.schema_version !== 1 || !Array.isArray(catalog.repositories)) {
        throw new Error('test repository catalog is invalid');
      }
      state.testsRepositories = catalog;
    } catch (err) {
      // During a rolling deployment an older Console process has no catalog
      // endpoint. Retained metrics still provide canonical repository roots,
      // so test data need not wait for heavyweight inventory.
      if (err.status !== 401 && err.status !== 404 && testRepositories().length === 0) {
        showBanner(err, () => loadTestRepositories({ force: true }), 'tests');
      }
    } finally {
      state.testsRepositoriesLoading = false;
      loadTests();
    }
  }

  async function loadTests({ force = false } = {}) {
    const repositories = testRepositories();
    const select = $('#tests-project');
    const available = new Set(repositories.map((repository) => String(repository.project)));
    if (!state.testsProject || !available.has(state.testsProject)) {
      state.testsProject = repositories[0]?.project ?? null;
      state.tests = null;
      state.testsQueryKey = null;
    }
    select.replaceChildren(...repositories.map((repository) => h('option', {
      value: repository.project,
      selected: repository.project === state.testsProject,
    }, repository.display_name || projectTail(repository.canonical_root) || repository.repo_id)));
    $('#tests-days').value = String(state.testsDays);
    if (!state.testsProject) {
      renderTests();
      return;
    }
    const queryKey = `${state.testsProject}\u0000${state.testsDays}`;
    if (!force && state.tests && state.testsQueryKey === queryKey) {
      renderTests();
      return;
    }
    if (state.testsLoading) return;
    state.testsLoading = true;
    renderTests();
    try {
      state.tests = await api(`/api/tests?project=${encodeURIComponent(state.testsProject)}&days=${state.testsDays}&limit=50`);
      state.testsQueryKey = queryKey;
      state.testsLoadedAt = Date.now();
      clearBanner('tests');
    } catch (err) {
      showBanner(err, () => loadTests({ force: true }), 'tests');
    } finally {
      state.testsLoading = false;
      renderTests();
    }
  }

  function testTable(title, headers, rows) {
    for (const row of rows) {
      [...row.children].forEach((cell, index) => {
        cell.dataset.label = headers[index] || '';
        cell.setAttribute('aria-label', `${headers[index] || 'Value'}: ${cell.textContent}`);
      });
    }
    return h('section', { class: 'test-panel' },
      h('h3', null, title),
      rows.length === 0
        ? h('p', { class: 'empty-inline' }, 'No recorded data in this period.')
        : h('div', { class: 'test-table-wrap' },
          h('table', { class: 'test-table' },
            h('thead', null, h('tr', null, headers.map((label) => h('th', { scope: 'col' }, label)))),
            h('tbody', null, rows))));
  }

  function testPassRate(summary) {
    const passed = Number(summary?.passed_count || 0);
    const failed = Number(summary?.failed_count || 0) + Number(summary?.error_count || 0);
    const decided = passed + failed;
    return decided > 0 ? (100 * passed) / decided : null;
  }

  function testDelta(current, previous) {
    const before = Number(previous || 0);
    return before > 0 ? (100 * (Number(current || 0) - before)) / before : null;
  }

  function testDeltaText(value) {
    if (!Number.isFinite(value)) return 'new';
    const rounded = Math.abs(value) >= 10 ? Math.round(value) : Number(value.toFixed(1));
    return `${value > 0 ? '+' : ''}${rounded}%`;
  }

  function testMixRgb(from, to, amount) {
    const ratio = Math.max(0, Math.min(1, amount));
    const channels = from.map((value, index) => Math.round(value + (to[index] - value) * ratio));
    return `rgb(${channels.join(' ')})`;
  }

  // Three-stop heat scale: blue through 60 aggregate test-minutes, amber
  // through 120, and red above it. Parallel test intervals add together, so
  // a single wall-clock hour can truthfully exceed 60 minutes.
  function testHeatColor(seconds) {
    const minutes = Math.max(0, Number(seconds || 0) / 60);
    if (minutes === 0) return '#142234';
    if (minutes <= 60) return testMixRgb([20, 43, 75], [47, 140, 255], minutes / 60);
    if (minutes <= 120) return testMixRgb([47, 140, 255], [255, 176, 32], (minutes - 60) / 60);
    return testMixRgb([255, 176, 32], [236, 95, 103], Math.min(1, (minutes - 120) / 60));
  }

  function testDayLabel(day) {
    const date = new Date(`${day}T00:00:00Z`);
    if (!Number.isFinite(date.getTime())) return day;
    return date.toLocaleDateString([], {
      weekday: 'short', month: 'short', day: 'numeric', timeZone: 'UTC',
    });
  }

  function testDayShortLabel(day) {
    const date = new Date(`${day}T00:00:00Z`);
    if (!Number.isFinite(date.getTime())) return day;
    return date.toLocaleDateString([], {
      weekday: 'short', day: 'numeric', timeZone: 'UTC',
    });
  }

  function testSummaryDetails(stats) {
    const summary = stats.summary || {};
    const comparison = stats.comparison_summary || {};
    const change = testDelta(summary.test_seconds, comparison.test_seconds);
    const hourlyTotals = new Map();
    const dailyTotals = new Map();
    for (const cell of stats.hourly || []) {
      hourlyTotals.set(Number(cell.hour), (hourlyTotals.get(Number(cell.hour)) || 0) + Number(cell.test_seconds || 0));
      dailyTotals.set(String(cell.day), (dailyTotals.get(String(cell.day)) || 0) + Number(cell.test_seconds || 0));
    }
    const peakHour = [...hourlyTotals].sort((a, b) => b[1] - a[1])[0]?.[0];
    const busiestDay = [...dailyTotals].sort((a, b) => b[1] - a[1])[0]?.[0];
    return {
      summary,
      change,
      peakHour,
      busiestDay,
      deltaClass: Number.isFinite(change) ? (change > 0 ? 'is-worse' : 'is-better') : '',
    };
  }

  function testCompactSummary(stats) {
    const { summary, peakHour, busiestDay } = testSummaryDetails(stats);
    return h('dl', { class: 'test-summary-compact', 'aria-label': 'Testing summary' },
      h('div', null, h('dt', null, 'Total time'), h('dd', null, fmtSeconds(summary.test_seconds || 0))),
      h('div', null, h('dt', null, 'Peak hour'), h('dd', null, Number.isInteger(peakHour) ? `${String(peakHour).padStart(2, '0')}:00` : '—')),
      h('div', null, h('dt', null, 'Busiest day'), h('dd', null, busiestDay ? testDayShortLabel(busiestDay) : '—')));
  }

  let activeTestHeatTooltipTarget = null;

  function testHeatTooltipNode() {
    let tooltip = $('#test-heat-tooltip');
    if (tooltip) return tooltip;
    tooltip = h('div', {
      id: 'test-heat-tooltip',
      class: 'test-heat-tooltip',
      role: 'tooltip',
      hidden: true,
    });
    document.body.append(tooltip);
    window.addEventListener('resize', () => {
      if (activeTestHeatTooltipTarget?.isConnected) {
        showTestHeatTooltip(activeTestHeatTooltipTarget);
      } else {
        hideTestHeatTooltip();
      }
    });
    document.addEventListener('scroll', () => hideTestHeatTooltip(), true);
    return tooltip;
  }

  function hideTestHeatTooltip(target = null) {
    if (target && activeTestHeatTooltipTarget !== target) return;
    activeTestHeatTooltipTarget = null;
    const tooltip = $('#test-heat-tooltip');
    if (tooltip) tooltip.hidden = true;
  }

  function showTestHeatTooltip(target) {
    const tooltip = testHeatTooltipNode();
    const seconds = Number(target.dataset.testSeconds || 0);
    const minutes = seconds / 60;
    const failures = Number(target.dataset.testFailures || 0);
    activeTestHeatTooltipTarget = target;
    tooltip.replaceChildren(
      h('span', { class: 'test-heat-tooltip-period' }, target.dataset.testPeriod || ''),
      h('strong', null, `${minutes.toFixed(1)} test-min`),
      h('span', { class: 'test-heat-tooltip-detail' },
        `${String(seconds)} aggregate seconds${failures ? ` · ${failures} failed ${failures === 1 ? 'test' : 'tests'}` : ''}`),
    );
    tooltip.hidden = false;
    tooltip.style.left = '0px';
    tooltip.style.top = '0px';
    const targetRect = target.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    const margin = 8;
    const gap = 7;
    const left = Math.min(
      window.innerWidth - tooltipRect.width - margin,
      Math.max(margin, targetRect.left + (targetRect.width / 2) - (tooltipRect.width / 2)),
    );
    let top = targetRect.top - tooltipRect.height - gap;
    if (top < margin) top = targetRect.bottom + gap;
    top = Math.min(window.innerHeight - tooltipRect.height - margin, Math.max(margin, top));
    tooltip.style.left = `${Math.round(left)}px`;
    tooltip.style.top = `${Math.round(top)}px`;
  }

  function testHeatmap(stats) {
    hideTestHeatTooltip();
    const cells = Array.isArray(stats.hourly) ? stats.hourly : [];
    const byDay = new Map();
    for (const cell of cells) {
      const day = String(cell.day || '');
      const hour = Number(cell.hour);
      if (!day || !Number.isInteger(hour) || hour < 0 || hour > 23) continue;
      if (!byDay.has(day)) byDay.set(day, new Map());
      byDay.get(day).set(hour, cell);
    }
    const days = [...byDay.keys()].sort();
    const head = h('tr', null, h('th', { scope: 'col', class: 'test-heat-day' }, 'UTC'));
    for (let hour = 0; hour < 24; hour += 1) {
      head.append(h('th', {
        scope: 'col',
        class: `test-heat-hour${hour % 2 === 0 ? ' is-even' : ''}${hour % 6 === 0 ? ' is-six' : ''}`,
      }, String(hour).padStart(2, '0')));
    }
    const body = h('tbody');
    for (const day of days) {
      const row = h('tr', null, h('th', { scope: 'row', class: 'test-heat-day' },
        h('span', { class: 'test-heat-day-full' }, testDayLabel(day)),
        h('span', { class: 'test-heat-day-short' }, testDayShortLabel(day))));
      for (let hour = 0; hour < 24; hour += 1) {
        const cell = byDay.get(day).get(hour) || { test_seconds: 0, failure_count: 0 };
        const minutes = Number(cell.test_seconds || 0) / 60;
        const failures = Number(cell.failure_count || 0);
        const period = `${testDayLabel(day)} · ${String(hour).padStart(2, '0')}:00 UTC`;
        const node = h('td', {
          class: `test-heat-cell${failures > 0 ? ' has-failure' : ''}`,
          style: `background-color:${testHeatColor(cell.test_seconds)}`,
          title: `${period} — ${minutes.toFixed(1)} aggregate test-minutes${failures ? `, ${failures} failed ${failures === 1 ? 'test' : 'tests'}` : ''}`,
          'aria-label': `${testDayLabel(day)}, ${String(hour).padStart(2, '0')}:00 UTC: ${minutes.toFixed(1)} aggregate test-minutes${failures ? `; ${failures} failures` : ''}`,
          tabindex: Number(cell.test_seconds || 0) > 0 || failures > 0 ? '0' : null,
          'data-test-period': period,
          'data-test-seconds': Number(cell.test_seconds || 0),
          'data-test-failures': failures,
          onpointerenter: (event) => showTestHeatTooltip(event.currentTarget),
          onpointerleave: (event) => hideTestHeatTooltip(event.currentTarget),
          onfocus: (event) => showTestHeatTooltip(event.currentTarget),
          onblur: (event) => hideTestHeatTooltip(event.currentTarget),
          onkeydown: (event) => {
            if (event.key === 'Escape') hideTestHeatTooltip(event.currentTarget);
          },
        });
        if (failures > 0) node.append(icon('x'));
        row.append(node);
      }
      body.append(row);
    }
    const table = h('table', { class: 'test-heatmap' }, h('thead', null, head), body);
    return h('section', { class: 'test-heat-panel' },
      h('div', { class: 'test-panel-title' },
        h('h3', null, 'Testing time by hour'),
        h('span', { class: 'meta-passive' }, 'aggregate test-minutes · UTC')),
      testCompactSummary(stats),
      days.length === 0
        ? h('p', { class: 'empty-inline' }, 'No hourly test timing is recorded for the last seven days.')
        : h('div', { class: 'test-heat-scroll' }, table),
      h('div', { class: 'test-heat-legend', 'aria-label': 'Heatmap scale: blue zero to 60 minutes, amber 60 to 120 minutes, red above 120 minutes' },
        h('div', { class: 'test-heat-scale', 'aria-hidden': 'true' }),
        h('div', { class: 'test-heat-ticks' }, h('span', null, '0m'), h('span', null, '60m'), h('span', null, '120m'), h('span', null, '180m+')),
        h('p', null, 'Aggregate test time may exceed 60m when tests run in parallel.')));
  }

  function testSeries(rows, days, offsetDays = 0) {
    const values = new Map((rows || []).map((row) => [String(row.day), Number(row.test_seconds || 0)]));
    const result = [];
    const end = new Date();
    end.setUTCHours(0, 0, 0, 0);
    end.setUTCDate(end.getUTCDate() - offsetDays);
    for (let index = days - 1; index >= 0; index -= 1) {
      const date = new Date(end);
      date.setUTCDate(date.getUTCDate() - index);
      const day = date.toISOString().slice(0, 10);
      result.push({ day, seconds: values.get(day) || 0 });
    }
    return result;
  }

  function testTrendChart(stats) {
    const days = Math.max(1, Math.min(365, Number(stats.days || state.testsDays || 30)));
    const current = testSeries(stats.daily, days, 0);
    const previous = testSeries(stats.previous_daily, days, days);
    const values = [...current, ...previous].map((item) => item.seconds);
    const maxValue = Math.max(1, ...values);
    const width = 1000;
    const height = 190;
    const padX = 8;
    const padY = 12;
    const points = (series) => series.map((item, index) => {
      const x = padX + (index / Math.max(1, series.length - 1)) * (width - padX * 2);
      const y = height - padY - (item.seconds / maxValue) * (height - padY * 2);
      return { ...item, x, y };
    });
    const currentPoints = points(current);
    const previousPoints = points(previous);
    const svg = svgEl('svg', {
      class: 'test-trend-chart', viewBox: `0 0 ${width} ${height}`,
      preserveAspectRatio: 'none', role: 'img',
      'aria-label': 'Daily aggregate testing time compared with the previous period',
    });
    for (const ratio of [0, .5, 1]) {
      const y = padY + ratio * (height - padY * 2);
      svg.append(svgEl('line', { class: 'test-trend-grid', x1: padX, y1: y, x2: width - padX, y2: y }));
    }
    const currentLine = currentPoints.map((point) => `${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(' ');
    const previousLine = previousPoints.map((point) => `${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(' ');
    svg.append(
      svgEl('polygon', {
        class: 'test-trend-area',
        points: `${padX},${height - padY} ${currentLine} ${width - padX},${height - padY}`,
      }),
      svgEl('polyline', { class: 'test-trend-previous', fill: 'none', points: previousLine }),
      svgEl('polyline', { class: 'test-trend-current', fill: 'none', points: currentLine }),
    );
    const differences = currentPoints.map((point, index) => point.seconds - previousPoints[index].seconds);
    const riseIndex = differences.indexOf(Math.max(...differences));
    const fallIndex = differences.indexOf(Math.min(...differences));
    for (const [index, kind] of [[riseIndex, 'rise'], [fallIndex, 'fall']]) {
      const point = currentPoints[index];
      if (!point || Math.abs(differences[index]) < 1) continue;
      svg.append(
        svgEl('line', { class: `test-trend-marker is-${kind}`, x1: point.x, y1: padY, x2: point.x, y2: height - padY }),
        svgEl('circle', { class: `test-trend-dot is-${kind}`, cx: point.x, cy: point.y, r: 4 }),
      );
    }
    const first = current[0]?.day || '';
    const middle = current[Math.floor(current.length / 2)]?.day || '';
    const last = current.at(-1)?.day || '';
    return h('section', { class: 'test-trend-panel' },
      h('div', { class: 'test-panel-title' },
        h('h3', null, 'Testing time trend'),
        h('div', { class: 'test-trend-legend' },
          h('span', { class: 'is-current' }, 'Current period'),
          h('span', { class: 'is-previous' }, 'Previous period'))),
      h('div', { class: 'test-trend-wrap' },
        h('div', { class: 'test-trend-y' }, h('span', null, fmtSeconds(maxValue)), h('span', null, fmtSeconds(maxValue / 2)), h('span', null, '0s')),
        svg),
      h('div', { class: 'test-trend-x' }, h('span', null, first), h('span', null, middle), h('span', null, last)));
  }

  function testSummary(stats) {
    const { summary, change, peakHour, busiestDay, deltaClass } = testSummaryDetails(stats);
    return h('aside', { class: 'test-summary' },
      h('h3', null, `${stats.days || state.testsDays}-day summary`),
      h('strong', { class: 'test-summary-total' }, fmtSeconds(summary.test_seconds || 0)),
      h('span', { class: 'test-summary-label' }, 'Total testing time'),
      h('div', { class: `test-summary-delta ${deltaClass}` },
        h('strong', null, testDeltaText(change)), h('span', null, `vs previous ${stats.days || state.testsDays} days`)),
      h('dl', { class: 'test-summary-facts' },
        h('div', null, h('dt', null, 'Peak hour'), h('dd', null, Number.isInteger(peakHour) ? `${String(peakHour).padStart(2, '0')}:00 UTC` : '—')),
        h('div', null, h('dt', null, 'Busiest day'), h('dd', null, busiestDay ? testDayLabel(busiestDay) : '—'))));
  }

  function renderTestHeader(stats) {
    $('#tests-comparison').textContent = `Previous ${state.testsDays} days`;
    $('#tests-updated').textContent = state.testsLoadedAt ? `Updated ${fmtWhen(new Date(state.testsLoadedAt).toISOString())}` : 'Waiting for data';
    const rate = testPassRate(stats?.summary);
    $('#tests-pass-rate').textContent = Number.isFinite(rate) ? `${rate.toFixed(1)}%` : '—';
    $('#tests-failed-runs').textContent = stats
      ? String(stats.summary?.failed_run_count ?? (stats.recent_runs || []).filter((run) => ['failed', 'incomplete'].includes(run.status)).length)
      : '—';
  }

  function renderTests() {
    if (currentPage() !== 'tests') return;
    const host = $('#tests-body');
    renderTestHeader(state.tests);
    if (state.testsLoading && !state.tests) {
      host.replaceChildren(h('div', { class: 'skel', 'aria-hidden': 'true' }), h('div', { class: 'skel', 'aria-hidden': 'true' }));
      return;
    }
    const stats = state.tests;
    if (!state.testsProject) {
      if (!state.testsRepositories && !state.overview && !state.metrics) {
        host.replaceChildren(
          h('div', { class: 'skel', 'aria-hidden': 'true' }),
          h('div', { class: 'skel', 'aria-hidden': 'true' }),
        );
        return;
      }
      host.replaceChildren(emptyState('No enrolled repositories are available for test statistics.'));
      return;
    }
    if (!stats) {
      host.replaceChildren(emptyState('Test statistics are unavailable.'));
      return;
    }
    renderTestHeader(stats);
    const dynamicsRows = (stats.dynamics || []).map((row) => {
      const change = row.change_percent === null || row.change_percent === undefined
        ? Number.NaN
        : Number(row.change_percent);
      const changeClass = Number.isFinite(change) ? (change > 0 ? 'is-worse' : 'is-better') : '';
      return h('tr', null,
        h('td', { class: 'mono test-name' }, row.suite),
        h('td', null, fmtSeconds(row.current_seconds)),
        h('td', null, fmtSeconds(row.previous_seconds)),
        h('td', { class: `test-dynamic-change ${changeClass}` }, testDeltaText(change)),
        h('td', null, row.failure_count),
        h('td', null, row.last_run ? fmtWhen(row.last_run) : '—'));
    });
    host.replaceChildren(
      h('div', { class: 'test-overview-grid' }, testHeatmap(stats), testSummary(stats)),
      testTrendChart(stats),
      testTable('Largest dynamics', ['Suite / test set', 'Current time', 'Previous time', 'Change', 'Failures', 'Last run'], dynamicsRows),
    );
  }

  // ---------------------------------------------------------------- render root

  const SECTION_BODY_PAGES = Object.freeze({
    'projects-body': 'projects',
    'tests-body': 'tests',
    'routes-body': 'routes',
    'servers-body': 'servers',
    'docker-body': 'docker',
    'leases-body': 'ports',
    'assignments-body': 'ports',
    'perf-body': 'performance',
    'usage-body': 'performance',
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
    unmountInactiveSections(page);
    const o = state.overview;
    if (!o) {
      if (page === 'performance') {
        setSection('usage-body', sig('overview-loading'),
          () => [emptyState('Loading current project usage…')], force);
        setSection('perf-body', sig(state.metricsAt, 'metrics-only'), () => buildPerf(null), force);
        const count = state.metrics
          ? (state.metrics.entities || []).filter((e) => e.kind === 'server' || e.kind === 'docker').length
          : null;
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
          o.inventory?.resources?.databases ?? null, o.routes ?? null, state.archives,
          ui.lifecycleViews.projects, coordSig),
        () => ui.lifecycleViews.projects === 'archived'
          ? buildArchivedCollection('projects') : buildProjects(o), force);
    } else if (page === 'tests') {
      renderTests();
    } else if (page === 'routes') {
      setSection('routes-body', sig(o.routes), () => buildRoutes(o), force);
    } else if (page === 'servers') {
      setSection('servers-body',
        sig(o.inventory?.servers ?? null, o.inventory?.port_assignments ?? null,
          o.inventory?.docker ?? null, o.inventory?.repository_trees ?? null,
          o.inventory?.resources?.databases ?? null, o.routes ?? null, state.archives,
          ui.lifecycleViews.servers, coordSig),
        () => ui.lifecycleViews.servers === 'archived'
          ? buildArchivedCollection('servers') : buildServers(o), force);
    } else if (page === 'docker') {
      setSection('docker-body',
        sig(o.inventory?.docker ?? null, o.inventory?.repository_trees ?? null,
          o.inventory?.resources?.databases ?? null, o.routes ?? null, state.archives,
          ui.lifecycleViews.docker, coordSig),
        () => ui.lifecycleViews.docker === 'archived'
          ? buildArchivedCollection('docker') : buildDocker(o), force);
    } else if (page === 'ports') {
      setSection('leases-body', sig(o.inventory?.leases ?? null, coordSig), () => buildLeases(o), force);
      setSection('assignments-body', sig(o.inventory?.port_assignments ?? null, coordSig), () => buildAssignments(o), force);
    } else if (page === 'performance') {
      setSection('usage-body',
        sig(o.inventory?.project_usage ?? null, o.inventory?.repository_trees ?? null,
          o.inventory?.resources?.databases ?? null, coordSig),
        () => buildUsage(o), force);
      setSection('perf-body', sig(state.metricsAt, o.inventory ? 1 : 0, coordSig), () => buildPerf(o), force);
    } else if (page === 'invites') {
      renderInvites();
    } else if (page === 'telegram') {
      renderTelegram();
    }

    const perfEntities = state.metrics
      ? (state.metrics.entities || []).filter((e) => e.kind === 'server' || e.kind === 'docker').length
      : null;
    const projectGroups = o.inventory ? projectGroupsOf(o).length : null;
    // The Servers page lists coordinator servers plus docker-hosted web
    // servers, so its badges count both.
    const webContainerCount = o.inventory
      ? projectGroupsOf(o).reduce(
          (n, g) => n + g.members.containers.filter((c) => isWebServerContainer(o, g, c)).length, 0)
      : 0;
    setCount('projects-count', ui.lifecycleViews.projects === 'archived'
      ? (archivesCurrent ? archivesForPage('projects').length : null) : projectGroups);
    setCount('tests-count', state.tests?.summary?.test_count ?? null);
    setCount('routes-count', (o.routes || []).length);
    setCount('servers-count', ui.lifecycleViews.servers === 'archived'
      ? (archivesCurrent ? archivesForPage('servers').length : null)
      : o.inventory ? (o.inventory.servers || []).length + webContainerCount : null);
    setCount('docker-count', ui.lifecycleViews.docker === 'archived'
      ? (archivesCurrent ? archivesForPage('docker').length : null)
      : o.inventory?.docker?.available ? (o.inventory.docker.containers || []).length : null);
    setCount('leases-count', o.inventory ? (o.inventory.leases || []).length : null);
    setCount('assignments-count', o.inventory ? (o.inventory.port_assignments || []).length : null);
    setCount('usage-count', o.inventory
      ? (Array.isArray(o.inventory.repository_trees)
          ? projectGroupsOf(o).filter((group) => group.row).length
          : (o.inventory.project_usage || []).length)
      : null);
    setCount('perf-count', perfEntities);
    setCount('projects-active-count', projectGroups);
    setCount('servers-active-count', o.inventory ? (o.inventory.servers || []).length + webContainerCount : null);
    setCount('docker-active-count', o.inventory?.docker?.available ? (o.inventory.docker.containers || []).length : null);
    syncLifecycleFilters();

    setNavCount('projects', projectGroups);
    setNavCount('tests', state.tests?.summary?.test_count ?? null);
    setNavCount('servers', o.inventory ? (o.inventory.servers || []).length + webContainerCount : null);
    setNavCount('routes', (o.routes || []).length);
    setNavCount('docker', o.inventory?.docker?.available ? (o.inventory.docker.containers || []).length : null);
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

    const scrolls = new Map();
    for (const el of host.querySelectorAll('[data-scrollkey]')) scrolls.set(el.dataset.scrollkey, el.scrollTop);
    const active = document.activeElement;
    const fk = active && host.contains(active) ? active.dataset.fk : null;

    const nodes = build();
    host.replaceChildren(...(Array.isArray(nodes) ? nodes.filter(Boolean) : [nodes]));

    for (const el of host.querySelectorAll('[data-scrollkey]')) {
      if (scrolls.has(el.dataset.scrollkey)) el.scrollTop = scrolls.get(el.dataset.scrollkey);
    }
    if (fk) {
      const again = host.querySelector(`[data-fk="${CSS.escape(fk)}"]`);
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

    const c = o.coordinator || {};
    const coordOk = !!c.ok && !!o.inventory;
    if (!coordOk && c.failureKind !== 'maintenance') {
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

    if (state.stale && state.lastFetch) {
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
    if (o?.coordinator?.inventoryState === 'loading') {
      return h('p', { class: 'empty' }, 'Loading live Coordinator inventory…');
    }
    const maintenance = o?.coordinator?.failureKind === 'maintenance';
    return h('div', {
      class: `degraded${maintenance ? ' maintenance' : ''}`,
      role: maintenance ? 'status' : null,
    },
      icon(maintenance ? 'refresh' : 'warn'),
      h('div', null,
        h('p', { class: 'deg-title' }, coordinatorFailureTitle(o)),
        h('p', { class: 'deg-msg' }, coordErrorText(o)),
        maintenance ? h('p', { class: 'deg-hint' }, coordinatorFailureHint(o)) : h('button', {
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
      return [emptyState(`No routes yet — use the form above to publish a dev server at https://<name>.${domain}.`)];
    }
    const out = [
      h('div', { class: 'grid-head routes-grid', 'aria-hidden': 'true' },
        h('span', null, 'URL'), h('span', null, 'Target'), h('span', null, 'Status'),
        h('span', null, 'Access'), h('span', null, '')),
    ];
    for (const r of routes) out.push(h('div', { class: 'item' }, routeRow(o, r)));
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

  function wireForm() {
    const form = $('#route-form');
    const slug = $('#rf-slug');
    const access = $('#rf-access');

    slug.addEventListener('input', () => {
      const lower = slug.value.toLowerCase();
      if (lower !== slug.value) slug.value = lower;
      updatePreview();
    });

    for (const radio of form.querySelectorAll('input[name="rf-kind"]')) {
      radio.addEventListener('change', () => {
        const kind = form.querySelector('input[name="rf-kind"]:checked').value;
        $('#rf-port-wrap').hidden = kind !== 'port';
        $('#rf-server-wrap').hidden = kind !== 'server';
        $('#rf-container-wrap').hidden = kind !== 'docker';
      });
    }

    access.addEventListener('click', () => {
      const now = access.getAttribute('aria-checked') === 'true';
      access.setAttribute('aria-checked', String(!now));
      access.classList.toggle('public-on', now);
      $('#rf-access-text').textContent = now ? 'Public — no sign-in' : 'Google sign-in required';
    });

    form.addEventListener('submit', onCreateRoute);
    updatePreview();
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
      $('#rf-slug').value = '';
      $('#rf-title').value = '';
      // Access always snaps back to the safe default for the next route.
      const access = $('#rf-access');
      access.setAttribute('aria-checked', 'true');
      access.classList.remove('public-on');
      $('#rf-access-text').textContent = 'Google sign-in required';
      updatePreview();
      announce(`Route ${slug}.${domain} created`);
      await refreshOverview({ force: true, fresh: true });
    } catch (err) {
      if (err.status !== 401) {
        fail(err.message);
        showBanner(err, () => $('#route-form').requestSubmit());
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
      options.confirmText ? { confirmText: options.confirmText } : undefined,
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
    const button = (action, label, iconName, options = {}) => h('button', {
      class: `btn small act-${action}${busy ? ' is-busy' : ''}`, type: 'button',
      'data-fk': `${prefix}-worker-${action}:${server.id}`,
      disabled: (busy || options.disabled) || undefined,
      title: options.title || `${label} ${server.name}`,
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

  function buildServers(o) {
    if (!o.inventory) return [degradedPanel(o)];
    const inventoryError = authoritativeInventoryErrorPanel(o);
    if (inventoryError) return [inventoryError];
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
      return [emptyState('No dev servers registered with the coordinator yet — start one with "server start" and it appears here.')];
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
    const archiveTarget = ownership.genericLifecycle
      ? lifecycleTarget('container', c.host_resource_id, name, 'docker', {
          projectId: c.repo_id || null,
        })
      : null;

    const chev = h('button', {
      class: `chev${open ? ' open' : ''}`, type: 'button',
      'data-fk': `srv-dock-x:${name}`,
      'aria-expanded': String(open),
      'aria-controls': panelId,
      'aria-label': `${open ? 'Collapse' : 'Expand'} logs for ${name}`,
      title: open ? 'Collapse logs' : 'Expand container logs',
      onclick: () => toggleDocker(name),
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
      disabled: busy || undefined,
      title: `${label} container ${name}`,
      onclick: () => runAction(`docker:${name}`,
        () => api('/api/docker/action', { method: 'POST', body: { name, action } }),
        confirmText ? { confirmText } : undefined),
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
        toggleDocker(name);
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
      h('span', { class: 'cell mono', 'data-label': 'Port' }, portCell),
      usageCellNode({
        key: `dock:${name}`,
        title: name,
        cpu: c.stats?.cpu_percent ?? null,
        mem: c.stats?.memory_usage_bytes ?? null,
        running: running && !!c.stats,
        scope: 'srv',
      }),
      h('span', { class: 'cell', 'data-label': 'Status' }, badge),
      h('span', { 'aria-hidden': 'true' }),
      h('span', { class: 'cell actions' },
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

  function serverItem(o, s, hiddenRow = false) {
    const id = s.id;
    const open = ui.expanded.has(id);
    const busy = ui.busy.has(`server:${id}`);
    const meta = serverStatusMeta(s);
    const panelId = `srv-panel-${id}`;
    const archiveTarget = lifecycleTarget('server', id, s.name || 'Unnamed server', 'servers');

    const chev = h('button', {
      class: `chev${open ? ' open' : ''}`, type: 'button',
      'data-fk': `srv-x:${id}`,
      'aria-expanded': String(open),
      'aria-controls': panelId,
      'aria-label': `${open ? 'Collapse' : 'Expand'} details for ${s.name}`,
      title: open ? 'Collapse details' : 'Expand details and logs',
      onclick: () => toggleServer(id),
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
    const actions = h('span', { class: 'cell actions' },
      supervised ? workerControlButtons(s, busy) : h('button', {
        class: `btn small act-restart${busy ? ' is-busy' : ''}`, type: 'button',
        'data-fk': `srv-restart:${id}`,
        disabled: (busy || s.missing_command || !restartable) || undefined,
        title: !restartable
          ? 'No observed server instance is available to restart'
          : s.missing_command
          ? 'Registered without a start command — cannot be restarted from here'
          : `Restart ${s.name} on the same port`,
        onclick: () => runAction(`server:${id}`,
          () => api('/api/servers/action', { method: 'POST', body: { id, action: 'restart' } })),
      }, icon('refresh'), busy ? 'Working…' : 'Restart'),
      supervised ? null : h('button', {
        class: `btn small act-stop${busy ? ' is-busy' : ''}`, type: 'button',
        'data-fk': `srv-stop:${id}`,
        disabled: (busy || !stoppable) || undefined,
        title: stoppable ? `Stop ${s.name}` : 'Server is not running',
        onclick: () => runAction(`server:${id}`,
          () => api('/api/servers/action', { method: 'POST', body: { id, action: 'stop' } })),
      }, icon('stop'), busy ? 'Working…' : 'Stop'),
      hiddenRow
        ? unhideButton('servers', s.key, s.name || 'server')
        : (s.status === 'stopped' ? hideButton('servers', s.key, s.name || 'server') : ghostIconSlot()),
      supervised
        ? workerRemoveButton(s, { compact: true })
        : archiveButton(archiveTarget, { compact: true }));

    const row = h('div', {
      class: `row srv-grid expandable${hiddenRow ? ' is-hidden' : ''}`,
      tabindex: '-1',
      'data-lifecycle-target': `${archiveTarget.target_kind}:${archiveTarget.target_id}`,
      onclick: (e) => {
        if (e.target.closest('button, a, input, select')) return;
        toggleServer(id);
      },
    },
      chev,
      h('span', { class: 'cell c-primary', 'data-label': 'Server' },
        h('span', { class: 'srv-name' },
          h('strong', null, s.name || '—'),
          ' ',
          h('span', { class: 'dim', title: s.project || '' }, projectTail(s.project))),
        subdomainControl(o, s)),
      h('span', { class: 'cell mono', 'data-label': 'Port' }, serverPortCell(o, s)),
      usageCellNode({
        key: `srv:${id}`,
        title: s.name || 'Server',
        cpu: s.process_usage?.cpu_percent ?? null,
        mem: s.process_usage?.memory_bytes ?? null,
        running: !!s.process_usage,
      }),
      h('span', { class: 'cell', 'data-label': 'Status' }, badge),
      warnFlag,
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
        opts),
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
        opts),
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
    const save = h('button', { class: 'btn primary small', type: 'button' }, route ? 'Update' : 'Assign');

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
      }, chosenPort());
    };

    const remove = route
      ? h('button', {
          class: 'btn small danger', type: 'button',
          'aria-label': `Remove the ${route.slug}.${domain} subdomain`, title: 'Remove subdomain (server keeps running)',
          onclick: () => spec.save('', access, {
            confirmText: `Remove https://${route.slug}.${domain}?\n\nThe dev server keeps running — only this public URL stops working.`,
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

  function toggleServer(id) {
    if (ui.expanded.has(id)) {
      ui.expanded.delete(id);
    } else {
      ui.expanded.add(id);
      const cached = ui.logs.get(`srv:${id}`);
      if (!cached || (cached.text == null && !cached.loading)) loadServerLogs(id);
    }
    bump();
    renderAll(true);
  }

  async function loadServerLogs(id) {
    const key = `srv:${id}`;
    ui.logs.set(key, { ...(ui.logs.get(key) || {}), loading: true, error: null });
    bump();
    renderAll(true);
    try {
      const resp = await api('/api/servers/logs', { method: 'POST', body: { id, tail: 200 } });
      ui.logs.set(key, { loading: false, text: resp?.text ?? '', error: null, at: Date.now() });
    } catch (err) {
      if (err.status === 401) return;
      ui.logs.set(key, { loading: false, text: null, error: err.message, at: Date.now() });
      showBanner(err, () => loadServerLogs(id));
    }
    bump();
    renderAll(true);
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
    return h('div', { class: 'panel', id: panelId },
      workerSupervisionPanel(s),
      h('div', { class: 'panel-meta' },
        kv('PID', s.pid != null ? String(s.pid) : '—', { mono: true }),
        kv('Working dir', s.cwd || '—', { mono: true }),
        kv('Command', s.cmd || s.cmd_template || '—', { mono: true }),
        kv('Log file', s.log_path || '—', { mono: true })),
      h('div', { class: 'panel-toolbar' },
        h('span', { class: 'panel-title' }, 'Recent log'),
        lg?.at ? h('span', { class: 'meta-passive' }, `fetched ${fmtClock(lg.at)}`) : null,
        h('button', {
          class: 'btn small', type: 'button',
          'data-fk': `srv-logs-refresh:${s.id}`,
          disabled: lg?.loading || undefined,
          title: 'Fetch the latest 200 log lines',
          onclick: () => loadServerLogs(s.id),
        }, icon('refresh'), lg?.loading ? 'Loading…' : 'Refresh')),
      logboxNode(key, lg));
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
      return [emptyState('No containers found — anything started with docker run or compose shows up here.')];
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
      disabled: busy || undefined,
      title: `${label} ${name}`,
      onclick: () => runAction(`docker:${name}`,
        () => api('/api/docker/action', { method: 'POST', body: { name, action } }),
        confirmText ? { confirmText } : undefined),
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
        toggleDocker(name);
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
          onclick: () => toggleDocker(name),
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

  function toggleDocker(name) {
    if (ui.dockerOpen.has(name)) {
      ui.dockerOpen.delete(name);
    } else {
      ui.dockerOpen.add(name);
      const cached = ui.logs.get(`dock:${name}`);
      if (!cached || (cached.text == null && !cached.loading)) loadDockerLogs(name);
    }
    bump();
    renderAll(true);
  }

  async function loadDockerLogs(name) {
    const key = `dock:${name}`;
    ui.logs.set(key, { ...(ui.logs.get(key) || {}), loading: true, error: null });
    bump();
    renderAll(true);
    try {
      const resp = await api('/api/docker/logs', { method: 'POST', body: { name, tail: 120 } });
      const text = typeof resp?.text === 'string'
        ? resp.text
        : [resp?.stdout, resp?.stderr].filter(Boolean).join('\n');
      ui.logs.set(key, { loading: false, text: text ?? '', error: null, at: Date.now() });
    } catch (err) {
      if (err.status === 401) return;
      ui.logs.set(key, { loading: false, text: null, error: err.message, at: Date.now() });
      showBanner(err, () => loadDockerLogs(name));
    }
    bump();
    renderAll(true);
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
          onclick: () => loadDockerLogs(c.name),
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
      return [emptyState('No active port leases — lease one with the form above, or through the coordinator CLI, and it shows up here with its expiry.')];
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
      return (h('div', { class: 'item' },
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

  function wireLeaseForm() {
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
      $('#lf-purpose').value = '';
      $('#lf-preferred').value = '';
      $('#lf-project').value = '';
      announce(`Port ${resp?.lease?.port ?? ''} leased`);
      await refreshOverview({ force: true, fresh: true });
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

  // ---------------------------------------------------------------- usage

  function buildUsage(o) {
    if (!o.inventory) return [degradedPanel(o)];
    const inventoryError = authoritativeInventoryErrorPanel(o);
    if (inventoryError) return [inventoryError];
    const authoritative = Array.isArray(o.inventory.repository_trees);
    const groups = authoritative ? projectGroupsOf(o).filter((group) => group.row) : [];
    const items = authoritative ? groups.map((group) => ({ ...group.row, metricsKey: group.metricsKey }))
      : (o.inventory.project_usage || []);
    if (!items.length) {
      return [emptyState('No per-project usage measured yet — start a server or container and its CPU/memory appears here.')];
    }
    const maxMem = Math.max(1, ...items.map((p) => p.memory_bytes || 0));
    const maxCpu = Math.max(100, ...items.map((p) => p.cpu_percent || 0));
    return items.map((p) => {
      const key = p.metricsKey || `proj:${p.usage_key ?? p.project_key ?? p.project ?? p.name}`;
      const familyLabel = p.temporary_repo_count > 0
        ? `Family total · root + ${p.temporary_repo_count} temporary repo${sfx(p.temporary_repo_count)}`
        : null;
      return h('div', { class: 'usage-item' },
        h('div', { class: 'usage-head' },
          h('strong', { title: p.project || '' }, p.name || projectTail(p.project)),
          sparkline(metricsEntity(key)),
          h('span', { class: 'meta-passive' },
            familyLabel ? `${familyLabel} · ` : '',
            `${p.server_count || 0} server${sfx(p.server_count || 0)} · `
            + `${p.container_count || 0} container${sfx(p.container_count || 0)} · `
            + `${p.process_count || 0} process${(p.process_count || 0) === 1 ? '' : 'es'}`)),
        barRow('CPU', `${(p.cpu_percent ?? 0).toFixed(1)}%`, (p.cpu_percent || 0) / maxCpu, false),
        barRow('Memory', fmtBytes(p.memory_bytes || 0), (p.memory_bytes || 0) / maxMem, true));
    });
  }

  function barRow(label, valueText, frac, isMem) {
    const fill = h('div', { class: `fill${isMem ? ' mem' : ''}` });
    fill.style.width = `${Math.min(100, Math.max(2, frac * 100)).toFixed(1)}%`;
    return h('div', { class: 'bar-row' },
      h('span', { class: 'bar-label' }, label),
      h('div', { class: 'bar', 'aria-hidden': 'true' }, fill),
      h('span', { class: `bar-val mono ${isMem ? 'u-mem' : 'u-cpu'}` }, valueText));
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
    runAction(`project:${group.key}`,
      () => api('/api/projects/action', { method: 'POST', body: { project: group.project, action } }),
      confirms[action] ? { confirmText: confirms[action] } : undefined);
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
    const slot = (action, label, iconName) => ({
      fk: `proj-${action}:${group.key}`,
      label,
      icon: iconName,
      busy,
      disabled: noPath,
      title: noPath
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
    const detail = supervised
      ? `${s.supervision.keep_alive === true ? 'Keep alive on' : 'Keep alive off'}${s.url ? ` · ${s.url}` : ''}`
      : (s.url || '');
    const archiveTarget = lifecycleTarget('server', s.id, s.name || 'Unnamed server', 'servers');
    const slot = (action, label, iconName, disabled, title) => ({
      fk: `tree-srv-${action}-${label}:${s.id}`,
      label,
      icon: iconName,
      busy,
      disabled,
      title,
      onclick: () => runAction(`server:${s.id}`,
        () => api('/api/servers/action', { method: 'POST', body: { id: s.id, action } })),
    });
    return h('div', {
      class: `row tree-grid tree-item${hiddenRow ? ' is-hidden' : ''}`,
      tabindex: '-1',
      'data-lifecycle-target': `${archiveTarget.target_kind}:${archiveTarget.target_id}`,
    },
      h('span', { class: 'cell c-kind' },
        h('span', { class: 'kind-tag k-srv' }, supervised ? 'worker' : 'server')),
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
        supervised ? workerControlButtons(s, busy, 'tree') : treeActionSlots({
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
          : archiveButton(archiveTarget, { compact: true })));
  }

  function treeContainerRow(o, c, isDb, hiddenRow, webish = false) {
    const busy = ui.busy.has(`docker:${c.name}`);
    const running = isContainerRunning(c);
    const ownership = containerOwnershipState(c);
    const archiveTarget = ownership.genericLifecycle
      ? lifecycleTarget('container', c.host_resource_id, c.name, 'docker')
      : null;
    const slot = (action, label, iconName, disabled, title, confirmText) => ({
      fk: `tree-dock-${action}:${c.name}`,
      label,
      icon: iconName,
      busy,
      disabled: !ownership.genericLifecycle || disabled,
      title: ownership.genericLifecycle
        ? title
        : (ownership.ephemeral
            ? `${label} is unavailable here; use coordinator ephemeral renew or finish`
            : `${label} is unavailable until the coordinator proves one repository owner`),
      onclick: ownership.genericLifecycle
        ? () => runAction(`docker:${c.name}`,
            () => api('/api/docker/action', { method: 'POST', body: { name: c.name, action } }),
            confirmText ? { confirmText } : undefined)
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
        h('span', { class: `kind-tag ${isDb ? 'k-db' : 'k-dock'}` }, isDb ? 'database' : 'container')),
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
      h('span', { class: 'kind-tag k-temp' }, 'temporary'),
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
      h('h4', { class: `temporary-scope-head${expanded ? ' is-open' : ''}` }, toggle),
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
    const chev = h('button', {
      class: `chev${collapsed ? '' : ' open'}`, type: 'button',
      'data-fk': `tree-x:${group.key}`,
      'aria-expanded': String(!collapsed),
      'aria-label': `${collapsed ? 'Expand' : 'Collapse'} project ${group.name}`,
      title: collapsed ? 'Expand project' : 'Collapse project',
      onclick: () => {
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
      },
    }, icon('chevron'));

    const header = h('div', {
      class: `row tree-grid tree-head${hiddenProject ? ' is-hidden' : ''}`,
      title: group.project || '',
      tabindex: '-1',
      'data-lifecycle-target': archiveTarget
        ? `${archiveTarget.target_kind}:${archiveTarget.target_id}` : null,
    },
      h('span', { class: 'cell c-kind' }, chev),
      h('span', { class: 'cell c-primary' },
        group.authoritative ? h('span', { class: 'kind-tag k-root' }, 'root') : null,
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
      h('span', { class: 'cell actions' },
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
    const groups = projectGroupsOf(o);
    if (!groups.length) {
      return [emptyState('No projects yet — anything an agent starts or registers through the coordinator appears here, grouped by repo.')];
    }
    const hiddenProjects = hiddenSet('projects');
    const hiddenServers = hiddenSet('servers');
    const hiddenDocker = hiddenSet('docker');
    const focus = ui.lifecycleFocus?.view === 'active' && ui.lifecycleFocus.page === 'projects'
      ? ui.lifecycleFocus : null;
    if (focus) ui.reveal.add('projects');
    const revealing = ui.reveal.has('projects');

    let hiddenCount = 0;
    const out = [];
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

  // Overall machine health: CPU, memory, storage, load and uptime for the
  // box everything above runs on, with the same history charts as any row.
  function hostPanel() {
    const info = state.metrics?.host;
    if (!info) return null;

    const meter = (frac, alarm) => {
      const fill = h('div', { class: `fill${alarm ? ' alarm' : ''}` });
      fill.style.width = `${Math.min(100, Math.max(2, (frac || 0) * 100)).toFixed(1)}%`;
      return h('div', { class: 'host-meter', 'aria-hidden': 'true' }, fill);
    };
    const tile = ({ label, value, sub, frac, alarm, valueClass }) => h('div', { class: `host-tile${alarm ? ' alarm' : ''}` },
      h('span', { class: 'host-tile-label' }, label),
      h('strong', { class: `host-tile-value mono${valueClass ? ` ${valueClass}` : ''}` }, value),
      sub ? h('span', { class: 'host-tile-sub' }, sub) : null,
      frac !== undefined ? meter(frac, alarm) : null);

    const tiles = [];
    const cpu = info.cpuPercent;
    const load = (info.load || []).map((n) => n.toFixed(2)).join(' · ');
    tiles.push(tile({
      label: 'CPU',
      value: cpu === null || cpu === undefined ? '—' : fmtCpu(cpu),
      valueClass: 'u-cpu',
      sub: `${info.cores ?? '—'} cores · load ${load}`,
      frac: cpu === null || cpu === undefined ? 0 : cpu / 100,
      alarm: cpu > 90,
    }));

    const mem = info.mem || {};
    const memFrac = mem.totalBytes ? (mem.usedBytes || 0) / mem.totalBytes : 0;
    tiles.push(tile({
      label: 'Memory',
      value: `${fmtBytes(mem.usedBytes || 0)} / ${fmtBytes(mem.totalBytes || 0)}`,
      valueClass: 'u-mem',
      sub: `${(memFrac * 100).toFixed(0)}% used · ${fmtBytes(mem.availableBytes || 0)} available`,
      frac: memFrac,
      alarm: memFrac > 0.9,
    }));

    for (const disk of info.disks || []) {
      const frac = disk.totalBytes ? (disk.usedBytes || 0) / disk.totalBytes : 0;
      tiles.push(tile({
        label: `Storage ${disk.mount}`,
        value: `${fmtBytes(disk.usedBytes || 0)} / ${fmtBytes(disk.totalBytes || 0)}`,
        sub: `${(frac * 100).toFixed(0)}% used · ${fmtBytes(disk.availableBytes || 0)} free`,
        frac,
        alarm: frac > 0.9,
      }));
    }

    tiles.push(tile({
      label: 'Uptime',
      value: fmtUptime(info.uptimeSec),
      sub: 'since last boot',
    }));

    const ent = metricsEntity('host');
    const charts = ent && ent.points.length >= 2
      ? h('div', { class: 'host-charts' },
          chartBlock('CPU', ent.points, (p) => p[1], fmtCpu, 'c-cpu'),
          chartBlock('Memory used', ent.points, (p) => p[2], fmtBytes, 'c-mem'))
      : h('p', { class: 'pop-hint' }, 'History charts appear after a couple of samples.');

    return h('div', { class: 'host-panel' },
      h('div', { class: 'host-head' },
        h('strong', null, 'Machine'),
        h('span', { class: 'meta-passive' }, 'everything below runs on this box')),
      h('div', { class: 'host-tiles' }, ...tiles),
      charts);
  }

  function buildPerf(o) {
    const m = state.metrics;
    if (!m) {
      return [emptyState('Collecting metrics — charts appear after the first samples.')];
    }
    const out = [];
    if (m.sampler?.lastError) {
      out.push(h('p', { class: 'inline-note warn-note' },
        `Sampling is failing right now (${m.sampler.lastError}) — charts show the last collected history.`));
    }

    const hp = hostPanel();
    if (hp) out.push(hp);

    // Live inventory tells us which charted entities are still running.
    const running = new Set();
    for (const s of o?.inventory?.servers || []) {
      if (s.process_usage) running.add(`srv:${s.id}`);
    }
    if (o?.inventory?.docker?.available) {
      for (const c of o.inventory.docker.containers || []) {
        if (isContainerRunning(c)) running.add(`dock:${c.name}`);
      }
    }

    const entities = (m.entities || []).filter((e) => e.kind === 'server' || e.kind === 'docker');
    if (entities.length) {
      out.push(h('p', { class: 'perf-sec-title' }, 'Servers & containers'));
    }
    if (!entities.length) {
      out.push(emptyState('Nothing to chart yet — start a dev server or container and its CPU/memory history appears here.'));
      return out;
    }
    // Same stable-ordering contract as the list pages: running cards first,
    // then name/key — never current load, which changes every sample.
    entities.sort((a, b) => (running.has(b.key) ? 1 : 0) - (running.has(a.key) ? 1 : 0)
      || String(a.name).localeCompare(String(b.name))
      || String(a.key).localeCompare(String(b.key)));
    out.push(h('div', { class: 'perf-grid' }, entities.map((e) => perfCard(e, running.has(e.key)))));
    return out;
  }

  function perfCard(e, isRunning) {
    const points = e.points || [];
    return h('div', { class: `perf-card${isRunning ? '' : ' stale'}` },
      h('div', { class: 'perf-head' },
        h('span', { class: `kind-tag ${e.kind === 'docker' ? 'k-dock' : 'k-srv'}` },
          e.kind === 'docker' ? 'container' : 'server'),
        h('strong', { class: 'perf-name', title: e.project || '' }, e.name || e.key),
        h('span', { class: 'dim' }, projectTail(e.project)),
        isRunning ? null : h('span', { class: 'meta-passive' }, 'not running — recent history')),
      chartBlock('CPU', points, (p) => p[1], fmtCpu, 'c-cpu'),
      chartBlock('Memory', points, (p) => p[2], fmtBytes, 'c-mem'));
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
      }
    }, POLL_MS);
    setInterval(() => {
      if (!document.hidden) refreshMetrics();
    }, METRICS_POLL_MS);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        refreshOverview();
        refreshMetrics();
        // Pick up hides made on another device while this tab slept.
        loadPrefs();
        if (state.session?.accessAdmin === true) loadAccess({ force: true });
        if (state.session?.accessAdmin === true) loadInvites({ force: true });
        if (state.session?.email) loadTelegram({ force: true });
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
        if (s.accessAdmin === true) {
          loadAccess();
          loadInvites();
        }
        if (lifecycleAvailable()) {
          loadArchives();
        }
        loadTelegram();
      })
      .catch((err) => {
        if (err.status !== 401) {
          showBanner(err, () => api('/api/session').then((s) => {
            state.session = s;
            syncAccessVisibility();
            renderHeader();
            if (s.accessAdmin === true) {
              loadAccess();
              loadInvites();
            }
            if (lifecycleAvailable()) {
              loadArchives();
            }
            loadTelegram();
          }).catch(() => {}));
        }
      });

    const initialOverview = refreshOverview({ force: true });
    const initialMetrics = refreshMetrics();
    startPolling();
    startCountdowns();
    await Promise.allSettled([initialOverview, initialMetrics]);
  }

  boot();
})();
