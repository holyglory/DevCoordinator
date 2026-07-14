/* DevOps Console control panel.
 * Vanilla JS, no dependencies. Talks only to same-origin /api/*.
 * Hash-routed pages (#/projects, #/servers, #/routes, #/docker, #/ports,
 * #/performance, #/access)
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
  };

  const ui = {
    expanded: new Set(),   // server ids with open detail panels
    dockerOpen: new Set(), // container names with open log panels
    logs: new Map(),       // 'srv:<id>' | 'dock:<name>' -> {loading,text,error,at}
    busy: new Set(),       // action keys currently in flight
    reveal: new Set(),     // pages currently showing their hidden items
    treeCollapsed: new Set(), // project usage_keys collapsed on the Projects page
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
    constructor(message, status) { super(message); this.status = status; }
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
      throw new ApiError(msg, res.status);
    }
    return data;
  }

  // ---------------------------------------------------------------- error banner

  let bannerKey = null;

  function showBanner(message, retry, key = 'action') {
    bannerKey = key;
    $('#banner-slot').replaceChildren(
      h('div', { class: 'banner', role: 'alert' },
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
    { id: 'servers', title: 'Servers' },
    { id: 'routes', title: 'Routes' },
    { id: 'docker', title: 'Docker' },
    { id: 'ports', title: 'Port leases' },
    { id: 'performance', title: 'Performance' },
    { id: 'access', title: 'Access' },
  ];

  function currentPage() {
    const m = /^#\/([a-z-]+)/.exec(location.hash || '');
    const id = m ? m[1] : '';
    if (!PAGES.some((p) => p.id === id)) return 'projects';
    if (id === 'access' && state.session?.accessAdmin !== true) return 'projects';
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
    // The performance page charts use a longer history window than sparklines.
    if (page === 'performance') refreshMetrics();
    if (page === 'access' && state.session?.accessAdmin === true) loadAccess();
  }

  function wireNav() {
    $('#nav-toggle').addEventListener('click', () => setNavOpen(!navOpen()));
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
    $('#access-add').hidden = !admin;
    if (!admin) state.access = null;
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
      $('#access-body').replaceChildren(
        h('p', { class: 'empty err' }, 'Could not load the access list. Use Retry above.'));
      showBanner(err.message, () => loadAccess({ force: true }), 'access');
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
    if (state.session?.accessAdmin !== true) return;
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
        showBanner(err.message, () => changeAccessGrant(email, resource, input, allowed));
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
      if (err.status !== 401) showBanner(err.message, () => removeAccessUser(email));
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
      if (err.status !== 401) showBanner(err.message, () => sendHiddenDelta(delta));
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

  const isServerRunning = (s) => s.status !== 'stopped';
  // Hide-gating and auto-unhide use "active" (anything not cleanly down):
  // a crash-looping "Restarting (1) …" container is very much running work
  // and must be neither hideable nor kept hidden.
  const isContainerActive = (c) => !/^\s*(exited|created|dead)\b/i.test(String(c.status || ''));

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
    if (/^\s*up\b/i.test(status)) {
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

  // ---------------------------------------------------------------- project grouping

  // Groups come straight from the coordinator's project_usage rows, which
  // carry authoritative membership (server_ids / container_names) — the UI
  // never re-implements the repo-identity heuristics.
  function projectGroupsOf(o) {
    const inv = o?.inventory;
    if (!inv) return [];
    const groups = [];
    const claimedServers = new Set();
    const claimedContainers = new Set();
    const servers = inv.servers || [];
    const containers = inv.docker?.available ? (inv.docker.containers || []) : [];
    const dbNames = new Set((inv.docker?.postgres || []).map((c) => c.name));

    for (const row of inv.project_usage || []) {
      const serverIds = new Set(row.server_ids || []);
      const containerNames = new Set(row.container_names || []);
      const members = {
        servers: servers.filter((s) => serverIds.has(s.id)),
        containers: containers.filter((c) => containerNames.has(c.name)),
      };
      members.servers.forEach((s) => claimedServers.add(s.id));
      members.containers.forEach((c) => claimedContainers.add(c.name));
      const runningCount = members.servers.filter(isServerRunning).length
        + members.containers.filter(isContainerActive).length;
      groups.push({
        key: String(row.usage_key ?? row.project_key ?? row.project ?? row.name),
        // usage_key first: project_key is a display name and NOT unique
        // (two repos named "app", or a repo plus a same-named container).
        metricsKey: `proj:${row.usage_key ?? row.project_key ?? row.project ?? row.name}`,
        name: row.name || projectTail(row.project),
        project: row.project || null,
        row,
        members,
        dbNames,
        runningCount,
      });
    }

    // Safety net: anything the rollup did not claim still gets displayed.
    const strayServers = servers.filter((s) => !claimedServers.has(s.id));
    const strayContainers = containers.filter((c) => !claimedContainers.has(c.name));
    if (strayServers.length || strayContainers.length) {
      groups.push({
        key: 'other',
        metricsKey: null,
        name: 'other',
        project: null,
        row: null,
        members: { servers: strayServers, containers: strayContainers },
        dbNames,
        runningCount: strayServers.filter(isServerRunning).length
          + strayContainers.filter(isContainerActive).length,
      });
    }

    groups.sort(projectGroupOrder);
    return groups;
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

  const groupsByProjectPath = (o) => {
    const map = new Map();
    for (const g of projectGroupsOf(o)) if (g.project) map.set(g.project, g);
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

  async function refreshOverview({ force = false } = {}) {
    if (fetching) { refetchQueued = true; return; }
    fetching = true;
    try {
      const data = await api('/api/overview');
      state.overview = data;
      state.stale = false;
      state.lastFetch = Date.now();
      clearBanner('overview');
      renderAll(force);
      if (state.session?.accessAdmin === true && state.access && accessRoutesSig !== currentAccessRoutesSig()) {
        loadAccess({ force: true });
      }
      // A failed boot-time prefs fetch retries with the polling cadence.
      if (!prefsLoaded) loadPrefs();
      // Anything running must never stay hidden (fire-and-forget PATCH).
      autoUnhide(data);
    } catch (err) {
      if (err.status === 401) return;
      state.stale = true;
      showBanner(err.message, () => refreshOverview({ force: true }), 'overview');
      if (!state.overview) renderFirstLoadError();
      else renderHeader();
    } finally {
      fetching = false;
      if (refetchQueued) {
        // A mutation finished while a poll was in flight — fetch once more so
        // the UI reflects post-mutation state instead of the stale response.
        refetchQueued = false;
        refreshOverview({ force });
      }
    }
  }

  function renderFirstLoadError() {
    for (const id of ['projects-body', 'routes-body', 'servers-body', 'docker-body', 'leases-body', 'assignments-body', 'usage-body', 'perf-body']) {
      document.getElementById(id).replaceChildren(
        h('p', { class: 'empty err' }, 'Could not load — use Retry in the error banner above.'));
    }
  }

  // ---------------------------------------------------------------- mutations

  async function runAction(busyKey, fn, { confirmText, onError } = {}) {
    if (confirmText && !window.confirm(confirmText)) return false;
    ui.busy.add(busyKey);
    bump();
    renderAll(true);
    try {
      await fn();
      ui.busy.delete(busyKey);
      bump();
      await refreshOverview({ force: true });
      return true;
    } catch (err) {
      ui.busy.delete(busyKey);
      bump();
      renderAll(true);
      if (err.status !== 401) {
        showBanner(err.message, () => runAction(busyKey, fn, { onError }));
        onError?.(err);
      }
      return false;
    }
  }

  // ---------------------------------------------------------------- render root

  function renderAll(force = false) {
    const o = state.overview;
    if (!o) return;
    if (popover.key !== null) {
      if (!force) { popover.pending = true; return; }
      popover.pending = false;
      popover.close();
    }
    renderHeader();
    updateServerOptions(o);
    updateContainerOptions(o);

    // Only render-relevant coordinator facts belong in section signatures:
    // lastOkAt changes on every poll and would defeat the memoization,
    // rebuilding every card each 6s even when nothing visible changed.
    const coordSig = o.coordinator ? [o.coordinator.ok, o.coordinator.lastError] : null;

    setSection('projects-body',
      sig(o.inventory?.servers ?? null, o.inventory?.docker ?? null, o.inventory?.project_usage ?? null,
        o.routes ?? null, coordSig),
      () => buildProjects(o), force);
    setSection('routes-body', sig(o.routes), () => buildRoutes(o), force);
    setSection('servers-body',
      sig(o.inventory?.servers ?? null, o.inventory?.port_assignments ?? null,
        o.inventory?.docker ?? null, o.routes ?? null, coordSig),
      () => buildServers(o), force);
    setSection('docker-body', sig(o.inventory?.docker ?? null, o.routes ?? null, coordSig), () => buildDocker(o), force);
    setSection('leases-body', sig(o.inventory?.leases ?? null, coordSig), () => buildLeases(o), force);
    setSection('assignments-body', sig(o.inventory?.port_assignments ?? null, coordSig), () => buildAssignments(o), force);
    setSection('usage-body', sig(o.inventory?.project_usage ?? null, coordSig), () => buildUsage(o), force);
    setSection('perf-body', sig(state.metricsAt, o.inventory ? 1 : 0, coordSig), () => buildPerf(o), force);

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
    setCount('projects-count', projectGroups);
    setCount('routes-count', (o.routes || []).length);
    setCount('servers-count', o.inventory ? (o.inventory.servers || []).length + webContainerCount : null);
    setCount('docker-count', o.inventory?.docker?.available ? (o.inventory.docker.containers || []).length : null);
    setCount('leases-count', o.inventory ? (o.inventory.leases || []).length : null);
    setCount('assignments-count', o.inventory ? (o.inventory.port_assignments || []).length : null);
    setCount('usage-count', o.inventory ? (o.inventory.project_usage || []).length : null);
    setCount('perf-count', perfEntities);

    setNavCount('projects', projectGroups);
    setNavCount('servers', o.inventory ? (o.inventory.servers || []).length + webContainerCount : null);
    setNavCount('routes', (o.routes || []).length);
    setNavCount('docker', o.inventory?.docker?.available ? (o.inventory.docker.containers || []).length : null);
    setNavCount('ports', o.inventory
      ? (o.inventory.leases || []).length + (o.inventory.port_assignments || []).length
      : null);
    setNavCount('performance', perfEntities);
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
      again?.focus({ preventScroll: true });
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
    if (!coordOk) {
      problems.push({
        severity: 'err',
        title: 'Coordinator unreachable',
        body: () => [
          kv('URL', c.url || '—', { mono: true }),
          kv('Last OK', fmtWhen(c.lastOkAt)),
          c.lastError ? kv('Error', String(c.lastError), { mono: true }) : null,
          h('p', { class: 'pop-hint' }, 'Servers, containers and leases cannot be managed until it answers. The console keeps retrying; in production the dedicated coordinator service is restarted by systemd. Routes to fixed ports keep working meanwhile.'),
          h('div', { class: 'prob-actions' },
            h('button', {
              class: 'btn small', type: 'button', 'data-fk': 'hdr-coord-retry',
              onclick: () => refreshOverview({ force: true }),
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
              onclick: () => refreshOverview({ force: true }),
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
    const e = o?.coordinator?.lastError;
    return e ? String(e) : 'The control engine on 127.0.0.1 did not respond.';
  }

  function degradedPanel(o) {
    return h('div', { class: 'degraded' },
      icon('warn'),
      h('div', null,
        h('p', { class: 'deg-title' }, 'Coordinator unreachable'),
        h('p', { class: 'deg-msg' }, coordErrorText(o)),
        h('button', {
          class: 'btn small', type: 'button',
          onclick: () => refreshOverview({ force: true }),
        }, icon('refresh'), 'Try again')));
  }

  function emptyState(text) {
    return h('p', { class: 'empty' }, text);
  }

  function isContainerRunning(c) {
    return /^\s*up\b/i.test(String(c.status || ''));
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
    if (o.coordinator && o.coordinator.ok === false) {
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
        ? `Route status: serving from port ${res.port} — show details`
        : 'Route status: not reachable — show details',
      title: live ? `Proxying to 127.0.0.1:${res.port}` : (res?.reason || 'Not resolvable'),
      onclick: (e) => popover.toggle(dotKey, e.currentTarget, () => (
        h('div', null,
          popHead(`https://${host}`),
          kv('State', live ? 'live' : 'not reachable'),
          live ? kv('Upstream', `127.0.0.1:${res.port}`, { mono: true }) : null,
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
        ? `${r.containerName} · container :${r.containerPort}`
        : `${r.serverName} · ${projectTail(r.project)}`;

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
      }, `${row.name}${row.project ? ` · ${projectTail(row.project)}` : ''} · :${row.port} (host :${row.hostPort})`));
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
      await refreshOverview({ force: true });
    } catch (err) {
      if (err.status !== 401) {
        fail(err.message);
        showBanner(err.message, () => $('#route-form').requestSubmit());
      }
    } finally {
      btn.disabled = false;
      btn.textContent = oldText;
    }
  }

  // ---------------------------------------------------------------- servers

  function serverStatusMeta(s) {
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

  function buildServers(o) {
    if (!o.inventory) return [degradedPanel(o)];
    const hidden = hiddenSet('servers');
    const hiddenDocker = hiddenSet('docker');
    const revealing = ui.reveal.has('servers');
    const rank = (s) => (s.status === 'running' ? 0 : s.status === 'stopped' ? 2 : 1);
    let total = 0;
    let hiddenCount = 0;

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
      const visible = [];
      for (const s of servers) {
        const isHidden = hidden.has(s.key);
        if (isHidden) hiddenCount += 1;
        if (isHidden && !revealing) continue;
        visible.push(serverItem(o, s, isHidden));
      }
      for (const c of webContainers) {
        const isHidden = hiddenDocker.has(c.name);
        if (isHidden) hiddenCount += 1;
        if (isHidden && !revealing) continue;
        visible.push(dockerServerItem(o, c, isHidden));
      }
      if (!visible.length) continue;
      const running = servers.filter(isServerRunning).length
        + webContainers.filter(isContainerRunning).length;
      const memberCount = servers.length + webContainers.length;
      out.push(groupHeader(group, `${running} of ${memberCount} running`));
      out.push(...visible);
    }

    if (total === 0) {
      return [emptyState('No dev servers registered with the coordinator yet — start one with "server start" and it appears here.')];
    }
    const toggle = revealToggle('servers', hiddenCount);
    if (toggle) out.push(toggle);
    return out;
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
          h('p', { class: 'pop-hint' }, 'This server runs as a Docker container — actions start, stop and restart the container itself.'))
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
      class: `row srv-grid expandable${hiddenRow ? ' is-hidden' : ''}`,
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
        dockerSubdomainControl(o, c, 'srv')),
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
        running
          ? [act('restart', 'Restart', 'refresh'),
             act('stop', 'Stop', 'stop', `Stop container ${name}?\n\nAnything depending on it (like a database) loses its service.`)]
          : act('start', 'Start', 'play'),
        hiddenRow
          ? unhideButton('docker', name, name)
          : (!isContainerActive(c) ? hideButton('docker', name, name) : ghostIconSlot())));

    return h('div', { class: 'item' }, row, open ? dockerPanel(c, panelId) : null);
  }

  function serverItem(o, s, hiddenRow = false) {
    const id = s.id;
    const open = ui.expanded.has(id);
    const busy = ui.busy.has(`server:${id}`);
    const meta = serverStatusMeta(s);
    const panelId = `srv-panel-${id}`;

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
    const actions = h('span', { class: 'cell actions' },
      h('button', {
        class: `btn small act-restart${busy ? ' is-busy' : ''}`, type: 'button',
        'data-fk': `srv-restart:${id}`,
        disabled: (busy || s.missing_command) || undefined,
        title: s.missing_command
          ? 'Registered without a start command — cannot be restarted from here'
          : `Restart ${s.name} on the same port`,
        onclick: () => runAction(`server:${id}`,
          () => api('/api/servers/action', { method: 'POST', body: { id, action: 'restart' } })),
      }, icon('refresh'), busy ? 'Working…' : 'Restart'),
      h('button', {
        class: `btn small act-stop${busy ? ' is-busy' : ''}`, type: 'button',
        'data-fk': `srv-stop:${id}`,
        disabled: (busy || !stoppable) || undefined,
        title: stoppable ? `Stop ${s.name}` : 'Server is not running',
        onclick: () => runAction(`server:${id}`,
          () => api('/api/servers/action', { method: 'POST', body: { id, action: 'stop' } })),
      }, icon('stop'), busy ? 'Working…' : 'Stop'),
      hiddenRow
        ? unhideButton('servers', s.key, s.name || 'server')
        : (s.status === 'stopped' ? hideButton('servers', s.key, s.name || 'server') : ghostIconSlot()));

    const row = h('div', {
      class: `row srv-grid expandable${hiddenRow ? ' is-hidden' : ''}`,
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
            ? `container port ${op.containerPort} (not published right now)`
            : `container port ${op.containerPort} → host :${op.hostPort}`)));
      } else if (options.length === 1) {
        portNote = h('p', { class: 'pop-hint' },
          `Publishes container port ${options[0].containerPort}`
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
      kv('Started', fmtWhen(s.created_at)),
      kv('Updated', fmtWhen(s.updated_at)),
      s.stopped_at ? kv('Stopped', fmtWhen(s.stopped_at)) : null,
      s.stopped_reason ? kv('Stop reason', s.stopped_reason) : null,
      s.url_is_current === false
        ? h('p', { class: 'pop-hint' }, 'Warning: the recorded URL may be stale — another process may be listening on this port.')
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
      showBanner(err.message, () => loadServerLogs(id));
    }
    bump();
    renderAll(true);
  }

  function serverPanel(s, panelId) {
    const key = `srv:${s.id}`;
    const lg = ui.logs.get(key);
    return h('div', { class: 'panel', id: panelId },
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
    const docker = o.inventory.docker;
    if (!docker || docker.available === false) {
      return [h('div', { class: 'degraded' },
        icon('warn'),
        h('div', null,
          h('p', { class: 'deg-title' }, 'Docker unavailable'),
          h('p', { class: 'deg-msg' }, docker?.error ? String(docker.error) : 'Docker did not respond on this machine.')))];
    }
    const hidden = hiddenSet('docker');
    const revealing = ui.reveal.has('docker');
    const sortContainers = (list) => list.slice().sort((a, b) =>
      (isContainerRunning(b) ? 1 : 0) - (isContainerRunning(a) ? 1 : 0)
      || String(a.name).localeCompare(String(b.name)));
    let total = 0;
    let hiddenCount = 0;

    const out = [
      h('div', { class: 'grid-head dock-grid', 'aria-hidden': 'true' },
        h('span', null, ''), h('span', null, 'Container'), h('span', null, 'Image'),
        h('span', null, 'CPU / Mem'), h('span', null, 'Ports'), h('span', null, 'Actions')),
    ];

    for (const group of projectGroupsOf(o)) {
      const containers = sortContainers(group.members.containers);
      if (!containers.length) continue;
      total += containers.length;
      const visible = [];
      for (const c of containers) {
        const isHidden = hidden.has(c.name);
        if (isHidden) hiddenCount += 1;
        if (isHidden && !revealing) continue;
        visible.push(dockerItem(o, c, isHidden, isWebServerContainer(o, group, c)));
      }
      if (!visible.length) continue;
      const up = containers.filter(isContainerRunning).length;
      out.push(groupHeader(group, `${up} of ${containers.length} up`));
      out.push(...visible);
    }

    if (total === 0) {
      return [emptyState('No containers found — anything started with docker run or compose shows up here.')];
    }
    if (docker.stats_error) {
      out.push(h('p', { class: 'inline-note' }, `Stats unavailable: ${docker.stats_error}`));
    }
    const toggle = revealToggle('docker', hiddenCount);
    if (toggle) out.push(toggle);
    return out;
  }

  function dockerItem(o, c, hiddenRow = false, webish = false) {
    const name = c.name;
    const running = isContainerRunning(c);
    const open = ui.dockerOpen.has(name);
    const busy = ui.busy.has(`docker:${name}`);
    const panelId = `dock-panel-${name}`;

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
      class: `row dock-grid expandable${hiddenRow ? ' is-hidden' : ''}`,
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
        webish ? dockerSubdomainControl(o, c, 'dock') : null),
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
        running
          ? [act('restart', 'Restart', 'refresh'),
             act('stop', 'Stop', 'stop', `Stop container ${name}?\n\nAnything depending on it (like a database) loses its service.`)]
          : act('start', 'Start', 'play'),
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
          : (!isContainerActive(c) ? hideButton('docker', name, name) : ghostIconSlot())));

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
      showBanner(err.message, () => loadDockerLogs(name));
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
      await refreshOverview({ force: true });
    } catch (err) {
      if (err.status !== 401) {
        fail(err.message);
        showBanner(err.message, () => $('#lease-form').requestSubmit());
      }
    } finally {
      btn.disabled = false;
      btn.textContent = oldText;
    }
  }

  // ---------------------------------------------------------------- usage

  function buildUsage(o) {
    if (!o.inventory) return [degradedPanel(o)];
    const items = o.inventory.project_usage || [];
    if (!items.length) {
      return [emptyState('No per-project usage measured yet — start a server or container and its CPU/memory appears here.')];
    }
    const maxMem = Math.max(1, ...items.map((p) => p.memory_bytes || 0));
    const maxCpu = Math.max(100, ...items.map((p) => p.cpu_percent || 0));
    return items.map((p) => {
      const key = `proj:${p.usage_key ?? p.project_key ?? p.project ?? p.name}`;
      return h('div', { class: 'usage-item' },
        h('div', { class: 'usage-head' },
          h('strong', { title: p.project || '' }, p.name || projectTail(p.project)),
          sparkline(metricsEntity(key)),
          h('span', { class: 'meta-passive' },
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
      stop: `Stop project "${group.name}"?\n\nThe coordinator stops the runtime it manages for this repo (its declared servers and containers).`,
      restart: `Restart project "${group.name}"?\n\nThe coordinator restarts the runtime it manages for this repo; brief downtime for each piece.`,
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
        : `${label} the whole project (dependencies first, pinned ports preserved)`,
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
    return h('div', { class: `row tree-grid tree-item${hiddenRow ? ' is-hidden' : ''}` },
      h('span', { class: 'cell c-kind' }, h('span', { class: 'kind-tag k-srv' }, 'server')),
      h('span', { class: 'cell c-primary' },
        h('strong', null, s.name || '—'),
        h('span', { class: 'dim mono' }, s.port != null ? ` :${s.port}` : ''),
        h('span', { class: 'tree-detail dim mono', title: s.url || '' }, s.url || '')),
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
        treeActionSlots({
          start: slot('restart', 'Start', 'play', !stopped || s.missing_command,
            !stopped ? 'Already running'
              : (s.missing_command ? 'Registered without a start command' : `Start ${s.name} on its pinned port`)),
          restart: slot('restart', 'Restart', 'refresh', stopped || s.missing_command,
            stopped ? 'Not running — use Start'
              : (s.missing_command ? 'Registered without a start command' : `Restart ${s.name} on the same port`)),
          stop: slot('stop', 'Stop', 'stop', stopped,
            stopped ? 'Already stopped' : `Stop ${s.name}`),
        }),
        hiddenRow
          ? unhideButton('servers', s.key, s.name || 'server')
          : (stopped ? hideButton('servers', s.key, s.name || 'server') : ghostIconSlot())));
  }

  function treeContainerRow(o, c, isDb, hiddenRow, webish = false) {
    const busy = ui.busy.has(`docker:${c.name}`);
    const running = isContainerRunning(c);
    const slot = (action, label, iconName, disabled, title, confirmText) => ({
      fk: `tree-dock-${action}:${c.name}`,
      label,
      icon: iconName,
      busy,
      disabled,
      title,
      onclick: () => runAction(`docker:${c.name}`,
        () => api('/api/docker/action', { method: 'POST', body: { name: c.name, action } }),
        confirmText ? { confirmText } : undefined),
    });
    return h('div', { class: `row tree-grid tree-item${hiddenRow ? ' is-hidden' : ''}` },
      h('span', { class: 'cell c-kind' },
        h('span', { class: `kind-tag ${isDb ? 'k-db' : 'k-dock'}` }, isDb ? 'database' : 'container')),
      h('span', { class: 'cell c-primary' },
        h('strong', null, c.name),
        h('span', { class: 'tree-detail dim mono', title: c.image || '' }, c.image || ''),
        // Own wrapping block: the name line is nowrap+ellipsis and would
        // otherwise clip the chip invisible.
        webish ? h('span', { class: 'tree-sub' }, dockerSubdomainControl(o, c, 'tree')) : null),
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
          : (!isContainerActive(c) ? hideButton('docker', c.name, c.name) : ghostIconSlot())));
  }

  function projectNode(o, group, hiddenProject, revealing, hiddenServers, hiddenDocker) {
    const collapsed = ui.treeCollapsed.has(group.key);
    const memberCount = group.members.servers.length + group.members.containers.length;
    const chev = h('button', {
      class: `chev${collapsed ? '' : ' open'}`, type: 'button',
      'data-fk': `tree-x:${group.key}`,
      'aria-expanded': String(!collapsed),
      'aria-label': `${collapsed ? 'Expand' : 'Collapse'} project ${group.name}`,
      title: collapsed ? 'Expand project' : 'Collapse project',
      onclick: () => {
        if (collapsed) ui.treeCollapsed.delete(group.key); else ui.treeCollapsed.add(group.key);
        bump();
        renderAll(true);
      },
    }, icon('chevron'));

    const header = h('div', { class: `row tree-grid tree-head${hiddenProject ? ' is-hidden' : ''}`, title: group.project || '' },
      h('span', { class: 'cell c-kind' }, chev),
      h('span', { class: 'cell c-primary' },
        h('strong', { class: 'proj-name' }, group.name)),
      group.metricsKey
        ? usageCellNode({
            key: group.metricsKey,
            title: `Project ${group.name}`,
            cpu: group.row?.cpu_percent ?? null,
            mem: group.row?.memory_bytes ?? null,
            running: group.runningCount > 0,
            scope: 'proj',
          })
        : h('span', { class: 'cell usage-cell dim' }, '—'),
      h('span', { class: 'cell c-status meta-passive tree-count' },
        `${group.runningCount} of ${memberCount} running`),
      h('span', { class: 'cell actions' },
        projectActionButtons(group),
        hiddenProject
          ? unhideButton('projects', group.key, group.name)
          : (group.runningCount === 0 ? hideButton('projects', group.key, group.name) : ghostIconSlot())));

    const children = [];
    if (!collapsed) {
      for (const s of group.members.servers.slice().sort((a, b) => String(a.name).localeCompare(String(b.name)))) {
        const isHidden = hiddenServers.has(s.key);
        if (isHidden && !revealing) continue;
        children.push(treeServerRow(o, s, isHidden));
      }
      const containers = group.members.containers.slice().sort((a, b) => String(a.name).localeCompare(String(b.name)));
      for (const c of containers) {
        const isHidden = hiddenDocker.has(c.name);
        if (isHidden && !revealing) continue;
        children.push(treeContainerRow(o, c, group.dbNames.has(c.name), isHidden,
          isWebServerContainer(o, group, c)));
      }
      if (!children.length && memberCount > 0) {
        children.push(h('p', { class: 'inline-note' }, 'All items in this project are hidden.'));
      }
      if (memberCount === 0) {
        children.push(h('p', { class: 'inline-note' }, 'Nothing registered under this project yet.'));
      }
    }
    return h('div', { class: 'item tree-node' }, header, h('div', { class: 'tree-children' }, children));
  }

  function buildProjects(o) {
    if (!o.inventory) return [degradedPanel(o)];
    const groups = projectGroupsOf(o);
    if (!groups.length) {
      return [emptyState('No projects yet — anything an agent starts or registers through the coordinator appears here, grouped by repo.')];
    }
    const hiddenProjects = hiddenSet('projects');
    const hiddenServers = hiddenSet('servers');
    const hiddenDocker = hiddenSet('docker');
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
      if (!document.hidden) refreshOverview();
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
    applyPage();

    loadPrefs();

    api('/api/session')
      .then((s) => {
        state.session = s;
        syncAccessVisibility();
        renderHeader();
        if (s.accessAdmin === true) loadAccess();
      })
      .catch((err) => {
        if (err.status !== 401) {
          showBanner(err.message, () => api('/api/session').then((s) => {
            state.session = s;
            syncAccessVisibility();
            renderHeader();
            if (s.accessAdmin === true) loadAccess();
          }).catch(() => {}));
        }
      });

    await refreshOverview({ force: true });
    await refreshMetrics();
    startPolling();
    startCountdowns();
  }

  boot();
})();
