// Self-contained dark-theme HTML pages for the auth/error surfaces.
// No external assets, inline CSS only, and every interpolation is escaped.

const ESCAPE_MAP = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ESCAPE_MAP[ch]);
}

const CSS = `
:root{color-scheme:dark}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%}
body{background:#0b0f15;color:#e7edf5;font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px;background-image:radial-gradient(900px 480px at 50% -8%,rgba(46,90,150,.18),transparent 65%)}
.card{width:100%;max-width:432px;background:#101724;border:1px solid #1f2b3d;border-radius:14px;padding:30px 28px 20px;box-shadow:0 24px 64px rgba(0,0,0,.5)}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:24px}
.brand-name{font-weight:650;font-size:15px;letter-spacing:.2px}
.brand-domain{margin-left:auto;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:#8fa1b8;border:1px solid #24344b;border-radius:999px;padding:2px 10px;background:#0d1420;white-space:nowrap}
.status-code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:42px;font-weight:700;line-height:1;color:#33445e;letter-spacing:1px;margin-bottom:12px}
h1{font-size:20px;font-weight:650;margin-bottom:8px}
p{color:#a7b4c6;font-size:14px;margin-bottom:14px}
p.small{font-size:12.5px;color:#7787a0;margin-bottom:10px}
a{color:#6ea8ff;text-decoration:none}
a:hover{text-decoration:underline}
a:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid #4c8dff;outline-offset:2px;border-radius:6px}
.note{border-radius:10px;padding:12px 14px;font-size:13.5px;line-height:1.55;margin:0 0 16px}
.note-error{border:1px solid #5a2732;background:#2a141b;color:#ffa3ad}
.note-warn{border:1px solid #57431c;background:#271f0f;color:#e8cf9c}
.note-warn strong{display:block;color:#f5c66d;margin-bottom:6px}
.note-warn ol{margin:8px 0 0 18px}
.note-warn li{margin:6px 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;background:#0d1420;border:1px solid #24344b;border-radius:6px;padding:1px 6px;color:#c7d4e6;word-break:break-all}
.block{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#0d1420;border:1px solid #24344b;border-radius:8px;padding:10px 12px;font-size:12.5px;color:#c7d4e6;word-break:break-all;margin:10px 0;user-select:all}
.meta{display:flex;flex-direction:column;gap:6px;margin:0 0 16px}
.meta-row{display:flex;gap:12px;font-size:13px;align-items:baseline}
.meta-row .k{color:#7787a0;min-width:58px;flex:none}
.meta-row .v{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;color:#c7d4e6;word-break:break-all}
.btn{display:flex;width:100%;align-items:center;justify-content:center;gap:10px;border-radius:8px;font-weight:600;font-size:14px;padding:10px 16px;cursor:pointer;text-decoration:none;border:1px solid transparent}
.btn:hover{text-decoration:none}
.btn svg{flex:none}
.btn-google{background:#fff;color:#1f1f1f;border-color:#d5d9e0}
.btn-google:hover{background:#f2f4f8}
.btn-google[disabled]{opacity:.4;cursor:not-allowed}
.btn-ghost{background:#152033;color:#dbe6f5;border-color:#2a3b55;margin-top:4px}
.btn-ghost:hover{background:#1a2740}
form{margin:18px 0 8px}
.gap-top{margin-top:14px}
.foot{margin-top:22px;padding-top:14px;border-top:1px solid #1c2837;font-size:11.5px;color:#5d6d85;text-align:center;letter-spacing:.3px}
@media (max-width:480px){body{padding:14px}.card{padding:24px 18px 14px}}
`.trim();

const MARK_SVG =
  '<svg width="26" height="26" viewBox="0 0 26 26" aria-hidden="true">' +
  '<rect x="1" y="1" width="24" height="24" rx="6.5" fill="#0d1420" stroke="#2c3e57" stroke-width="1.5"/>' +
  '<path d="M7.5 9.5 11 13l-3.5 3.5" stroke="#4c8dff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
  '<path d="M13.5 16.5h5" stroke="#8fa1b8" stroke-width="2" stroke-linecap="round"/>' +
  '</svg>';

const GOOGLE_ICON =
  '<svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">' +
  '<path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>' +
  '<path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>' +
  '<path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>' +
  '<path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>' +
  '</svg>';

export function createPages({ config }) {
  const domain = config.domain;
  const consoleOrigin = config.consoleOrigin;
  const brandLine = `DevOps Console — ${domain}`;

  function page({ title, body }) {
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)} · DevOps Console</title>
<style>${CSS}</style>
</head>
<body>
<main class="card">
<div class="brand">${MARK_SVG}<span class="brand-name">DevOps Console</span><span class="brand-domain">${escapeHtml(domain)}</span></div>
${body}
<footer class="foot">${escapeHtml(brandLine)}</footer>
</main>
</body>
</html>`;
  }

  function consoleButton(label = 'Open the console', href = `${consoleOrigin}/`) {
    const safeHref = /^https?:\/\//i.test(String(href)) ? String(href) : `${consoleOrigin}/`;
    return `<a class="btn btn-ghost" href="${escapeHtml(safeHref)}">${escapeHtml(label)}</a>`;
  }

  function renderLogin({ rt = '', error = '', degraded = false } = {}) {
    const safeRt = typeof rt === 'string' ? rt : '';
    const errorNote = error
      ? `<div class="note note-error" role="alert">${escapeHtml(error)}</div>\n`
      : '';
    let action;
    if (degraded) {
      action = `<div class="note note-warn">
<strong>Google OAuth is not configured yet</strong>
Sign-in stays disabled until this console has an OAuth client. To finish setup:
<ol>
<li>In Google Cloud Console open <em>APIs &amp; Services &rarr; Credentials</em> and create an <em>OAuth client ID</em> of type <em>Web application</em>.</li>
<li>Register this exact authorized redirect URI:
<span class="block">${escapeHtml(consoleOrigin)}/auth/callback</span></li>
<li>Put the client ID and secret in the console&#39;s <code>.env</code> as <code>GOOGLE_CLIENT_ID</code> and <code>GOOGLE_CLIENT_SECRET</code>, then restart the console.</li>
</ol>
</div>
<button class="btn btn-google" type="button" disabled aria-disabled="true">${GOOGLE_ICON}Sign in with Google</button>`;
    } else {
      // GET form → the browser submits to /auth/start?rt=<value>.
      const rtField = safeRt ? `\n<input type="hidden" name="rt" value="${escapeHtml(safeRt)}">` : '';
      action = `<form method="get" action="/auth/start">${rtField}
<button class="btn btn-google" type="submit">${GOOGLE_ICON}Sign in with Google</button>
</form>`;
    }
    const body = `<h1>Sign in</h1>
<p>The console and every <code>*.${escapeHtml(domain)}</code> route are restricted to approved Google accounts.</p>
${errorNote}${action}
<p class="small gap-top">After signing in you will be returned to the page you asked for.</p>`;
    return { status: error ? 400 : 200, html: page({ title: 'Sign in', body }) };
  }

  function renderDenied({ email = '' } = {}) {
    const who = email
      ? `<code>${escapeHtml(email)}</code> signed in with Google successfully, but that address`
      : 'Your Google account';
    const body = `<div class="status-code">403</div>
<h1>Access denied</h1>
<p>${who} is not on the allowlist for this console.</p>
<p class="small">If you should have access, ask the operator to add your address to <code>ALLOWED_EMAILS</code> and restart the console. No session cookie was set.</p>
<a class="btn btn-ghost" href="/auth/login">Try a different account</a>`;
    return { status: 403, html: page({ title: 'Access denied', body }) };
  }

  function renderNotFound({ slug = '' } = {}) {
    const host = slug ? `${slug}.${domain}` : '';
    const lead = host
      ? `<p>There is no route configured for <code>${escapeHtml(host)}</code>.</p>`
      : '<p>This page does not exist.</p>';
    const body = `<div class="status-code">404</div>
<h1>Route not found</h1>
${lead}
<p class="small">Subdomain routes are managed from the console — create one there to bring this hostname to life.</p>
${consoleButton()}`;
    return { status: 404, html: page({ title: 'Not found', body }) };
  }

  const UPSTREAM_MESSAGES = {
    connect: 'The upstream server refused the connection — nothing is listening on its port.',
    timeout: 'The upstream server did not respond in time.',
    reset: 'The upstream server closed the connection unexpectedly.',
    stopped: 'The server behind this route is not running.',
  };

  function renderUpstreamError({ slug = '', kind = '', detail = '', consoleUrl = '' } = {}) {
    const status = kind === 'timeout' ? 504 : 502;
    const host = slug ? `${slug}.${domain}` : domain;
    const message = UPSTREAM_MESSAGES[kind] || 'The server behind this route is currently unreachable.';
    const rows = [
      `<div class="meta-row"><span class="k">Host</span><span class="v">${escapeHtml(host)}</span></div>`,
      kind ? `<div class="meta-row"><span class="k">Cause</span><span class="v">${escapeHtml(kind)}</span></div>` : '',
    ].filter(Boolean).join('\n');
    const detailBlock = detail ? `<span class="block">${escapeHtml(String(detail))}</span>\n` : '';
    const body = `<div class="status-code">${status}</div>
<h1>Upstream unavailable</h1>
<p>${escapeHtml(message)}</p>
<div class="meta">
${rows}
</div>
${detailBlock}<p class="small">Start or restart the server from the console, then reload this page.</p>
${consoleButton('Open the console', consoleUrl)}`;
    return { status, html: page({ title: 'Upstream unavailable', body }) };
  }

  function renderError({ status = 500, title = 'Something went wrong', detail = '' } = {}) {
    const safeStatus = Number.isInteger(status) && status >= 400 && status <= 599 ? status : 500;
    const safeTitle = typeof title === 'string' && title !== '' ? title : 'Something went wrong';
    const detailPara = detail
      ? `<p>${escapeHtml(String(detail))}</p>`
      : '<p>The request could not be completed.</p>';
    const body = `<div class="status-code">${safeStatus}</div>
<h1>${escapeHtml(safeTitle)}</h1>
${detailPara}
${consoleButton()}`;
    return { status: safeStatus, html: page({ title: safeTitle, body }) };
  }

  return { renderLogin, renderDenied, renderNotFound, renderUpstreamError, renderError };
}
