'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config({ path: process.env.ENV_FILE || path.join(__dirname, '.env') });
const { applyTrafficProtection, configureHttpServer, httpErrorStatus } = require('./traffic-protection');
const { pool, initialize } = require('./db');
const {
  expirationDate,
  hashCode,
  makeCode,
  safeEqual,
  hashPassword,
  validCode,
  validUsername,
  verifyPassword,
  validateEnvironment
} = require('./security');
const {
  pageWindow,
  paginationLinks,
  parseKeyStatus,
  parsePage,
  parseSearch
} = require('./admin-pages');
const { summarizeReport } = require('./report-view');

const DAY = 24 * 60 * 60 * 1000;
const SESSION_TTL = 4 * 60 * 60 * 1000;
const COOKIE_NAMES = Object.freeze({
  admin: 'blue_owner',
  account: 'blue_account',
  adminLoginCsrf: 'blue_login_csrf',
  accountLoginCsrf: 'blue_account_login_csrf'
});

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]);
}

function parseCookies(header = '') {
  const cookies = {};
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator > 0) cookies[part.slice(0, separator).trim()] = part.slice(separator + 1).trim();
  }
  return cookies;
}

function cookieOptions(maxAge) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(maxAge / 1000)}${secure}`;
}

function csrfCookieOptions() {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `Path=/; HttpOnly; SameSite=Strict; Max-Age=600${secure}`;
}

function sign(value) {
  return crypto.createHmac('sha256', process.env.SESSION_SECRET).update(value).digest('base64url');
}

function createSession(role, id, sessionVersion = 0) {
  const payload = Buffer.from(JSON.stringify({
    role,
    id,
    sessionVersion,
    csrf: crypto.randomBytes(24).toString('base64url'),
    expiresAt: Date.now() + SESSION_TTL
  })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function readSession(req, cookieName, expectedRole) {
  const value = parseCookies(req.headers.cookie)[cookieName] || '';
  const [payload, signature, ...extra] = value.split('.');
  if (!payload || !signature || extra.length || !safeEqual(signature, sign(payload))) return null;
  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (session.role !== expectedRole || typeof session.id !== 'string' ||
        typeof session.csrf !== 'string' || session.expiresAt <= Date.now()) return null;
    return session;
  } catch {
    return null;
  }
}

function setSession(res, cookieName, role, id, sessionVersion = 0) {
  res.setHeader('Set-Cookie', `${cookieName}=${createSession(role, id, sessionVersion)}; ${cookieOptions(SESSION_TTL)}`);
}

function csrfInput(session) {
  return `<input type="hidden" name="csrf" value="${escapeHtml(session.csrf)}">`;
}

function validCsrf(req, session) {
  const supplied = req.body && req.body.csrf;
  return typeof supplied === 'string' && safeEqual(supplied, session.csrf);
}

function sameOrigin(req, res) {
  const origin = req.get('origin');
  if (!origin || origin === 'null') return true;
  try {
    if (new URL(origin).host === req.get('host')) return true;
  } catch {
  }
  res.status(403).send('Request origin rejected.');
  return false;
}

function page(title, content) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} · Blue Detected</title>
<style>
body{font:16px system-ui,sans-serif;background:#0b1020;color:#e8eefb;margin:0}main{max-width:1100px;margin:36px auto;padding:24px}a{color:#8db8ff}section,article{background:#141c30;border:1px solid #2b3855;border-radius:10px;padding:18px;margin:16px 0}input,select,button{font:inherit;border:1px solid #405171;border-radius:6px;padding:9px;margin:4px;background:#0b1020;color:#e8eefb}button{background:#2459b4;cursor:pointer}table{border-collapse:collapse;width:100%;margin-top:12px}th,td{text-align:left;border-bottom:1px solid #2b3855;padding:9px;vertical-align:top;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}nav{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}.muted{color:#a6b3ca}.error{color:#ff9a9a}.new-code{font-size:2rem;letter-spacing:.3rem;color:#94ffca}.pagination{display:flex;justify-content:space-between;gap:12px;margin:18px 0}
</style></head><body><main><nav><a href="/">Blue Detected</a><a href="/privacy">Privacy</a></nav><h1>${escapeHtml(title)}</h1>${content}</main></body></html>`;
}

function loginPage(action, csrfCookieName, csrfToken, message = '') {
  return page('Sign in', `${message ? `<p class="error">${escapeHtml(message)}</p>` : ''}
<section><form method="post" action="${action}"><input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
<label>Username or password <input name="${action === '/admin/login' ? 'password' : 'username'}" ${action === '/owner/login' ? 'required autocomplete="username"' : 'required type="password" autocomplete="current-password"'}></label>
${action === '/owner/login' ? '<label>Password <input type="password" name="password" required autocomplete="current-password"></label>' : ''}
<button type="submit">Sign in</button></form></section>`);
}

function issueLoginCsrf(res, cookieName) {
  const token = crypto.randomBytes(24).toString('base64url');
  res.append('Set-Cookie', `${cookieName}=${token}; ${csrfCookieOptions()}`);
  return token;
}

function loginCsrfValid(req, cookieName) {
  const token = parseCookies(req.headers.cookie)[cookieName];
  return typeof token === 'string' && typeof req.body.csrf === 'string' && safeEqual(token, req.body.csrf);
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function buildAdminDashboard(req, session, stats, accounts, keys, reports, pagination) {
  const status = parseKeyStatus(req.query.keyStatus);
  const search = parseSearch(req.query.reportSearch);
  const accountRows = accounts.map((account) => `<tr><td>${escapeHtml(account.username)}</td><td>${escapeHtml(account.created_at)}</td><td>${account.disabled_at ? 'Disabled' : 'Active'}</td><td>${account.disabled_at ? '' : `<form method="post" action="/admin/accounts/${escapeHtml(account.id)}/disable">${csrfInput(session)}<button>Disable</button></form>`}</td></tr>`).join('');
  const keyRows = keys.map((key) => `<tr><td>${escapeHtml(key.code_hint)}</td><td>${escapeHtml(key.username || 'Unassigned')}</td><td>${escapeHtml(key.created_at)}</td><td>${key.revoked_at ? 'Revoked' : key.consumed_at ? 'Used' : key.expires_at && new Date(key.expires_at) < new Date() ? 'Expired' : 'Available'}</td></tr>`).join('');
  const reportRows = reports.map((item) => `<tr><td><a href="/admin/reports/${escapeHtml(item.id)}">${escapeHtml(item.report && item.report.hostname || 'Unknown device')}</a></td><td>${escapeHtml(item.username || 'Unassigned')}</td><td>${escapeHtml(item.created_at)}</td><td>${escapeHtml(item.report && item.report.assessment || 'Unknown')}</td></tr>`).join('');
  const reportLinks = paginationLinks('/admin', 'reportsPage', pagination.page, pagination.pages, { reportSearch: search, keyStatus: status });
  const content = `<p>Administrator dashboard · <a href="/admin/logout">Sign-out form</a></p>
<div><strong>${stats.accounts}</strong> owner accounts · <strong>${stats.keys}</strong> keys · <strong>${stats.reports}</strong> reports</div>
<section><h2>Create owner account</h2><form method="post" action="/admin/accounts">${csrfInput(session)}<label>Username <input name="username" required minlength="3" maxlength="40" autocomplete="off"></label><label>Temporary password <input type="password" name="password" required minlength="16" maxlength="256" autocomplete="new-password"></label><button>Create account</button></form></section>
<section><h2>Owner accounts</h2><table><thead><tr><th>Username</th><th>Created</th><th>Status</th><th>Action</th></tr></thead><tbody>${accountRows}</tbody></table></section>
<section><h2>Access keys</h2><p>Keys are created by owner accounts and displayed only once.</p><table><thead><tr><th>Hint</th><th>Owner</th><th>Created</th><th>Status</th></tr></thead><tbody>${keyRows}</tbody></table></section>
<section><h2>Reports</h2><form method="get" action="/admin"><label>Search <input name="reportSearch" value="${escapeHtml(search)}" maxlength="100"></label><button>Search</button></form><table><thead><tr><th>Device</th><th>Owner</th><th>Received</th><th>Assessment</th></tr></thead><tbody>${reportRows}</tbody></table>${reportLinks}</section>
<form method="post" action="/admin/logout">${csrfInput(session)}<button>Sign out</button></form>`;
  return page('Administrator dashboard', content);
}

function buildOwnerDashboard(session, account, keys, reports, pagination, query) {
  const keyRows = keys.map((key) => `<tr><td>${escapeHtml(key.code_hint)}</td><td>${escapeHtml(key.created_at)}</td><td>${key.revoked_at ? 'Revoked' : key.consumed_at ? 'Used' : key.expires_at && new Date(key.expires_at) < new Date() ? 'Expired' : 'Available'}</td><td>${key.revoked_at || key.consumed_at ? '' : `<form method="post" action="/owner/keys/${escapeHtml(key.id)}/revoke">${csrfInput(session)}<button>Revoke</button></form>`}</td></tr>`).join('');
  const reportRows = reports.map((item) => `<tr><td><a href="/owner/reports/${escapeHtml(item.id)}">${escapeHtml(item.report && item.report.hostname || 'Unknown device')}</a></td><td>${escapeHtml(item.created_at)}</td><td>${escapeHtml(item.report && item.report.assessment || 'Unknown')}</td></tr>`).join('');
  const reportLinks = paginationLinks('/owner', 'reportsPage', pagination.page, pagination.pages, { reportSearch: query });
  return page(`Owner dashboard — ${account.username}`, `<p>Reports and keys for this owner account only.</p>
<section><h2>Create one-time scan key</h2><form method="post" action="/owner/keys">${csrfInput(session)}<label>Expires after<select name="expiration" required><option value="1d">1 day</option><option value="7d">7 days</option><option value="30d">30 days</option><option value="365d">1 year</option><option value="never">Never</option></select></label><button>Create key</button></form></section>
<section><h2>Access keys</h2><table><thead><tr><th>Hint</th><th>Created</th><th>Status</th><th>Action</th></tr></thead><tbody>${keyRows}</tbody></table></section>
<section><h2>Your reports</h2><form method="get" action="/owner"><label>Search <input name="reportSearch" value="${escapeHtml(query)}" maxlength="100"></label><button>Search</button></form><table><thead><tr><th>Device</th><th>Received</th><th>Assessment</th></tr></thead><tbody>${reportRows}</tbody></table>${reportLinks}</section>
<section><h2>Change password</h2><form method="post" action="/owner/password">${csrfInput(session)}<label>New password <input name="password" type="password" minlength="16" maxlength="256" required autocomplete="new-password"></label><button>Change password</button></form></section>
<form method="post" action="/owner/logout">${csrfInput(session)}<button>Sign out</button></form>`);
}

function buildReportPage(title, report, session, deleteAction) {
  const summary = summarizeReport(report);
  const rows = Object.entries(summary).filter(([key]) => key !== 'findings')
    .map(([key, value]) => `<tr><th>${escapeHtml(key)}</th><td>${escapeHtml(value)}</td></tr>`).join('');
  const findings = summary.findings.map((finding) => `<li><strong>${escapeHtml(finding.severity)} · ${escapeHtml(finding.category)}</strong>: ${escapeHtml(finding.reason)} ${escapeHtml(finding.detail)}</li>`).join('');
  return page(title, `<p><a href="javascript:history.back()">Back to dashboard</a></p><section><h2>Summary</h2><table>${rows}</table><h3>Findings</h3><ul>${findings || '<li>No findings recorded.</li>'}</ul><h3>Raw report</h3><pre>${escapeHtml(JSON.stringify(report, null, 2))}</pre></section>${deleteAction ? `<section><h2>Delete report</h2><p>Deletion is permanent; it does not restore the consumed one-time code.</p><form method="post" action="${deleteAction}">${csrfInput(session)}<button>Delete report permanently</button></form></section>` : ''}`);
}

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet({ contentSecurityPolicy: false }));
  applyTrafficProtection(app, ['/admin', '/owner', '/validate-code', '/submit']);
  app.use(express.urlencoded({ extended: false, limit: '16kb' }));
  app.use(express.json({ limit: '1mb' }));

  const loginLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
  const codeLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false });

  function requireAdmin(req, res, next) {
    const session = readSession(req, COOKIE_NAMES.admin, 'admin');
    if (!session) return res.redirect('/admin/login');
    req.session = session;
    next();
  }

  function requireAccount(req, res, next) {
    const session = readSession(req, COOKIE_NAMES.account, 'account');
    if (!session) return res.redirect('/owner/login');
    pool.query('SELECT id, username, session_version, disabled_at FROM owner_accounts WHERE id = $1', [session.id])
      .then(({ rows }) => {
        const account = rows[0];
        if (!account || account.disabled_at || account.session_version !== session.sessionVersion) {
          res.setHeader('Set-Cookie', `${COOKIE_NAMES.account}=; ${cookieOptions(0)}`);
          return res.redirect('/owner/login');
        }
        req.session = session;
        req.account = account;
        next();
      }).catch(next);
  }

  app.get('/health', asyncRoute(async (_req, res) => {
    await pool.query('SELECT 1');
    res.type('text').send('ok');
  }));

  app.get('/privacy', (_req, res) => {
    const filename = path.join(__dirname, 'privacy-owner.html');
    const storage = process.env.LOCAL_DEMO === '1'
      ? 'The local demo uses temporary in-memory storage. Data is lost when its process stops.'
      : 'Reports are stored in the configured PostgreSQL database.';
    res.type('html').send(fs.readFileSync(filename, 'utf8').replace('{{STORAGE}}', storage));
  });

  app.get('/admin/login', (req, res) => {
    const token = issueLoginCsrf(res, COOKIE_NAMES.adminLoginCsrf);
    res.type('html').send(loginPage('/admin/login', COOKIE_NAMES.adminLoginCsrf, token));
  });

  app.post('/admin/login', loginLimiter, (req, res) => {
    if (!sameOrigin(req, res)) return;
    if (!loginCsrfValid(req, COOKIE_NAMES.adminLoginCsrf)) return res.status(403).send('Login request rejected.');
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    if (!safeEqual(password, process.env.OWNER_PASSWORD)) {
      const token = issueLoginCsrf(res, COOKIE_NAMES.adminLoginCsrf);
      return res.status(401).type('html').send(loginPage('/admin/login', COOKIE_NAMES.adminLoginCsrf, token, 'Invalid credentials.'));
    }
    setSession(res, COOKIE_NAMES.admin, 'admin', 'site-admin');
    res.redirect(303, '/admin');
  });

  app.get('/owner/login', (req, res) => {
    const token = issueLoginCsrf(res, COOKIE_NAMES.accountLoginCsrf);
    res.type('html').send(loginPage('/owner/login', COOKIE_NAMES.accountLoginCsrf, token));
  });

  app.post('/owner/login', loginLimiter, asyncRoute(async (req, res) => {
    if (!sameOrigin(req, res)) return;
    if (!loginCsrfValid(req, COOKIE_NAMES.accountLoginCsrf)) return res.status(403).send('Login request rejected.');
    const username = typeof req.body.username === 'string' ? req.body.username.trim().toLowerCase() : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const { rows } = await pool.query(
      'SELECT id, username, password_hash, password_salt, session_version, disabled_at FROM owner_accounts WHERE username = $1',
      [username]
    );
    const account = rows[0];
    if (!account || account.disabled_at || !verifyPassword(password, account.password_salt, account.password_hash)) {
      const token = issueLoginCsrf(res, COOKIE_NAMES.accountLoginCsrf);
      return res.status(401).type('html').send(loginPage('/owner/login', COOKIE_NAMES.accountLoginCsrf, token, 'Invalid credentials.'));
    }
    setSession(res, COOKIE_NAMES.account, 'account', account.id, account.session_version);
    res.redirect(303, '/owner');
  }));

  app.get('/admin', requireAdmin, asyncRoute(async (req, res) => {
    const reportPage = parsePage(typeof req.query.reportsPage === 'string' ? req.query.reportsPage : undefined);
    const keysPage = parsePage(typeof req.query.keysPage === 'string' ? req.query.keysPage : undefined);
    const reportSearch = parseSearch(req.query.reportSearch);
    const keyStatus = parseKeyStatus(req.query.keyStatus);
    const [accounts, counts, keyRows, reportCountResult] = await Promise.all([
      pool.query('SELECT id, username, created_at, disabled_at FROM owner_accounts ORDER BY created_at DESC'),
      pool.query(`SELECT (SELECT COUNT(*) FROM owner_accounts)::int AS accounts,
        (SELECT COUNT(*) FROM access_keys)::int AS keys,
        (SELECT COUNT(*) FROM reports)::int AS reports`),
      pool.query(`SELECT k.id, k.code_hint, k.created_at, k.expires_at, k.consumed_at, k.revoked_at, a.username
        FROM access_keys k LEFT JOIN owner_accounts a ON a.id = k.owner_id
        ORDER BY k.created_at DESC LIMIT 100 OFFSET $1`, [(keysPage - 1) * 100]),
      pool.query(`SELECT COUNT(*)::int AS total FROM reports r LEFT JOIN owner_accounts a ON a.id = r.owner_id
        WHERE ($1 = '' OR COALESCE(r.report->>'hostname', '') ILIKE $1 OR COALESCE(a.username, '') ILIKE $1)`, [`%${reportSearch}%`])
    ]);
    const pagination = pageWindow(reportPage, reportCountResult.rows[0].total, 25);
    const reports = await pool.query(`SELECT r.id, r.created_at, r.report, a.username
      FROM reports r LEFT JOIN owner_accounts a ON a.id = r.owner_id
      WHERE ($1 = '' OR COALESCE(r.report->>'hostname', '') ILIKE $1 OR COALESCE(a.username, '') ILIKE $1)
      ORDER BY r.created_at DESC LIMIT $2 OFFSET $3`, [
      reportSearch ? `%${reportSearch}%` : '',
      pagination.limit,
      pagination.offset
    ]);
    const html = buildAdminDashboard(req, req.session, counts.rows[0], accounts.rows, keyRows.rows, reports.rows, pagination);
    res.type('html').send(html);
  }));

  app.post('/admin/accounts', requireAdmin, (req, res, next) => {
    if (!sameOrigin(req, res)) return;
    if (!validCsrf(req, req.session)) return res.status(403).send('Request rejected.');
    const username = typeof req.body.username === 'string' ? req.body.username.trim().toLowerCase() : '';
    const password = req.body.password;
    if (!validUsername(username) || typeof password !== 'string' || password.length < 16 || password.length > 256) {
      return res.status(400).send('Invalid username or password.');
    }
    const credentials = hashPassword(password);
    pool.query(`INSERT INTO owner_accounts (id, username, password_hash, password_salt)
      VALUES ($1, $2, $3, $4)`, [crypto.randomUUID(), username, credentials.hash, credentials.salt])
      .then(() => res.redirect(303, '/admin'))
      .catch((error) => error.code === '23505'
        ? res.status(409).send('That username is already in use.')
        : next(error));
  });

  app.post('/admin/accounts/:id/disable', requireAdmin, asyncRoute(async (req, res) => {
    if (!sameOrigin(req, res)) return;
    if (!validCsrf(req, req.session)) return res.status(403).send('Request rejected.');
    await pool.query('UPDATE owner_accounts SET disabled_at = NOW(), session_version = session_version + 1 WHERE id = $1', [req.params.id]);
    res.redirect(303, '/admin');
  }));

  app.post('/admin/logout', requireAdmin, (req, res) => {
    if (!sameOrigin(req, res)) return;
    if (!validCsrf(req, req.session)) return res.status(403).send('Request rejected.');
    res.setHeader('Set-Cookie', `${COOKIE_NAMES.admin}=; ${cookieOptions(0)}`);
    res.redirect(303, '/admin/login');
  });

  app.get('/owner', requireAccount, asyncRoute(async (req, res) => {
    const reportPage = parsePage(typeof req.query.reportsPage === 'string' ? req.query.reportsPage : undefined);
    const search = parseSearch(req.query.reportSearch);
    const [keys, totalResult] = await Promise.all([
      pool.query(`SELECT id, code_hint, created_at, expires_at, consumed_at, revoked_at
        FROM access_keys WHERE owner_id = $1 ORDER BY created_at DESC LIMIT 100`, [req.account.id]),
      pool.query(`SELECT COUNT(*)::int AS total FROM reports
        WHERE owner_id = $1 AND ($2 = '' OR COALESCE(report->>'hostname', '') ILIKE $2)`,
      [req.account.id, search ? `%${search}%` : ''])
    ]);
    const pagination = pageWindow(reportPage, totalResult.rows[0].total, 25);
    const reports = await pool.query(`SELECT id, created_at, report FROM reports
      WHERE owner_id = $1 AND ($2 = '' OR COALESCE(report->>'hostname', '') ILIKE $2)
      ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
    [req.account.id, search ? `%${search}%` : '', pagination.limit, pagination.offset]);
    res.type('html').send(buildOwnerDashboard(req.session, req.account, keys.rows, reports.rows, pagination, search));
  }));

  app.post('/owner/keys', requireAccount, asyncRoute(async (req, res) => {
    if (!sameOrigin(req, res)) return;
    if (!validCsrf(req, req.session)) return res.status(403).send('Request rejected.');
    if (!Object.prototype.hasOwnProperty.call(require('./security').EXPIRATIONS, req.body.expiration)) {
      return res.status(400).send('Invalid expiration policy.');
    }
    let code;
    let keyId;
    for (let attempt = 0; attempt < 20 && !keyId; attempt += 1) {
      code = makeCode();
      try {
        keyId = crypto.randomUUID();
        await pool.query(`INSERT INTO access_keys (id, owner_id, code_hash, code_hint, expires_at)
          VALUES ($1, $2, $3, $4, $5)`, [
          keyId,
          req.account.id,
          hashCode(code, process.env.KEY_PEPPER),
          code.slice(-2),
          expirationDate(req.body.expiration)
        ]);
      } catch (error) {
        if (error.code === '23505') keyId = null;
        else throw error;
      }
    }
    if (!keyId) throw new Error('Could not allocate a unique one-time code.');
    const expiresAt = expirationDate(req.body.expiration);
    res.type('html').send(page('Key created', `<p>Copy this code now; it is shown once and cannot be recovered.</p><p class="new-code"><code>${escapeHtml(code)}</code></p><p>Expires: ${escapeHtml(expiresAt ? expiresAt.toISOString() : 'Never')}</p><p><a href="/owner">Return to dashboard</a></p>`));
  }));

  app.post('/owner/keys/:id/revoke', requireAccount, asyncRoute(async (req, res) => {
    if (!sameOrigin(req, res)) return;
    if (!validCsrf(req, req.session)) return res.status(403).send('Request rejected.');
    await pool.query('UPDATE access_keys SET revoked_at = NOW() WHERE id = $1 AND owner_id = $2 AND consumed_at IS NULL', [req.params.id, req.account.id]);
    res.redirect(303, '/owner');
  }));

  app.post('/owner/password', requireAccount, asyncRoute(async (req, res) => {
    if (!sameOrigin(req, res)) return;
    if (!validCsrf(req, req.session)) return res.status(403).send('Request rejected.');
    if (typeof req.body.password !== 'string' || req.body.password.length < 16 || req.body.password.length > 256) {
      return res.status(400).send('Password must contain 16 to 256 characters.');
    }
    const credentials = hashPassword(req.body.password);
    await pool.query(`UPDATE owner_accounts SET password_hash = $1, password_salt = $2,
      session_version = session_version + 1 WHERE id = $3`, [credentials.hash, credentials.salt, req.account.id]);
    res.setHeader('Set-Cookie', `${COOKIE_NAMES.account}=; ${cookieOptions(0)}`);
    res.redirect(303, '/owner/login');
  }));

  app.post('/owner/logout', requireAccount, (req, res) => {
    if (!sameOrigin(req, res)) return;
    if (!validCsrf(req, req.session)) return res.status(403).send('Request rejected.');
    res.setHeader('Set-Cookie', `${COOKIE_NAMES.account}=; ${cookieOptions(0)}`);
    res.redirect(303, '/owner/login');
  });

  app.get('/admin/reports/:id', requireAdmin, asyncRoute(async (req, res) => {
    const { rows } = await pool.query('SELECT report FROM reports WHERE id = $1', [req.params.id]);
    if (!rows[0]) return res.sendStatus(404);
    res.type('html').send(buildReportPage('Report details', rows[0].report, req.session, `/admin/reports/${encodeURIComponent(req.params.id)}/delete`));
  }));

  app.get('/owner/reports/:id', requireAccount, asyncRoute(async (req, res) => {
    const { rows } = await pool.query('SELECT report FROM reports WHERE id = $1 AND owner_id = $2', [req.params.id, req.account.id]);
    if (!rows[0]) return res.sendStatus(404);
    res.type('html').send(buildReportPage('Report details', rows[0].report, req.session, `/owner/reports/${encodeURIComponent(req.params.id)}/delete`));
  }));

  app.get(['/admin/reports/:id/delete', '/owner/reports/:id/delete'], (req, res, next) => {
    const isOwner = req.path.startsWith('/owner/');
    const middleware = isOwner ? requireAccount : requireAdmin;
    middleware(req, res, () => {
      req.sessionRole = isOwner ? 'account' : 'admin';
      next();
    });
  }, asyncRoute(async (req, res) => {
    const ownerId = req.sessionRole === 'account' ? req.account.id : null;
    const query = ownerId
      ? pool.query('SELECT report FROM reports WHERE id = $1 AND owner_id = $2', [req.params.id, ownerId])
      : pool.query('SELECT report FROM reports WHERE id = $1', [req.params.id]);
    const { rows } = await query;
    if (!rows[0]) return res.sendStatus(404);
    res.type('html').send(buildReportPage('Confirm report deletion', rows[0].report, req.session, `${req.path}`));
  }));

  app.post(['/admin/reports/:id/delete', '/owner/reports/:id/delete'], (req, res, next) => {
    const isOwner = req.path.startsWith('/owner/');
    (isOwner ? requireAccount : requireAdmin)(req, res, next);
  }, asyncRoute(async (req, res) => {
    if (!sameOrigin(req, res)) return;
    if (!validCsrf(req, req.session)) return res.status(403).send('Request rejected.');
    if (req.path.startsWith('/owner/')) {
      await pool.query('DELETE FROM reports WHERE id = $1 AND owner_id = $2', [req.params.id, req.account.id]);
      return res.redirect(303, '/owner');
    }
    await pool.query('DELETE FROM reports WHERE id = $1', [req.params.id]);
    res.redirect(303, '/admin');
  }));

  app.post('/validate-code', codeLimiter, asyncRoute(async (req, res) => {
    const code = req.body && req.body.code;
    if (!validCode(code)) return res.status(400).json({ ok: false });
    const { rows } = await pool.query(`SELECT id FROM access_keys
      WHERE code_hash = $1 AND consumed_at IS NULL AND revoked_at IS NULL
      AND (expires_at IS NULL OR expires_at > NOW())`, [hashCode(code, process.env.KEY_PEPPER)]);
    res.status(rows.length ? 200 : 400).json({ ok: rows.length > 0 });
  }));

  app.post('/submit', codeLimiter, asyncRoute(async (req, res) => {
    const code = req.body && req.body.code;
    const report = req.body && req.body.report;
    if (!validCode(code) || !report || typeof report !== 'object' || Array.isArray(report)) {
      return res.status(400).json({ ok: false });
    }
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(`SELECT id, owner_id, consumed_at, expires_at, revoked_at
        FROM access_keys WHERE code_hash = $1 FOR UPDATE`, [hashCode(code, process.env.KEY_PEPPER)]);
      const key = rows[0];
      if (!key) {
        await client.query('ROLLBACK');
        return res.status(400).json({ ok: false });
      }
      if (key.consumed_at) {
        const previous = await client.query('SELECT report FROM reports WHERE access_key_id = $1', [key.id]);
        await client.query('ROLLBACK');
        if (previous.rows[0] && JSON.stringify(previous.rows[0].report) === JSON.stringify(report)) {
          return res.json({ ok: true, duplicate: true });
        }
        return res.status(400).json({ ok: false });
      }
      if (key.revoked_at || (key.expires_at && new Date(key.expires_at) <= new Date())) {
        await client.query('ROLLBACK');
        return res.status(400).json({ ok: false });
      }
      const reportId = crypto.randomUUID();
      await client.query(`INSERT INTO reports (id, access_key_id, owner_id, report)
        VALUES ($1, $2, $3, $4::jsonb)`, [reportId, key.id, key.owner_id, JSON.stringify(report)]);
      await client.query('UPDATE access_keys SET consumed_at = NOW() WHERE id = $1', [key.id]);
      await client.query('COMMIT');
      res.json({ ok: true });
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }));

  app.use((error, _req, res, _next) => {
    console.error('Request failed:', error.message);
    if (res.headersSent) return;
    const status = httpErrorStatus(error);
    if (error.retryAfter) res.set('Retry-After', String(error.retryAfter));
    const message = status === 503
      ? 'The service is busy. Retry shortly.'
      : status === 413
        ? 'Request body is too large.'
        : status === 500
          ? 'The request could not be completed.'
          : 'Invalid request.';
    res.status(status).send(message);
  });
  return app;
}

async function start() {
  validateEnvironment(process.env);
  await initialize();
  const app = createApp();
  const host = process.env.HOST || '0.0.0.0';
  const port = Number(process.env.PORT || 3000);
  const server = configureHttpServer(app.listen(port, host, () => console.log(`Blue Detected server listening on ${host}:${port}.`)));
  return server;
}

if (require.main === module) {
  start().catch((error) => {
    console.error('Blue Detected server failed:', error.message);
    process.exitCode = 1;
  });
}

module.exports = { createApp, start, escapeHtml };
