// Serveur Blue Detected
// Required in production: ADMIN_TOKEN, SESSION_SECRET, DATABASE_URL, BASE_URL,
// DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET.
const express = require('express'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config({ path: process.env.ENV_FILE || path.join(__dirname, '.env') });
const { SESSION_TTL_SECONDS, createSession, verifySession } = require('./session');
const {
  applyTrafficProtection,
  configureHttpServer,
  httpErrorStatus,
  nonNegativeIntegerFromEnv,
  positiveIntegerFromEnv
} = require('./traffic-protection');
const { createWriteQueue } = require('./write-queue');
const { Pool } = require('pg');
const ADMIN = process.env.ADMIN_TOKEN;
if (!ADMIN) throw new Error('ADMIN_TOKEN must be configured.');
const FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const DAY = 86400000, CODE_TTL = 24 * 3600000, SCAN_WINDOW = 30 * 60000;
const MAX_ACTIVE = nonNegativeIntegerFromEnv('MAX_ACTIVE_CODES', 3, 1000);
const RETENTION = Math.max(1, parseInt(process.env.RETENTION_DAYS, 10) || 30) * DAY;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('base64url');
const DC_ID = process.env.DISCORD_CLIENT_ID, DC_SECRET = process.env.DISCORD_CLIENT_SECRET;
const CONTACT = (process.env.CONTACT_EMAIL || '').trim();
const DOWNLOAD_URL = (process.env.DOWNLOAD_URL || '').trim();
const INVITE = /^https:\/\/(discord\.gg|discord\.com\/invite)\/[\w-]+$/.test(process.env.DISCORD_INVITE || '') ? process.env.DISCORD_INVITE : '';

if (process.env.NODE_ENV === 'production') {
  if (Buffer.byteLength(ADMIN, 'utf8') < 32) throw new Error('ADMIN_TOKEN must contain at least 32 bytes.');
  if (!process.env.SESSION_SECRET || Buffer.byteLength(process.env.SESSION_SECRET, 'utf8') < 32) {
    throw new Error('SESSION_SECRET must contain at least 32 bytes in production.');
  }
  if (ADMIN === process.env.SESSION_SECRET) throw new Error('ADMIN_TOKEN and SESSION_SECRET must be different secrets.');
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required in production; file storage is not durable on hosted instances.');
  let publicBaseUrl;
  try { publicBaseUrl = new URL(process.env.BASE_URL); } catch {}
  if (!publicBaseUrl || publicBaseUrl.protocol !== 'https:' || publicBaseUrl.username || publicBaseUrl.password ||
      publicBaseUrl.pathname !== '/' || publicBaseUrl.search || publicBaseUrl.hash ||
      publicBaseUrl.origin !== process.env.BASE_URL) {
    throw new Error('BASE_URL must be the public HTTPS origin in production.');
  }
  if (!DC_ID || !DC_SECRET) throw new Error('Discord OAuth credentials are required in production.');
}
if (CONTACT && !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(CONTACT)) {
  throw new Error('CONTACT_EMAIL must be a valid email address.');
}
if (DOWNLOAD_URL) {
  let downloadUrl;
  try { downloadUrl = new URL(DOWNLOAD_URL); } catch { throw new Error('DOWNLOAD_URL must be an absolute URL.'); }
  if (downloadUrl.username || downloadUrl.password ||
      (downloadUrl.protocol !== 'https:' && !(process.env.NODE_ENV !== 'production' && downloadUrl.hostname === '127.0.0.1' && downloadUrl.protocol === 'http:'))) {
    throw new Error('DOWNLOAD_URL must use HTTPS.');
  }
}

let cache = { keys: {}, checks: {}, users: {} }, pgPool = null, initialized = false;
const maxPendingWrites = positiveIntegerFromEnv('MAX_PENDING_WRITES', 250);
const enqueueWrite = createWriteQueue(maxPendingWrites);
const load = () => cache;
const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

async function persist(data) {
  const snapshot = structuredClone(data);
  if (pgPool) {
    await pgPool.query(
      'INSERT INTO blue_detected_store (id, data) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()',
      ['main', JSON.stringify(snapshot)]
    );
  } else {
    const temporaryFile = `${FILE}.${process.pid}.tmp`;
    fs.mkdirSync(path.dirname(FILE), { recursive: true });
    fs.writeFileSync(temporaryFile, JSON.stringify(snapshot), { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(temporaryFile, FILE);
  }
  cache = snapshot;
}

function updateData(mutator) {
  return enqueueWrite(async () => {
    const next = structuredClone(cache);
    const result = await mutator(next);
    await persist(next);
    return result;
  });
}

async function init() {
  if (process.env.DATABASE_URL) {
    pgPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      // Render's internal PostgreSQL connection string is intended for private
      // service-to-database traffic. Set PGSSL=true only if your provider requires TLS.
      ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : undefined,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    });
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS blue_detected_store (
        id TEXT PRIMARY KEY,
        data JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    const result = await pgPool.query('SELECT data FROM blue_detected_store WHERE id = $1', ['main']);
    if (result.rows.length) {
      if (!isRecord(result.rows[0].data)) throw new Error('PostgreSQL contains an invalid application data document.');
      cache = result.rows[0].data;
    } else {
      await pgPool.query('INSERT INTO blue_detected_store (id, data) VALUES ($1, $2::jsonb)', ['main', JSON.stringify(cache)]);
    }
    console.log('PostgreSQL persistence connected.');
  } else if (fs.existsSync(FILE)) {
    cache = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    if (!isRecord(cache)) throw new Error('Local data file has an invalid format.');
  }

  for (const collection of ['keys', 'checks', 'users']) {
    if (cache[collection] === undefined) cache[collection] = {};
    else if (!isRecord(cache[collection])) throw new Error(`Stored ${collection} data has an invalid format.`);
  }
  initialized = true;
}

async function purge() {
  const removed = await updateData((db) => {
    let count = 0;
    for (const code of Object.keys(db.checks)) {
      if (Date.now() - db.checks[code].createdAt > RETENTION) {
        delete db.checks[code];
        count += 1;
      }
    }
    return count;
  });
  if (removed) console.log(`${removed} expired report(s) deleted.`);
}

// ---------- Utilitaires ----------
const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
applyTrafficProtection(app, ['/auth', '/owner', '/seller', '/validate-code', '/submit']);
app.use(express.json({ limit: '1mb' }));
const sellerLimit = positiveIntegerFromEnv('SELLER_RATE_LIMIT_PER_10_MINUTES', 40);
const sellerLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: sellerLimit,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Seller request limit reached. Please try again later.' }
});
const parseCookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map((x) => x.trim()).filter(Boolean).map((x) => { const i = x.indexOf('='); return [x.slice(0, i), x.slice(i + 1)]; }));
function readSession(req) {
  return verifySession(parseCookies(req).sess, SECRET);
}
const baseUrl = (req) => process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
const cookie = (name, val, age) => `${name}=${val}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
const adminTokenMatches = (supplied) => {
  if (typeof supplied !== 'string') return false;
  const expected = crypto.createHash('sha256').update(ADMIN).digest();
  const actual = crypto.createHash('sha256').update(supplied).digest();
  return crypto.timingSafeEqual(actual, expected);
};

// ---------- Vendeur (vous) : clés ----------
const adminAuth = (q, r, n) => adminTokenMatches(q.headers['x-admin-token']) ? n() : r.status(401).json({ error: 'Non autorisé' });
app.post('/seller/create', sellerLimiter, adminAuth, async (req, res, next) => {
  const body = req.body || {};
  const days = Number.parseInt(body.days, 10), count = Number.parseInt(body.count, 10);
  if (!Number.isInteger(days) || days < 1 || days > 3650 || !Number.isInteger(count) || count < 1 || count > 100) {
    return res.status(400).json({ error: 'Durée (1–3650 jours) ou quantité (1–100) invalide.' });
  }
  try {
    const result = await updateData((db) => {
      const made = [];
      while (made.length < count) {
        const key = 'PCK-' + [1, 2, 3].map(() => crypto.randomBytes(2).toString('hex').toUpperCase()).join('-');
        if (db.keys[key]) continue;
        db.keys[key] = { days, createdAt: Date.now(), expiresAt: null, revoked: false, owner: null, label: String(body.label || '').slice(0, 60) };
        made.push(key);
      }
      return made;
    });
    res.json({ keys: result, days });
  } catch (error) {
    next(error);
  }
});
app.get('/seller/list', sellerLimiter, adminAuth, (_, res) => {
  const db = load(); res.json(Object.entries(db.keys).map(([key, v]) => ({ key, ...v,
    ownerName: v.owner && db.users[v.owner] ? db.users[v.owner].name : '',
    checks: Object.values(db.checks).filter((c) => c.key === key).length })));
});
app.post('/seller/revoke', sellerLimiter, adminAuth, async (req, res, next) => {
  try {
    const key = typeof req.body?.key === 'string' ? req.body.key.trim().toUpperCase() : '';
    if (!/^PCK-(?:[A-F0-9]{4}-){2}[A-F0-9]{4}$/.test(key)) {
      return res.status(400).json({ error: 'Invalid key format.' });
    }
    const found = await updateData((db) => {
      if (!db.keys[key]) return false;
      db.keys[key].revoked = true;
      return true;
    });
    res.status(found ? 200 : 404).json(found ? { ok: true } : { error: 'Introuvable' });
  } catch (error) { next(error); }
});
app.post('/seller/unbind', sellerLimiter, adminAuth, async (req, res, next) => {
  try {
    const key = typeof req.body?.key === 'string' ? req.body.key.trim().toUpperCase() : '';
    if (!/^PCK-(?:[A-F0-9]{4}-){2}[A-F0-9]{4}$/.test(key)) {
      return res.status(400).json({ error: 'Invalid key format.' });
    }
    const found = await updateData((db) => {
      const keyRecord = db.keys[key];
      if (!keyRecord) return false;
      Object.values(db.users).forEach((user) => { if (user.key === key) user.key = null; });
      keyRecord.owner = null;
      return true;
    });
    res.status(found ? 200 : 404).json(found ? { ok: true } : { error: 'Introuvable' });
  } catch (error) { next(error); }
});

// ---------- Connexion Discord ----------
const oauthLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: 'Too many sign-in attempts. Please try again later.'
});
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Scan request limit reached. Please try again later.' }
});
app.get('/auth/discord', oauthLimiter, (req, res) => {
  if (!DC_ID || !DC_SECRET) return res.status(503).send('Discord sign-in is not configured (DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET).');
  const state = crypto.randomBytes(16).toString('hex');
  res.setHeader('Set-Cookie', cookie('ost', state, 600));
  res.redirect('https://discord.com/oauth2/authorize?' + new URLSearchParams({ client_id: DC_ID, response_type: 'code',
    redirect_uri: baseUrl(req) + '/auth/discord/callback', scope: 'identify', state, prompt: 'none' }));
});
app.get('/auth/discord/callback', oauthLimiter, async (req, res) => {
  if (!DC_ID || !DC_SECRET) {
    return res.status(503).send('Discord sign-in is not configured (DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET).');
  }
  try {
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const stateCookie = parseCookies(req).ost || '';
    if (typeof req.query.code !== 'string' || !state || !stateCookie) {
      return res.status(400).send('Sign-in denied. <a href="/">Retour</a>');
    }
    const stateMatches = crypto.timingSafeEqual(
      crypto.createHash('sha256').update(state).digest(),
      crypto.createHash('sha256').update(stateCookie).digest()
    );
    if (!stateMatches) return res.status(400).send('Sign-in denied. <a href="/">Retour</a>');
    const tr = await fetch('https://discord.com/api/oauth2/token', { method: 'POST', signal: AbortSignal.timeout(10000), headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: DC_ID, client_secret: DC_SECRET, grant_type: 'authorization_code', code: String(req.query.code), redirect_uri: baseUrl(req) + '/auth/discord/callback' }) });
    if (!tr.ok) throw new Error(`Discord token endpoint returned HTTP ${tr.status}.`);
    const t = await tr.json(); if (!t.access_token) throw new Error('Discord did not return an access token.');
    const userResponse = await fetch('https://discord.com/api/users/@me', { signal: AbortSignal.timeout(10000), headers: { Authorization: 'Bearer ' + t.access_token } });
    if (!userResponse.ok) throw new Error(`Discord profile endpoint returned HTTP ${userResponse.status}.`);
    const u = await userResponse.json();
    if (!u.id) throw new Error('user');
    await updateData((db) => {
      const previous = db.users[u.id] || { id: u.id, createdAt: Date.now(), key: null };
      db.users[u.id] = Object.assign(previous, {
        name: String(u.global_name || u.username || '').slice(0, 60),
        avatar: typeof u.avatar === 'string' ? u.avatar : null
      });
    });
    res.setHeader('Set-Cookie', [cookie('sess', createSession(u.id, SECRET), SESSION_TTL_SECONDS), cookie('ost', '', 0)]);
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Discord OAuth callback failed:', error.message);
    res.status(502).send('Discord sign-in is unavailable. Please try again later.');
  }
});
app.post('/auth/logout', (req, res) => {
  const origin = req.get('origin');
  if (origin && origin !== 'null') {
    try {
      if (new URL(origin).host !== req.get('host')) return res.status(403).json({ error: 'Origine refusée' });
    } catch { return res.status(403).json({ error: 'Origine refusée' }); }
  }
  res.setHeader('Set-Cookie', cookie('sess', '', 0));
  res.json({ ok: true });
});

// ---------- Propriétaire de serveur (compte Discord + clé) ----------
function userAuth(req, res, next) {
  const id = readSession(req), db = load(), u = id && db.users[id];
  if (!u) return res.status(401).json({ error: 'Not signed in' });
  req.user = u; req.db = db; next();
}
function keyState(db, u) {
  const k = u.key && db.keys[u.key];
  if (!k) return { status: 'none' };
  if (k.revoked) return { status: 'revoked', k };
  if (!k.expiresAt || Date.now() > k.expiresAt) return { status: 'expired', k };
  return { status: 'ok', k };
}
function ownerAuth(req, res, next) {
  userAuth(req, res, () => {
    const s = keyState(req.db, req.user);
    if (s.status !== 'ok') return res.status(403).json({ error: { none: 'No active key', expired: 'Key expired', revoked: 'Key disabled' }[s.status], status: s.status });
    req.k = s.k; next();
  });
}
app.get('/owner/me', userAuth, (req, res) => {
  const s = keyState(req.db, req.user), u = req.user;
  res.json({ user: { id: u.id, name: u.name, avatar: u.avatar }, status: s.status, expiresAt: s.k && s.k.expiresAt || null });
});
app.post('/owner/activate', scanLimiter, userAuth, async (req, res, next) => {
  try {
    const result = await updateData((db) => {
      const user = db.users[req.user.id];
      const key = String((req.body || {}).key || '').trim().toUpperCase();
      const item = db.keys[key];
      if (!item) return { ok: false, error: 'Key invalide' };
      if (item.revoked) return { ok: false, error: 'Key disabled' };
      if (item.owner && item.owner !== user.id) return { ok: false, error: 'Cette clé est déjà liée à un autre compte Discord' };
      if (keyState(db, user).status === 'ok' && user.key !== key) return { ok: false, error: 'You already have an active key' };
      if (!item.owner) item.owner = user.id;
      if (!item.expiresAt) item.expiresAt = Date.now() + item.days * DAY;
      user.key = key;
      return { ok: true, expiresAt: item.expiresAt };
    });
    res.json(result);
  } catch (error) { next(error); }
});
const mine = (db, u) => Object.entries(db.checks).filter(([, c]) => { const k = db.keys[c.key]; return k && k.owner === u.id; });
app.post('/owner/check/new', scanLimiter, ownerAuth, async (req, res, next) => {
  try {
    const result = await updateData((db) => {
      const user = db.users[req.user.id];
      const activeNow = mine(db, user).filter(([, check]) => !check.report && Date.now() - check.createdAt <= CODE_TTL).length;
      if (MAX_ACTIVE && activeNow >= MAX_ACTIVE) {
        return { error: `Maximum ${MAX_ACTIVE} codes actifs. Attendez qu'un joueur termine ou qu'un code expire.`, status: 429 };
      }
      let code;
      do { code = String(crypto.randomInt(100000, 1000000)); } while (db.checks[code]);
      db.checks[code] = {
        key: user.key,
        player: String((req.body || {}).player || '').slice(0, 60),
        createdAt: Date.now(),
        report: null
      };
      return { code };
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    res.json(result);
  } catch (error) { next(error); }
});
app.get('/owner/checks', ownerAuth, (req, res) => {
  res.json({ expiresAt: req.k.expiresAt, retentionDays: RETENTION / DAY, maxActive: MAX_ACTIVE, checks: mine(req.db, req.user)
    .sort((a, b) => b[1].createdAt - a[1].createdAt).slice(0, 200).map(([code, c]) => ({
      code, player: c.player, createdAt: c.createdAt, done: !!c.report,
      expired: !c.report && Date.now() - c.createdAt > CODE_TTL, expiresAt: c.createdAt + CODE_TTL,
      scanning: !c.report && !!c.startedAt && Date.now() - c.startedAt < SCAN_WINDOW && Date.now() - c.createdAt <= CODE_TTL, stats: c.report ? c.report.stats : null })) });
});
app.get('/owner/check/:code', ownerAuth, (req, res) => {
  const e = mine(req.db, req.user).find(([code]) => code === req.params.code); if (!e) return res.json({ error: 'Introuvable' });
  res.json({ player: e[1].player, report: e[1].report });
});
app.post('/owner/check/delete', scanLimiter, ownerAuth, async (req, res, next) => {
  try {
    const result = await updateData((db) => {
      const code = String((req.body || {}).code || '');
      if (!mine(db, db.users[req.user.id]).some(([storedCode]) => storedCode === code)) return false;
      delete db.checks[code];
      return true;
    });
    res.status(result ? 200 : 404).json(result ? { ok: true } : { ok: false, error: 'Introuvable' });
  } catch (error) { next(error); }
});

// ---------- Joueur ----------
function codeError(db, code) {
  if (!/^\d{6}$/.test(code)) return 'Code invalide';
  const c = db.checks[code];
  if (!c) return 'Code invalide';
  if (c.report) return 'This code has already been used';
  if (Date.now() - c.createdAt > CODE_TTL) return 'Code expiré';
  const k = db.keys[c.key];
  if (!k || k.revoked || !k.expiresAt || Date.now() > k.expiresAt) return 'Subscription du serveur expiré';
  return null;
}
app.post('/validate-code', scanLimiter, async (req, res, next) => {
  try {
    const code = typeof req.body.code === 'string' ? req.body.code : '';
    const result = await updateData((db) => {
      const error = codeError(db, code);
      if (error) return { error };
      db.checks[code].startedAt = Date.now();
      return { ok: true };
    });
    res.status(result.ok ? 200 : 400).json(result);
  } catch (error) { next(error); }
});
app.post('/submit', scanLimiter, async (req, res, next) => {
  try {
    const code = typeof req.body.code === 'string' ? req.body.code : '';
    const report = req.body.report;
    if (!report || typeof report !== 'object' || Array.isArray(report) ||
        Buffer.byteLength(JSON.stringify(report), 'utf8') > 1024 * 1024) {
      return res.status(400).json({ ok: false, error: 'Invalid or oversized report.' });
    }
    const result = await updateData((db) => {
      const check = db.checks[code];
      if (check && check.report) {
        return JSON.stringify(check.report) === JSON.stringify(report)
          ? { ok: true, duplicate: true }
          : { ok: false, error: 'This code has already been used' };
      }
      const error = codeError(db, code);
      if (error) return { ok: false, error };
      db.checks[code].report = report;
      return { ok: true };
    });
    res.status(result.ok ? 200 : 400).json(result);
  } catch (error) { next(error); }
});

// ---------- Pages ----------
const page = (f) => (_, r) => r.sendFile(path.join(__dirname, f));
const legal = (f) => (_, r) => {
  const contact = CONTACT ? `<a href="mailto:${CONTACT}">${CONTACT}</a>` : 'Contact details are not configured.';
  const html = fs.readFileSync(path.join(__dirname, f), 'utf8')
    .replace(/<a href="mailto:\{\{CONTACT\}\}">\{\{CONTACT\}\}<\/a>/g, contact)
    .split('{{DAYS}}').join(String(RETENTION / DAY));
  r.type('html').send(html);
};
app.get('/download', page('download.html'));
app.get('/download/file', (_, r) => DOWNLOAD_URL ? r.redirect(DOWNLOAD_URL) : r.status(404).send('Download is not configured (DOWNLOAD_URL).'));
app.get('/privacy', legal('privacy.html'));
app.get('/terms', legal('terms.html'));
app.get('/health', async (_req, res) => {
  if (!initialized) return res.status(503).json({ status: 'not_ready' });
  try {
    if (pgPool) await pgPool.query('SELECT 1');
    res.json({ status: 'ok', storage: pgPool ? 'postgresql' : 'local' });
  } catch (error) {
    console.error('Website health check failed:', error.message);
    res.status(503).json({ status: 'not_ready' });
  }
});
app.get('/logo.png', page('logo.png'));
app.get('/', (_, r) => r.type('html').send(fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8').split('{{INVITE}}').join(INVITE)));
app.get('/dashboard', page('dashboard.html'));
app.get('/style.css', page('style.css'));
app.get('/discord.svg', page('discord.svg'));
app.get('/seller', page('seller.html'));

async function start() {
  await init();
  await purge();
  const purgeTimer = setInterval(() => {
    purge().catch((error) => console.error('Report retention cleanup failed:', error.message));
  }, 6 * 3600000);
  purgeTimer.unref();
  // Render web services must bind to all network interfaces, not 127.0.0.1.
  const host = '0.0.0.0';
  const port = Number(process.env.PORT || 10000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be a valid TCP port.');
  }
  const server = configureHttpServer(
    app.listen(port, host, () => {
      console.log(`Blue Detected website listening on ${host}:${port}.`);
    })
  );
  server.on('close', async () => {
    clearInterval(purgeTimer);
    await pgPool?.end();
  });
  return server;
}

app.use((error, _req, res, _next) => {
  console.error('Website request failed:', error.message);
  if (!res.headersSent) {
    const status = httpErrorStatus(error);
    if (error.retryAfter) res.set('Retry-After', String(error.retryAfter));
    const message = status === 503
      ? 'The service is busy. Retry shortly.'
      : status === 413
        ? 'Request body is too large.'
        : status === 500
          ? 'The request could not be completed.'
          : 'Invalid request.';
    res.status(status).json({ error: message });
  }
});

if (require.main === module) {
  start().catch((error) => {
    console.error('Website startup failed:', error.message);
    process.exitCode = 1;
  });
}

module.exports = { app, init, start };
