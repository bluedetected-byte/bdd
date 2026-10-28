# Blue Detected website and owner services

This folder contains two separately-started services:

- `npm start` runs the submitted Discord-based website, seller key API, and scan-report API. Production requires PostgreSQL; it never silently falls back to an ephemeral local file.
- `npm run start:owners` runs the separate PostgreSQL owner-account/report panel. Use this service only when you intentionally want its administrator-created accounts and owner-scoped reports.

Both services implement `/validate-code` and `/submit`, but they use separate databases, code formats, dashboards, and credentials. They are not automatically synchronized. Point the desktop client to the service whose key flow you are using.

## Website service

### Real behavior and configuration

- Discord sign-in uses OAuth `identify` only. The site does not receive Discord passwords or email addresses. OAuth is explicitly unavailable until both Discord OAuth credentials are configured.
- `ADMIN_TOKEN` protects the seller API. Keep it private and use at least 32 random bytes. Never put it in source code or a browser URL.
- `SESSION_SECRET` signs account sessions and must be a different random value, at least 32 bytes.
- Production requires `DATABASE_URL`, `BASE_URL`, Discord OAuth credentials, `ADMIN_TOKEN`, and `SESSION_SECRET`. The service refuses to start if required production settings are absent. Set `BASE_URL` to the exact public HTTPS origin and use the matching Discord redirect URI `/auth/discord/callback`.
- Set `TRUST_PROXY=1` only when deployed behind the trusted Render proxy. Do not enable it on a directly exposed server.
- The app limits all routes to 600 requests per IP per minute by default, API routes to 240/minute, scan/OAuth routes to tighter limits, and seller operations to 40 per 10 minutes. Tune via `GLOBAL_RATE_LIMIT_PER_MINUTE`, `API_RATE_LIMIT_PER_MINUTE`, and `SELLER_RATE_LIMIT_PER_10_MINUTES` after measuring legitimate traffic. A bounded write queue rejects excess pending data mutations with HTTP 503 instead of allowing an unbounded memory backlog (`MAX_PENDING_WRITES`, default 250). HTTP header/request timeouts and request-body limits reduce resource pressure.
- `/health` checks application initialization and pings PostgreSQL when configured; it returns `503` while storage is unavailable so the host can detect an unhealthy instance. `MAX_ACTIVE_CODES` defaults to 3; set it to 0 only to deliberately disable that per-owner cap.
- PostgreSQL writes complete before successful API responses. Reports are removed by the configured retention job (`RETENTION_DAYS`, 30 days by default). The current PostgreSQL storage uses one shared state document; run one website instance to avoid cross-instance write conflicts.
- In non-production development only, the service can use an atomic local JSON file (`DATA_FILE` or `server/data.json`). Corrupt data causes a visible startup error instead of silently resetting the database.
- `DOWNLOAD_URL` is optional. If it is not set, `/download/file` returns 404 with an explicit setup message; no fake download is served.
- `CONTACT_EMAIL` and `DISCORD_INVITE` are optional. Missing values are not replaced with fictitious contact details or invite links.

### Run the website locally

1. Use Node.js 20 or newer and run `npm ci` in this folder.
2. Copy `.env.example` to `.env`, enter your own development values, and keep `.env` private. Discord login needs a real Discord application with the exact local callback URL registered.
3. Run `npm start` and open the configured local origin. For local HTTP, use `NODE_ENV=development`; production cookies are HTTPS-only.
4. The `/seller` page requires the `ADMIN_TOKEN` value in its password field. Test key creation, revocation, Discord account linking, code creation and report delivery.

Without Discord OAuth credentials, `/auth/discord` returns an explicit `503`; without `DOWNLOAD_URL`, download requests return `404`. These are unconfigured integrations, not simulated successes.

### Availability and DDoS limits

Application rate limits are an extra layer, not a guarantee against DDoS. The built-in rate-limit store is in memory and only coordinates requests within one Node.js process; it resets on restart and does not aggregate across multiple instances. Keep the website on one instance unless you configure a shared rate-limit store. For public deployment, put the domain behind a provider-level CDN/WAF with DDoS mitigation, bot controls, and origin protection; keep the origin inaccessible except through the trusted proxy where the host supports that. A saturated network or hosting-provider limit cannot be fixed by application middleware.

## PostgreSQL owner panel (separate service)

The administrator at `/admin/login` creates named owner accounts. Each owner signs in at `/owner/login`, creates one-time scan codes, and can view or delete only reports assigned to their own account. The report recipient is determined from the stored code record on the server, never from a client-supplied owner ID. The administrator can audit accounts and reports. Use `.env.owner.example` as a separate local configuration template (`ENV_FILE=.env.owner`); do not mix owner-panel secrets into the website's `.env`.

Configure `DATABASE_URL`, `OWNER_PASSWORD` (16+ characters), `SESSION_SECRET` (32+ bytes), and a distinct `KEY_PEPPER` (32+ bytes). Generate secrets independently with:

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

Run the service with `npm run start:owners`. It uses PostgreSQL with TLS certificate verification in production. `DATABASE_SSL_CA` can provide a private CA certificate.

For an isolated local owner-panel demo without PostgreSQL, run `npm run start:local`. It binds only to `127.0.0.1:3187`, uses temporary in-memory storage and a public demo administrator password, and never sends reports to a hosted service. Do not use demo credentials in production. The client for this demo is built separately with `build-local.bat`; its embedded server address is `server.local.txt`.

Run `npm test` to exercise the local owner-account workflow, key issuance, report upload, owner isolation, and deletion.

## Deployment

The root `render.yaml` describes separate website and PostgreSQL owner-panel services. Provision PostgreSQL and PostgreSQL independently, enter all secret values in Render, and verify each `/health` endpoint before changing the desktop client's `server.txt`. No cloud account, database, credentials, or production deployment is created by this repository change.
