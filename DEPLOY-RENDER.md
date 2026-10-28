# Blue Detected — Render deployment (PostgreSQL)

This archive configures the main Blue Detected website/API to persist its application data in Render PostgreSQL. MongoDB configuration and the unused MongoDB package have been removed. The private `.env` file from the source archive is intentionally excluded.

## 1. Upload and deploy

1. Extract this ZIP and upload the contents to a GitHub repository. Keep `render.yaml` at the repository root and the app files inside `server/`.
2. In Render, choose **New + → Blueprint** and select that repository.
3. Create a PostgreSQL database in Render (**New + → PostgreSQL**).
4. Open the database page and copy its **Internal Database URL**.
5. In the web service's **Environment** settings, set `DATABASE_URL` to that URL. Do not post it publicly or commit it to GitHub.

## 2. Required environment variables

Set these in the Render web service:
- `DATABASE_URL`: Internal Database URL from the Render PostgreSQL database.
- `BASE_URL`: the exact public HTTPS origin for this web service, with no trailing slash.
- `ADMIN_TOKEN`: unique random secret, at least 32 bytes.
- `SESSION_SECRET`: a different unique random secret, at least 32 bytes.
- `DISCORD_CLIENT_ID` and `DISCORD_CLIENT_SECRET`: required by this website's Discord OAuth login.
- `NODE_ENV=production`, `TRUST_PROXY=1`, `RETENTION_DAYS=30`, `MAX_ACTIVE_CODES=3` (configured in `render.yaml`).

Generate secrets in PowerShell or a terminal by running this command twice:
```bash
node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
```
Use different outputs for `ADMIN_TOKEN` and `SESSION_SECRET`. Never put either secret in the desktop application or source files.

## 3. Discord OAuth callback

In Discord Developer Portal → OAuth2, add this redirect URI, replacing the hostname with your Render service hostname:
`https://YOUR-SERVICE.onrender.com/auth/discord/callback`

## 4. Verify

Redeploy, then open `https://YOUR-SERVICE.onrender.com/health`. A working service should return JSON with `status` set to `ok` and `storage` set to `postgresql`.

## Notes

- The main website/API stores its state in a PostgreSQL JSONB row in `blue_detected_store`; it creates the table automatically on startup.
- The separate owner portal launched with `npm run start:owners` uses PostgreSQL relational tables (`owner_accounts`, `access_keys`, `reports`) but remains a separate system and does not automatically share reports with the main website/API. Do not assume those two report systems are synchronized.
- The desktop app must use the public HTTPS URL of this API. The app's upload endpoint and payload must match the API routes already implemented in `server.js`.
- Do not commit `.env` or production secrets to GitHub.
