BLUE DETECTED — WEB SITE AND REPORT SERVICES

Requirements: Node.js 20 or later. Install dependencies with npm ci.

Primary website:
1. Configure ADMIN_TOKEN and SESSION_SECRET with different random secrets (at least 32 bytes each).
2. Configure DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, and BASE_URL, then register BASE_URL/auth/discord/callback in the Discord application.
3. Configure DATABASE_URL for persistent storage in production. Production startup refuses to use a local JSON file.
4. Optionally set DOWNLOAD_URL, CONTACT_EMAIL, and DISCORD_INVITE to real values.
5. Start with npm start.

Separate PostgreSQL owner-report service:
1. Configure DATABASE_URL, OWNER_PASSWORD, SESSION_SECRET, and a distinct KEY_PEPPER.
2. Start with npm run start:owners.

The PostgreSQL demo starts with npm run start:local and is limited to 127.0.0.1. Never deploy its public demo password.
Run npm test to verify the owner-report workflow. No service is deployed automatically.
