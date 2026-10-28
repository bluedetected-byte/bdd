# Netlify deployment

This package preserves the original `server/download.html` file unchanged. Netlify configuration and a serverless wrapper were added for the existing Express app.

Set environment variables in Netlify Site configuration (never commit real secrets): `NODE_ENV=production`, `BASE_URL=https://YOUR-SITE.netlify.app`, `DOWNLOAD_URL` (public HTTPS URL for the EXE), `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, `ADMIN_TOKEN`, `SESSION_SECRET`, and `DATABASE_URL`. Add `https://YOUR-SITE.netlify.app/auth/discord/callback` as the Discord OAuth redirect URI.

If Netlify secret scanning flags example/documentation files, fix the matching example values or configure the scan exclusions in Netlify environment settings; do not place real credentials in repository files.
