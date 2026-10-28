'use strict';

const crypto = require('node:crypto');

process.env.NODE_ENV = 'development';
process.env.LOCAL_DEMO = '1';
process.env.HOST = '127.0.0.1';
process.env.PORT = '3187';
process.env.OWNER_PASSWORD = 'BlueDemo-LocalOnly-2026!';
process.env.SESSION_SECRET = crypto.randomBytes(32).toString('base64url');
process.env.KEY_PEPPER = crypto.randomBytes(32).toString('base64url');
delete process.env.DATABASE_URL;

console.log('LOCAL DEMO ONLY: bound to 127.0.0.1 with volatile in-memory storage.');
console.log(`Owner login: ${process.env.OWNER_PASSWORD}`);
console.log('Dashboard: http://127.0.0.1:3187/admin/login');
console.log('Stop with Ctrl+C. Local keys and reports are lost when the server stops.');

require('./owner-server').start().catch((error) => {
  console.error('Local demo server failed:', error.message);
  process.exitCode = 1;
});
