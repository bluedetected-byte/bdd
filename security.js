'use strict';

const crypto = require('node:crypto');

const EXPIRATIONS = Object.freeze({
  '1d': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
  '365d': 365 * 24 * 60 * 60 * 1000,
  never: null
});

function validCode(value) {
  return typeof value === 'string' && /^\d{6}$/.test(value);
}

function hashCode(code, pepper) {
  if (!validCode(code)) throw new TypeError('A code must contain exactly six digits.');
  return crypto.createHmac('sha256', pepper).update(code, 'utf8').digest('hex');
}

function makeCode() {
  return crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
}

function expirationDate(policy, now = Date.now()) {
  if (!Object.prototype.hasOwnProperty.call(EXPIRATIONS, policy)) {
    throw new TypeError('Unsupported expiration policy.');
  }
  const duration = EXPIRATIONS[policy];
  return duration === null ? null : new Date(now + duration);
}

function validateEnvironment(env) {
  const localDemo = env.LOCAL_DEMO === '1';
  const required = ['OWNER_PASSWORD', 'SESSION_SECRET', 'KEY_PEPPER'];
  if (!localDemo) required.push('DATABASE_URL');
  const missing = required.filter((key) => !env[key]);
  if (missing.length) throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  if (localDemo && env.NODE_ENV === 'production') {
    throw new Error('LOCAL_DEMO cannot run with NODE_ENV=production.');
  }
  if (localDemo && !['127.0.0.1', '::1', 'localhost'].includes(env.HOST || '127.0.0.1')) {
    throw new Error('LOCAL_DEMO must bind to a loopback address only.');
  }
  if (env.OWNER_PASSWORD.length < 16) throw new Error('OWNER_PASSWORD must be at least 16 characters long.');
  for (const key of ['SESSION_SECRET', 'KEY_PEPPER']) {
    if (Buffer.byteLength(env[key], 'utf8') < 32) {
      throw new Error(`${key} must contain at least 32 bytes.`);
    }
  }
  if (env.SESSION_SECRET === env.KEY_PEPPER) {
    throw new Error('SESSION_SECRET and KEY_PEPPER must be different secrets.');
  }
  if (localDemo && env.OWNER_PASSWORD === 'BlueDemo-LocalOnly-2026!') {
    return;
  }
  if (localDemo && env.OWNER_PASSWORD.length < 16) {
    throw new Error('LOCAL_DEMO owner password must be at least 16 characters long.');
  }
}

function safeEqual(left, right) {
  const leftHash = crypto.createHash('sha256').update(String(left)).digest();
  const rightHash = crypto.createHash('sha256').update(String(right)).digest();
  return crypto.timingSafeEqual(leftHash, rightHash);
}

function validUsername(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,39}$/.test(value);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  if (typeof password !== 'string' || password.length < 16 || password.length > 256) {
    throw new TypeError('Passwords must contain 16 to 256 characters.');
  }
  return {
    salt,
    hash: crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex')
  };
}

function verifyPassword(password, salt, expectedHash) {
  if (typeof password !== 'string' || password.length > 256 ||
      typeof salt !== 'string' || !/^[0-9a-f]{32}$/.test(salt) ||
      typeof expectedHash !== 'string' || !/^[0-9a-f]{128}$/.test(expectedHash)) return false;
  const actual = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return crypto.timingSafeEqual(actual, Buffer.from(expectedHash, 'hex'));
}

module.exports = {
  EXPIRATIONS,
  expirationDate,
  hashCode,
  makeCode,
  safeEqual,
  hashPassword,
  validUsername,
  verifyPassword,
  validCode,
  validateEnvironment
};
