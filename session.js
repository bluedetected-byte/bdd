'use strict';

const crypto = require('node:crypto');

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const SESSION_TTL_SECONDS = SESSION_TTL_MS / 1000;

function signature(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

function createSession(userId, secret, now = Date.now()) {
  const payload = Buffer.from(JSON.stringify({
    id: userId,
    iat: now,
    exp: now + SESSION_TTL_MS
  })).toString('base64url');
  return `${payload}.${signature(payload, secret)}`;
}

function verifySession(token, secret, now = Date.now()) {
  if (typeof token !== 'string') return null;
  const [payload, suppliedSignature, ...extra] = token.split('.');
  if (!payload || !suppliedSignature || extra.length) return null;

  const expectedSignature = signature(payload, secret);
  const supplied = Buffer.from(suppliedSignature);
  const expected = Buffer.from(expectedSignature);
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return null;

  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof session.id !== 'string' || !session.id ||
        !Number.isSafeInteger(session.iat) || !Number.isSafeInteger(session.exp) ||
        session.iat > now || session.exp - session.iat !== SESSION_TTL_MS ||
        session.exp <= now) return null;
    return session.id;
  } catch {
    return null;
  }
}

module.exports = { SESSION_TTL_MS, SESSION_TTL_SECONDS, createSession, verifySession };
