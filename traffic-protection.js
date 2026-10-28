'use strict';

const rateLimit = require('express-rate-limit');

const WINDOW_MS = 60 * 1000;

function positiveIntegerFromEnv(name, fallback, maximum = 100000) {
  const configured = process.env[name];
  if (configured === undefined || configured === '') return fallback;
  if (!/^\d+$/.test(configured)) throw new Error(`${name} must be a positive integer.`);
  const value = Number(configured);
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${name} must be between 1 and ${maximum}.`);
  }
  return value;
}

function nonNegativeIntegerFromEnv(name, fallback, maximum = 100000) {
  const configured = process.env[name];
  if (configured === undefined || configured === '') return fallback;
  if (!/^\d+$/.test(configured)) throw new Error(`${name} must be a non-negative integer.`);
  const value = Number(configured);
  if (!Number.isSafeInteger(value) || value > maximum) {
    throw new Error(`${name} must be between 0 and ${maximum}.`);
  }
  return value;
}

function applyTrafficProtection(app, apiPaths) {
  const trustProxy = process.env.TRUST_PROXY ?? '0';
  if (trustProxy !== '0' && trustProxy !== '1') {
    throw new Error('TRUST_PROXY must be 0 or 1.');
  }
  app.set('trust proxy', trustProxy === '1' ? 1 : false);

  const globalLimit = positiveIntegerFromEnv('GLOBAL_RATE_LIMIT_PER_MINUTE', 600);
  const apiLimit = positiveIntegerFromEnv('API_RATE_LIMIT_PER_MINUTE', 240);
  const options = {
    windowMs: WINDOW_MS,
    standardHeaders: 'draft-7',
    legacyHeaders: false
  };

  app.use(rateLimit({
    ...options,
    limit: globalLimit,
    skip: (req) => req.path === '/health',
    message: { error: 'Too many requests. Please try again later.' }
  }));

  app.use(apiPaths, rateLimit({
    ...options,
    limit: apiLimit,
    message: { error: 'API request limit reached. Please try again later.' }
  }));
}

function configureHttpServer(server) {
  server.headersTimeout = 10 * 1000;
  server.requestTimeout = 30 * 1000;
  server.keepAliveTimeout = 5 * 1000;
  server.maxHeadersCount = 100;
  return server;
}

function httpErrorStatus(error) {
  if (Number.isInteger(error && error.status) && error.status >= 400 && error.status < 500) {
    return error.status;
  }
  if (error && error.status === 503) return 503;
  return 500;
}

module.exports = {
  applyTrafficProtection,
  configureHttpServer,
  httpErrorStatus,
  nonNegativeIntegerFromEnv,
  positiveIntegerFromEnv
};
