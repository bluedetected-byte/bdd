'use strict';

const { Pool } = require('pg');

const schema = `
  CREATE TABLE IF NOT EXISTS owner_accounts (
    id UUID PRIMARY KEY,
    username VARCHAR(40) NOT NULL UNIQUE,
    password_hash CHAR(128) NOT NULL,
    password_salt CHAR(32) NOT NULL,
    session_version INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disabled_at TIMESTAMPTZ
  );
  CREATE TABLE IF NOT EXISTS access_keys (
    id UUID PRIMARY KEY,
    owner_id UUID REFERENCES owner_accounts(id),
    code_hash CHAR(64) NOT NULL UNIQUE,
    code_hint CHAR(2) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
  );
  CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY,
    access_key_id UUID NOT NULL UNIQUE REFERENCES access_keys(id),
    owner_id UUID REFERENCES owner_accounts(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    report JSONB NOT NULL
  );
  ALTER TABLE access_keys ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES owner_accounts(id);
  ALTER TABLE reports ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES owner_accounts(id);
  ALTER TABLE owner_accounts ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0;
  CREATE INDEX IF NOT EXISTS access_keys_owner_created_idx ON access_keys(owner_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS reports_owner_created_idx ON reports(owner_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS reports_created_at_idx ON reports(created_at DESC);
  CREATE INDEX IF NOT EXISTS access_keys_created_at_idx ON access_keys(created_at DESC);
`;

if (process.env.LOCAL_DEMO === '1') {
  const { newDb } = require('pg-mem');
  const memoryDb = newDb({ autoCreateForeignKeyIndices: true });
  const memoryPool = memoryDb.adapters.createPg().Pool;
  const pool = new memoryPool();
  module.exports = {
    initialize: async () => pool.query(schema),
    pool
  };
  return;
}

const ssl = process.env.DATABASE_SSL_CA
  ? { ca: process.env.DATABASE_SSL_CA.replace(/\\n/g, '\n'), rejectUnauthorized: true }
  : process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: true }
    : undefined;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

async function initialize() {
  await pool.query(schema);
}

module.exports = { initialize, pool };
