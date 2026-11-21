'use strict';

const { Pool } = require('pg');
const { config } = require('./config');

/**
 * Idempotent schema initialisation. Safe to run concurrently from several
 * replicas: CREATE ... IF NOT EXISTS plus an advisory lock so two pods
 * starting at the same time do not race on catalog updates.
 */
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS dmarc_records (
  id            BIGSERIAL PRIMARY KEY,
  record_hash   TEXT        NOT NULL UNIQUE,
  report_date   DATE        NOT NULL,
  report_id     TEXT        NOT NULL DEFAULT '',
  reporting_org TEXT        NOT NULL DEFAULT '',
  domain        TEXT        NOT NULL DEFAULT '',
  policy        TEXT        NOT NULL DEFAULT '',
  source_ip     TEXT        NOT NULL DEFAULT '',
  mail_count    INTEGER     NOT NULL DEFAULT 0,
  disposition   TEXT        NOT NULL DEFAULT '',
  dkim_result   TEXT        NOT NULL DEFAULT '',
  spf_result    TEXT        NOT NULL DEFAULT '',
  header_from   TEXT        NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dmarc_records_report_date ON dmarc_records (report_date);
CREATE INDEX IF NOT EXISTS idx_dmarc_records_domain_source_ip ON dmarc_records (domain, source_ip);
`;

// Arbitrary constant used as the advisory-lock key for migrations.
const MIGRATION_LOCK_KEY = 727001;

/** Build the pg pool from DATABASE_URL or the PG* environment variables. */
function createPool() {
  const opts = { max: config.pgPoolMax, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30000 };
  if (config.databaseUrl) {
    opts.connectionString = config.databaseUrl;
    // sslmode inside the URL wins; otherwise fall back to PGSSLMODE.
    if (!/sslmode=/i.test(config.databaseUrl) && config.pgSsl) opts.ssl = config.pgSsl;
  } else {
    // pg reads PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD itself.
    opts.ssl = config.pgSsl;
  }
  const pool = new Pool(opts);
  // An idle client error must not crash the process; log without credentials.
  pool.on('error', (err) => console.error(`[db] idle client error: ${err.code || err.message}`));
  return pool;
}

/** Run the schema migration under a session-level advisory lock. */
async function migrate(pool) {
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_KEY]);
    await client.query(SCHEMA_SQL);
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_KEY]).catch(() => {});
    client.release();
  }
}

/**
 * Retry migration until the database is reachable (handles pods starting
 * before PostgreSQL in docker-compose / k8s).
 */
async function migrateWithRetry(pool, { attempts = 30, delayMs = 2000 } = {}) {
  for (let i = 1; ; i++) {
    try {
      await migrate(pool);
      return;
    } catch (err) {
      if (i >= attempts) throw err;
      console.warn(`[db] migration attempt ${i}/${attempts} failed (${err.code || err.message}); retrying`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

module.exports = { createPool, migrate, migrateWithRetry, SCHEMA_SQL };
