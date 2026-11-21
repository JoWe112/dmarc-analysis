-- Idempotent schema for dmarc-analysis. The application runs the same SQL
-- automatically at startup (src/db.js); this file is for DBAs who prefer to
-- apply migrations manually, e.g.:
--   psql "$DATABASE_URL" -f db/migrations/001_init.sql

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
