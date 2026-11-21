'use strict';

/**
 * Data-access layer for dmarc_records. All SQL lives here.
 */

const COLUMNS = [
  'record_hash', 'report_date', 'report_id', 'reporting_org', 'domain', 'policy',
  'source_ip', 'mail_count', 'disposition', 'dkim_result', 'spf_result', 'header_from',
];

// 12 params per row; 500 rows = 6000 params, well below PostgreSQL's 65535 limit.
const CHUNK_SIZE = 500;

/**
 * Insert normalised records with `ON CONFLICT (record_hash) DO NOTHING`.
 * Returns the subset of records that were actually inserted (i.e. new).
 * Runs in a single transaction so a request is all-or-nothing.
 */
async function insertRecords(pool, records) {
  if (records.length === 0) return [];
  const byHash = new Map(records.map((r) => [r.record_hash, r]));
  const unique = [...byHash.values()];
  const inserted = [];

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (let i = 0; i < unique.length; i += CHUNK_SIZE) {
      const chunk = unique.slice(i, i + CHUNK_SIZE);
      const params = [];
      const tuples = chunk.map((r, rowIdx) => {
        const base = rowIdx * COLUMNS.length;
        COLUMNS.forEach((c) => params.push(r[c]));
        return `(${COLUMNS.map((_, j) => `$${base + j + 1}`).join(', ')})`;
      });
      const sql =
        `INSERT INTO dmarc_records (${COLUMNS.join(', ')}) VALUES ${tuples.join(', ')} ` +
        'ON CONFLICT (record_hash) DO NOTHING RETURNING record_hash';
      const res = await client.query(sql, params);
      for (const row of res.rows) inserted.push(byHash.get(row.record_hash));
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
  return inserted;
}

/**
 * Query history with optional filters.
 * @param {{days: number|null, failedOnly: boolean, q: string, limit: number}} f
 */
async function findRecords(pool, { days, failedOnly, q, limit }) {
  const where = [];
  const params = [];
  if (days !== null) {
    params.push(days);
    where.push(`report_date >= CURRENT_DATE - $${params.length}::int`);
  }
  if (failedOnly) {
    where.push(`dkim_result <> 'pass' AND spf_result <> 'pass'`);
  }
  if (q) {
    // Escape LIKE wildcards so user input is matched literally.
    params.push(`%${q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`);
    const p = `$${params.length}`;
    where.push(
      `(report_id ILIKE ${p} OR source_ip ILIKE ${p} OR reporting_org ILIKE ${p} ` +
        `OR domain ILIKE ${p} OR policy ILIKE ${p})`,
    );
  }
  params.push(limit);
  const sql =
    `SELECT id, record_hash, to_char(report_date, 'YYYY-MM-DD') AS report_date, report_id, reporting_org, ` +
    `domain, policy, source_ip, mail_count, disposition, dkim_result, spf_result, header_from, created_at ` +
    `FROM dmarc_records ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ` +
    `ORDER BY report_date DESC, id DESC LIMIT $${params.length}`;
  const res = await pool.query(sql, params);
  return res.rows;
}

module.exports = { insertRecords, findRecords, COLUMNS };
