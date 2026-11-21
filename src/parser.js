'use strict';

const crypto = require('node:crypto');
const { XMLParser } = require('fast-xml-parser');

/**
 * DMARC aggregate report (RFC 7489, appendix C) parsing, normalisation and
 * deterministic hashing. This module is the single source of truth for what
 * a "record" is – both raw XML and pre-parsed JSON go through normalizeRecord().
 */

const xml = new XMLParser({
  ignoreAttributes: true,
  parseTagValue: false, // keep everything as strings; we coerce explicitly
  trimValues: true,
  // Disable entity expansion to avoid billion-laughs style payloads.
  processEntities: false,
  // Only these paths repeat; policy_evaluated.dkim/spf must stay scalars.
  isArray: (name, jpath) =>
    ['feedback.record', 'feedback.record.auth_results.dkim', 'feedback.record.auth_results.spf'].includes(jpath),
});

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Coerce any value to a trimmed string ('' for null/undefined/objects). */
function str(v) {
  if (v === null || v === undefined || typeof v === 'object') return '';
  return String(v).trim();
}

/** Convert a UNIX timestamp (seconds) to an ISO date (YYYY-MM-DD, UTC). */
function epochToDate(seconds) {
  const n = Number(seconds);
  if (!Number.isFinite(n) || n <= 0) return '';
  return new Date(n * 1000).toISOString().slice(0, 10);
}

/**
 * Pick the effective DKIM/SPF result for a record. Prefer the DMARC-evaluated
 * policy_evaluated result (aligned pass/fail); fall back to the first raw
 * auth_results entry if policy_evaluated is missing.
 */
function pickResult(evaluated, authList) {
  const e = str(evaluated).toLowerCase();
  if (e) return e;
  const first = Array.isArray(authList) ? authList[0] : undefined;
  return first ? str(first.result).toLowerCase() : '';
}

/**
 * Validate and normalise one record into the canonical column shape.
 * Throws an Error with `status = 400` on invalid input.
 */
function normalizeRecord(input) {
  if (!input || typeof input !== 'object') throw badRequest('Record must be an object');
  const rec = {
    report_date: str(input.report_date),
    report_id: str(input.report_id),
    reporting_org: str(input.reporting_org),
    domain: str(input.domain).toLowerCase(),
    policy: str(input.policy).toLowerCase(),
    source_ip: str(input.source_ip),
    mail_count: Number(input.mail_count ?? 0),
    disposition: str(input.disposition).toLowerCase(),
    dkim_result: str(input.dkim_result ?? input.dkim).toLowerCase(),
    spf_result: str(input.spf_result ?? input.spf).toLowerCase(),
    header_from: str(input.header_from).toLowerCase(),
  };
  if (!DATE_RE.test(rec.report_date) || Number.isNaN(Date.parse(rec.report_date))) {
    throw badRequest('report_date must be a valid YYYY-MM-DD date');
  }
  if (!Number.isInteger(rec.mail_count) || rec.mail_count < 0 || rec.mail_count > 2147483647) {
    throw badRequest('mail_count must be a non-negative 32-bit integer');
  }
  for (const [k, v] of Object.entries(rec)) {
    if (typeof v === 'string' && v.length > 1024) throw badRequest(`${k} exceeds 1024 characters`);
  }
  rec.record_hash = recordHash(rec);
  return rec;
}

/**
 * Deterministic SHA-256 over every business field. Fields are JSON-encoded as
 * an ordered array so that separators inside values can never collide.
 */
function recordHash(r) {
  const parts = [
    r.report_id, r.report_date, r.reporting_org, r.domain, r.policy, r.source_ip,
    String(r.mail_count), r.disposition, r.dkim_result, r.spf_result, r.header_from,
  ];
  return crypto.createHash('sha256').update(JSON.stringify(parts)).digest('hex');
}

/**
 * Parse one DMARC aggregate XML document into normalised records.
 * The report date is the start of the report's date_range (UTC).
 */
function parseReportXml(text) {
  if (typeof text !== 'string' || !text.trim()) throw badRequest('XML document is empty');
  let doc;
  try {
    doc = xml.parse(text);
  } catch {
    throw badRequest('XML could not be parsed');
  }
  const feedback = doc && doc.feedback;
  if (!feedback || typeof feedback !== 'object') throw badRequest('Not a DMARC aggregate report (missing <feedback>)');

  const meta = feedback.report_metadata || {};
  const pol = feedback.policy_published || {};
  const reportDate = epochToDate(meta.date_range && meta.date_range.begin);
  const records = Array.isArray(feedback.record) ? feedback.record : [];

  return records.map((r) => {
    const row = r.row || {};
    const pe = row.policy_evaluated || {};
    const auth = r.auth_results || {};
    return normalizeRecord({
      report_date: reportDate,
      report_id: str(meta.report_id),
      reporting_org: str(meta.org_name),
      domain: str(pol.domain),
      policy: str(pol.p),
      source_ip: str(row.source_ip),
      mail_count: Number.parseInt(str(row.count) || '0', 10),
      disposition: str(pe.disposition),
      dkim_result: pickResult(pe.dkim, auth.dkim),
      spf_result: pickResult(pe.spf, auth.spf),
      header_from: str(r.identifiers && r.identifiers.header_from),
    });
  });
}

/** A record "fails" when neither DKIM nor SPF passed (DMARC fail). */
function isFailed(r) {
  return r.dkim_result !== 'pass' && r.spf_result !== 'pass';
}

function badRequest(message) {
  const err = new Error(message);
  err.status = 400;
  err.code = 'VALIDATION_FAILED';
  return err;
}

module.exports = { parseReportXml, normalizeRecord, recordHash, isFailed, epochToDate, badRequest };
