'use strict';

const path = require('node:path');
const fs = require('node:fs');
const express = require('express');
const { parseReportXml, normalizeRecord, badRequest } = require('./parser');
const { insertRecords, findRecords } = require('./repository');
const { failureStats, buildAlerts, sendAlerts } = require('./alerts');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const OPENAPI_PATH = path.join(__dirname, '..', 'docs', 'openapi.yaml');
const ALLOWED_DAYS = new Set(['7', '30', '90', 'all']);

/** Send the standard JSON error envelope. */
function sendError(res, status, code, message) {
  res.status(status).json({ error: { code, message } });
}

/**
 * Build the Express application. Dependencies are injected so integration
 * tests can supply their own pool / config.
 *
 * @param {{ pool: import('pg').Pool, config: object }} deps
 */
function createApp({ pool, config }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', true); // runs behind an ingress / gateway

  // Basic hardening headers for the static UI.
  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
    });
    next();
  });

  app.use(express.json({ limit: config.bodyLimit }));
  app.use(express.text({ type: ['application/xml', 'text/xml', 'text/plain'], limit: config.bodyLimit }));

  /** Liveness/readiness: 200 only when PostgreSQL answers SELECT 1. */
  app.get('/healthz', async (req, res) => {
    try {
      await pool.query('SELECT 1');
      res.json({ status: 'ok', database: 'up', version: config.version });
    } catch (err) {
      console.warn(`[healthz] database check failed: ${err.code || err.message}`);
      sendError(res, 503, 'DATABASE_UNAVAILABLE', 'The database is not reachable.');
    }
  });

  app.get('/api/version', (req, res) => res.json({ version: config.version }));

  /**
   * Ingest DMARC data. Accepted bodies:
   *  - application/xml | text/xml: one raw aggregate report
   *  - application/json: { xml: string | string[] } and/or { records: Record[] }
   */
  app.post('/api/reports', async (req, res, next) => {
    try {
      const records = collectRecords(req.body);
      const inserted = await insertRecords(pool, records);
      const uniqueCount = new Set(records.map((r) => r.record_hash)).size;
      const stats = failureStats(inserted);
      const alerts = buildAlerts(inserted, config.alertThreshold);
      const summary = {
        failedMails: stats.failedMails,
        totalMails: stats.totalMails,
        failedRate: Number(stats.failedRate.toFixed(4)),
        failedPercent: Number((stats.failedRate * 100).toFixed(2)),
        threshold: config.alertThreshold,
      };
      const alert = await sendAlerts(config.alertWebhookUrl, alerts, config.alertTimeoutMs, summary);

      res.status(inserted.length > 0 ? 201 : 200).json({
        received: records.length,
        inserted: inserted.length,
        duplicates: records.length - inserted.length,
        uniqueInRequest: uniqueCount,
        ...summary,
        alertTriggered: alerts.length > 0,
        alertSent: alert.sent,
        alerts,
      });
    } catch (err) {
      next(err);
    }
  });

  /** History with filters: days (7|30|90|all), failedOnly (true|false), q (free text). */
  app.get('/api/records', async (req, res, next) => {
    try {
      const days = String(req.query.days ?? '30');
      if (!ALLOWED_DAYS.has(days)) throw badRequest('days must be one of 7, 30, 90, all');
      const failedOnlyRaw = String(req.query.failedOnly ?? 'false');
      if (!['true', 'false'].includes(failedOnlyRaw)) throw badRequest('failedOnly must be true or false');
      const q = String(req.query.q ?? '').trim();
      if (q.length > 200) throw badRequest('q must be at most 200 characters');

      const rows = await findRecords(pool, {
        days: days === 'all' ? null : Number(days),
        failedOnly: failedOnlyRaw === 'true',
        q,
        limit: config.maxRecords,
      });
      res.json({ count: rows.length, limit: config.maxRecords, records: rows });
    } catch (err) {
      next(err);
    }
  });

  // OpenAPI spec + Swagger UI (assets from a pinned CDN version).
  app.get('/openapi.yaml', (req, res) => res.type('application/yaml').send(fs.readFileSync(OPENAPI_PATH, 'utf8')));
  app.get('/docs', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'swagger.html')));

  // maxAge 0 + ETag: browsers revalidate, so a new release is picked up immediately.
  app.use(express.static(PUBLIC_DIR, { index: 'index.html', maxAge: 0 }));

  app.use('/api', (req, res) => sendError(res, 404, 'NOT_FOUND', 'Resource not found.'));

  // Central error handler: never leak internals.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') return sendError(res, 400, 'MALFORMED_REQUEST', 'Malformed JSON body.');
    if (err.code === 'VALIDATION_FAILED') return sendError(res, 400, err.code, err.message);
    if (err.status === 400) return sendError(res, 400, 'MALFORMED_REQUEST', 'Malformed request.');
    if (err.type === 'entity.too.large') return sendError(res, 413, 'PAYLOAD_TOO_LARGE', 'Request body is too large.');
    if (err.code && /^(08|57P)/.test(err.code)) {
      console.error(`[api] database unavailable: ${err.code}`);
      return sendError(res, 503, 'DATABASE_UNAVAILABLE', 'The database is not reachable.');
    }
    if (err.code === 'ECONNREFUSED' || /timeout/i.test(err.message || '')) {
      console.error(`[api] database unavailable: ${err.code || 'timeout'}`);
      return sendError(res, 503, 'DATABASE_UNAVAILABLE', 'The database is not reachable.');
    }
    console.error(`[api] unhandled error: ${err.code || ''} ${err.message}`);
    return sendError(res, 500, 'INTERNAL_ERROR', 'An internal error occurred.');
  });

  return app;
}

/** Turn any accepted request body into a flat list of normalised records. */
function collectRecords(body) {
  if (typeof body === 'string') return parseReportXml(body);
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw badRequest('Body must be XML or a JSON object with "xml" and/or "records"');
  }
  const out = [];
  if (body.xml !== undefined) {
    const docs = Array.isArray(body.xml) ? body.xml : [body.xml];
    if (docs.length > 1000) throw badRequest('At most 1000 XML documents per request');
    docs.forEach((doc, i) => {
      try {
        out.push(...parseReportXml(doc));
      } catch (err) {
        err.message = `xml[${i}]: ${err.message}`;
        throw err;
      }
    });
  }
  if (body.records !== undefined) {
    if (!Array.isArray(body.records)) throw badRequest('"records" must be an array');
    body.records.forEach((r, i) => {
      try {
        out.push(normalizeRecord(r));
      } catch (err) {
        err.message = `records[${i}]: ${err.message}`;
        throw err;
      }
    });
  }
  if (body.xml === undefined && body.records === undefined) {
    throw badRequest('Body must contain "xml" and/or "records"');
  }
  if (out.length > 100000) throw badRequest('At most 100000 records per request');
  return out;
}

module.exports = { createApp, collectRecords };
