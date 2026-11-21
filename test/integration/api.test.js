'use strict';

/**
 * Integration tests against a real PostgreSQL. Requires TEST_DATABASE_URL, e.g.
 *   docker compose up -d postgres
 *   TEST_DATABASE_URL=postgres://dmarc:dmarc-local-only@localhost:5432/dmarc npm run test:integration
 * Uses a dedicated schema so it never touches real data.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');
const { migrate } = require('../../src/db');
const { startHarness } = require('../helpers/app-harness');

const url = process.env.TEST_DATABASE_URL;
const SAMPLE = fs.readFileSync(path.join(__dirname, '..', '..', 'examples', 'sample-report.xml'), 'utf8');
const SCHEMA = `it_${process.pid}`;

test('API against PostgreSQL', { skip: !url && 'TEST_DATABASE_URL not set' }, async (t) => {
  const pool = new Pool({ connectionString: url, options: `-c search_path=${SCHEMA}` });
  await pool.query(`CREATE SCHEMA IF NOT EXISTS ${SCHEMA}`);
  await migrate(pool);
  await migrate(pool); // idempotent

  // Capture webhook calls with a local HTTP server.
  const hooks = [];
  const hook = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => { hooks.push(JSON.parse(b)); res.end('ok'); });
  });
  await new Promise((r) => hook.listen(0, '127.0.0.1', r));

  // Real app + real PostgreSQL + mock OIDC provider; API calls use a bearer token.
  const h = await startHarness({
    pool,
    config: { alertWebhookUrl: `http://127.0.0.1:${hook.address().port}/`, maxRecords: 100 },
  });
  const base = h.base;
  const token = await h.idp.issueAccessToken();
  const authz = { authorization: `Bearer ${token}` };
  const post = (body, type = 'application/json') =>
    fetch(`${base}/api/reports`, { method: 'POST', headers: { 'content-type': type, ...authz }, body });
  const get = async (qs) => (await (await fetch(`${base}/api/records?${qs}`, { headers: authz })).json());

  t.after(async () => {
    await h.close();
    hook.close();
    await pool.query(`DROP SCHEMA ${SCHEMA} CASCADE`);
    await pool.end();
  });

  await t.test('healthz', async () => {
    const res = await fetch(`${base}/healthz`);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).database, 'up');
  });

  await t.test('first ingest inserts and alerts', async () => {
    const res = await post(SAMPLE, 'application/xml');
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.inserted, 2);
    assert.equal(body.duplicates, 0);
    assert.equal(body.failedPercent, 20);
    assert.equal(body.alertTriggered, true);
    assert.equal(body.alertSent, true);
    assert.equal(hooks.length, 1);
    assert.equal(hooks[0].alerts[0].domain, 'example.com');
    assert.equal(hooks[0].alerts[0].topIps[0].ip, '198.51.100.66');
    assert.equal(hooks[0].summary.failedPercent, 20);
    assert.match(hooks[0].text, /DMARC-larm/);
  });

  await t.test('re-ingest is fully deduplicated and does not alert', async () => {
    const res = await post(JSON.stringify({ xml: [SAMPLE, SAMPLE] }));
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.received, 4);
    assert.equal(body.inserted, 0);
    assert.equal(body.duplicates, 4);
    assert.equal(body.alertTriggered, false);
    assert.equal(hooks.length, 1);
  });

  await t.test('parallel ingest never creates duplicates', async () => {
    const xml = SAMPLE.replace(/12345678901234567890/g, 'parallel-1');
    const results = await Promise.all(Array.from({ length: 8 }, () => post(xml, 'application/xml').then((r) => r.json())));
    assert.equal(results.reduce((s, r) => s + r.inserted, 0), 2);
    const { rows } = await pool.query(`SELECT count(*)::int AS n FROM dmarc_records WHERE report_id = 'parallel-1'`);
    assert.equal(rows[0].n, 2);
  });

  await t.test('records filters', async () => {
    assert.equal((await get('days=all')).count, 4);
    assert.equal((await get('days=all&failedOnly=true')).count, 2);
    assert.equal((await get('days=all&q=198.51.100')).count, 2);
    assert.equal((await get('days=all&q=parallel')).count, 2);
    assert.equal((await get('days=all&q=%25')).count, 0); // LIKE wildcard is literal
    const old = await post(JSON.stringify({ records: [{ report_date: '2000-01-01', domain: 'old.example', mail_count: 1 }] }));
    assert.equal(old.status, 201);
    assert.equal((await get('days=7&q=old.example')).count, 0);
    assert.equal((await get('days=all&q=old.example')).count, 1);
  });

  await t.test('validation errors use the error envelope', async () => {
    let res = await fetch(`${base}/api/records?days=5`, { headers: authz });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error.code, 'VALIDATION_FAILED');
    res = await post('{not json');
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error.code, 'MALFORMED_REQUEST');
    res = await post('<nope/>', 'application/xml');
    assert.equal(res.status, 400);
    res = await fetch(`${base}/api/unknown`, { headers: authz });
    assert.equal(res.status, 404);
  });
});
