'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { parseReportXml, normalizeRecord, recordHash } = require('../src/parser');
const { failureStats, buildAlerts } = require('../src/alerts');
const { collectRecords } = require('../src/app');

const SAMPLE = fs.readFileSync(path.join(__dirname, '..', 'examples', 'sample-report.xml'), 'utf8');

test('parses a DMARC aggregate report', () => {
  const recs = parseReportXml(SAMPLE);
  assert.equal(recs.length, 2);
  assert.deepEqual(
    { ...recs[1], record_hash: undefined },
    {
      report_date: '2026-11-20', report_id: '12345678901234567890', reporting_org: 'google.com',
      domain: 'example.com', policy: 'reject', source_ip: '198.51.100.66', mail_count: 30,
      disposition: 'reject', dkim_result: 'fail', spf_result: 'fail', header_from: 'example.com',
      record_hash: undefined,
    },
  );
});

test('record_hash is deterministic and field-sensitive', () => {
  const [a] = parseReportXml(SAMPLE);
  const [b] = parseReportXml(SAMPLE);
  assert.equal(a.record_hash, b.record_hash);
  assert.match(a.record_hash, /^[0-9a-f]{64}$/);
  assert.notEqual(recordHash({ ...a, mail_count: a.mail_count + 1 }), a.record_hash);
  // Separator-collision guard: shifting characters between fields changes the hash.
  assert.notEqual(recordHash({ ...a, report_id: 'a|b', reporting_org: '' }), recordHash({ ...a, report_id: 'a', reporting_org: 'b' }));
});

test('JSON records and XML produce the same hash', () => {
  const [x] = parseReportXml(SAMPLE);
  const j = normalizeRecord({ ...x, record_hash: 'ignored', domain: 'EXAMPLE.com' });
  assert.equal(j.record_hash, x.record_hash);
});

test('rejects invalid input', () => {
  assert.throws(() => parseReportXml('<nope/>'), /missing <feedback>/);
  assert.throws(() => parseReportXml(''), /empty/);
  assert.throws(() => normalizeRecord({ report_date: '2026-13-40' }), /report_date/);
  assert.throws(() => normalizeRecord({ report_date: '2026-01-01', mail_count: -1 }), /mail_count/);
  assert.throws(() => collectRecords({}), /xml/);
  assert.throws(() => collectRecords({ records: 'x' }), /array/);
});

test('falls back to auth_results when policy_evaluated is missing', () => {
  const xml = SAMPLE.replace(/<policy_evaluated>[\s\S]*?<\/policy_evaluated>/g, '');
  const recs = parseReportXml(xml);
  assert.equal(recs[1].dkim_result, 'fail');
  assert.equal(recs[1].spf_result, 'softfail');
});

test('failure stats and alerts are mail-weighted per domain/policy', () => {
  const recs = parseReportXml(SAMPLE); // 120 pass, 30 fail => 20 %
  assert.deepEqual(failureStats(recs), { totalMails: 150, failedMails: 30, failedRate: 0.2 });
  const alerts = buildAlerts(recs, 0.1);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].domain, 'example.com');
  assert.equal(alerts[0].policy, 'reject');
  assert.deepEqual(alerts[0].reportIds, ['12345678901234567890']);
  assert.deepEqual(alerts[0].topIps, [{ ip: '198.51.100.66', failedMails: 30 }]);
  assert.equal(buildAlerts(recs, 0.25).length, 0);
  // Trigger is the OVERALL rate: a failing group diluted by passing mail elsewhere does not alert.
  const diluted = [...recs, { ...recs[0], domain: 'other.example', mail_count: 1000 }];
  assert.equal(buildAlerts(diluted, 0.1).length, 0);
  // When triggered, only groups that contain failed mail are listed.
  const mixed = [...recs, { ...recs[0], domain: 'clean.example', mail_count: 10 }];
  assert.deepEqual(buildAlerts(mixed, 0.1).map((a) => a.domain), ['example.com']);
  // Pass on either DKIM or SPF counts as passed.
  assert.equal(failureStats([{ ...recs[1], spf_result: 'pass' }]).failedMails, 0);
});
