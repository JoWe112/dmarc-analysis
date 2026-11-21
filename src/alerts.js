'use strict';

const { isFailed } = require('./parser');

/**
 * Compute failure statistics for a set of records. The rate is mail-weighted:
 * failed mail_count / total mail_count. A record fails when neither DKIM nor
 * SPF is "pass".
 */
function failureStats(records) {
  let total = 0;
  let failed = 0;
  for (const r of records) {
    total += r.mail_count;
    if (isFailed(r)) failed += r.mail_count;
  }
  return { totalMails: total, failedMails: failed, failedRate: total > 0 ? failed / total : 0 };
}

/**
 * Alerting rule: if the failed share of ALL newly inserted mail exceeds the
 * threshold, return one entry per (domain, policy) group that contains failed
 * mail – each with its report IDs, its own failure rate and top failing IPs.
 * Returns [] when the overall rate is at or below the threshold.
 */
function buildAlerts(records, threshold, topN = 5) {
  if (failureStats(records).failedRate <= threshold) return [];
  const groups = new Map();
  for (const r of records) {
    const key = `${r.domain}\u0000${r.policy}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }

  const alerts = [];
  for (const recs of groups.values()) {
    const stats = failureStats(recs);
    if (stats.failedMails === 0) continue; // nothing to report for a fully passing group

    const ipCounts = new Map();
    for (const r of recs) {
      if (!isFailed(r)) continue;
      ipCounts.set(r.source_ip, (ipCounts.get(r.source_ip) || 0) + r.mail_count);
    }
    const topIps = [...ipCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, topN)
      .map(([ip, count]) => ({ ip, failedMails: count }));

    // Group-level rate for context; the trigger itself is the overall rate.
    alerts.push({
      domain: recs[0].domain,
      policy: recs[0].policy,
      reportIds: [...new Set(recs.map((r) => r.report_id))].sort(),
      failedRate: Number(stats.failedRate.toFixed(4)),
      failedPercent: Number((stats.failedRate * 100).toFixed(2)),
      totalMails: stats.totalMails,
      failedMails: stats.failedMails,
      threshold,
      topIps,
    });
  }
  return alerts;
}

/**
 * POST alerts to the webhook. Never throws: returns a status object so the
 * ingest request succeeds even if the webhook is down. The payload includes a
 * Slack/Teams-friendly `text` field alongside structured data.
 */
async function sendAlerts(url, alerts, timeoutMs, summary) {
  if (!url || alerts.length === 0) return { sent: false, count: alerts.length };
  const text = [
    `DMARC-larm: ${summary.failedPercent} % underkända mejl bland nyinlagda poster ` +
      `(${summary.failedMails} av ${summary.totalMails}, tröskel ${summary.threshold * 100} %).`,
    ...alerts.map(
      (a) =>
        `• ${a.domain} (p=${a.policy}): ${a.failedPercent} %, rapporter ${a.reportIds.join(', ')}. ` +
        `Topp-IP: ${a.topIps.map((t) => `${t.ip} (${t.failedMails})`).join(', ')}`,
    ),
  ].join('\n');
  const payload = { text, source: 'dmarc-analysis', generatedAt: new Date().toISOString(), summary, alerts };
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) {
      console.warn(`[alert] webhook responded with HTTP ${res.status}`);
      return { sent: false, count: alerts.length, error: `HTTP ${res.status}` };
    }
    return { sent: true, count: alerts.length };
  } catch (err) {
    console.warn(`[alert] webhook delivery failed: ${err.name}`);
    return { sent: false, count: alerts.length, error: 'delivery failed' };
  }
}

module.exports = { failureStats, buildAlerts, sendAlerts };
