'use strict';

/*
 * DMARC-analys frontend. No external dependencies:
 *  - .gz is unpacked with the native DecompressionStream('gzip')
 *  - .zip is read with a small central-directory parser + DecompressionStream('deflate-raw')
 * The unpacked XML documents are sent as { xml: [...] } to POST /api/reports;
 * all parsing/normalisation happens server-side (single source of truth).
 */

const state = { days: '30', failedOnly: false, q: '' };
const $ = (id) => document.getElementById(id);
const nf = new Intl.NumberFormat('sv-SE');
const MAX_BATCH_BYTES = 8 * 1024 * 1024; // keep requests below the server body limit

/* ---------- Archive handling ---------- */

/** Inflate bytes with a native DecompressionStream format. */
async function inflate(bytes, format) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Extract all entries from a ZIP archive using the central directory
 * (works even when local headers use data descriptors). Supports stored (0)
 * and deflate (8) entries. Returns [{ name, bytes }].
 */
async function unzip(buf) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  // Locate End Of Central Directory record (signature 0x06054b50), scanning backwards.
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('ogiltig ZIP-fil');
  const count = view.getUint16(eocd + 10, true);
  let p = view.getUint32(eocd + 16, true);
  const dec = new TextDecoder();
  const out = [];
  for (let n = 0; n < count; n++) {
    if (view.getUint32(p, true) !== 0x02014b50) throw new Error('trasig ZIP-katalog');
    const method = view.getUint16(p + 10, true);
    const compSize = view.getUint32(p + 20, true);
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    const localOff = view.getUint32(p + 42, true);
    const name = dec.decode(buf.subarray(p + 46, p + 46 + nameLen));
    p += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith('/')) continue; // directory
    // Local header: 30 bytes + name + extra, then data.
    const lName = view.getUint16(localOff + 26, true);
    const lExtra = view.getUint16(localOff + 28, true);
    const start = localOff + 30 + lName + lExtra;
    const data = buf.subarray(start, start + compSize);
    if (method === 0) out.push({ name, bytes: data });
    else if (method === 8) out.push({ name, bytes: await inflate(data, 'deflate-raw') });
    else throw new Error(`${name}: komprimeringsmetod ${method} stöds inte`);
  }
  return out;
}

const isGzip = (b) => b[0] === 0x1f && b[1] === 0x8b;
const isZip = (b) => b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04;

/** Recursively turn a file (xml / gz / zip, by magic bytes) into XML strings. */
async function extractXml(name, bytes, depth = 0) {
  if (depth > 3) throw new Error(`${name}: för djupt nästlat arkiv`);
  if (isZip(bytes)) {
    const entries = await unzip(bytes);
    const nested = await Promise.all(entries.map((e) => extractXml(`${name}/${e.name}`, e.bytes, depth + 1)));
    return nested.flat();
  }
  if (isGzip(bytes)) return extractXml(name.replace(/\.gz(ip)?$/i, ''), await inflate(bytes, 'gzip'), depth + 1);
  const text = new TextDecoder().decode(bytes).trim();
  if (!text.startsWith('<')) throw new Error(`${name}: inte XML`);
  return [text];
}

/* ---------- Upload ---------- */

function setStatus(msg, kind = '') {
  const el = $('status');
  el.textContent = msg;
  el.className = `status ${kind}`;
}

/** Split XML docs into batches below MAX_BATCH_BYTES and POST them. */
async function submitXml(docs) {
  const totals = { received: 0, inserted: 0, duplicates: 0, failedMails: 0, totalMails: 0, alerts: [] };
  let batch = [];
  let size = 0;
  const flush = async () => {
    if (!batch.length) return;
    const res = await fetch('/api/reports', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ xml: batch }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error ? body.error.message : `HTTP ${res.status}`);
    for (const k of ['received', 'inserted', 'duplicates', 'failedMails', 'totalMails']) totals[k] += body[k] || 0;
    totals.alerts.push(...(body.alerts || []));
    batch = [];
    size = 0;
  };
  for (const d of docs) {
    if (size + d.length > MAX_BATCH_BYTES) await flush();
    batch.push(d);
    size += d.length;
  }
  await flush();
  return totals;
}

function reportResult(t, fileErrors) {
  const pct = t.totalMails ? ((t.failedMails / t.totalMails) * 100).toFixed(1) : '0.0';
  const lines = [
    `${nf.format(t.inserted)} nya poster inlagda, ${nf.format(t.duplicates)} dubbletter ignorerades.`,
    `Underkända bland nya poster: ${pct} % (${nf.format(t.failedMails)} av ${nf.format(t.totalMails)} mejl).`,
  ];
  let kind = 'ok';
  if (t.alerts.length) {
    kind = 'warn';
    lines.push(...t.alerts.map((a) => `⚠ Larm – ${a.domain} (p=${a.policy}): ${a.failedPercent} % underkända`));
  }
  if (fileErrors.length) {
    kind = 'warn';
    lines.push(`Kunde inte läsa: ${fileErrors.join('; ')}`);
  }
  setStatus(lines.join('\n'), kind);
}

async function handleFiles(files) {
  if (!files.length) return;
  if (typeof DecompressionStream === 'undefined') {
    setStatus('Din webbläsare saknar stöd för DecompressionStream – uppdatera webbläsaren.', 'err');
    return;
  }
  setStatus(`Packar upp ${files.length} fil(er)…`);
  const docs = [];
  const errors = [];
  for (const f of files) {
    try {
      docs.push(...(await extractXml(f.name, new Uint8Array(await f.arrayBuffer()))));
    } catch (e) {
      errors.push(e.message);
    }
  }
  if (!docs.length) {
    setStatus(`Inga XML-rapporter hittades. ${errors.join('; ')}`, 'err');
    return;
  }
  await upload(docs, errors);
}

async function upload(docs, fileErrors = []) {
  setStatus(`Skickar ${docs.length} rapport(er)…`);
  try {
    reportResult(await submitXml(docs), fileErrors);
    await loadRecords();
  } catch (e) {
    setStatus(`Fel vid inläsning: ${e.message}`, 'err');
  }
}

/* ---------- History, KPIs, chart, table ---------- */

const isFailed = (r) => r.dkim_result !== 'pass' && r.spf_result !== 'pass';
const pct = (n, d) => (d ? `${((n / d) * 100).toFixed(1)} %` : '–');

let loadSeq = 0;
let lastRecords = []; // kept so the chart can be redrawn on resize
async function loadRecords() {
  const seq = ++loadSeq; // ignore out-of-order responses while typing
  const params = new URLSearchParams({ days: state.days, failedOnly: String(state.failedOnly) });
  if (state.q) params.set('q', state.q);
  try {
    const res = await fetch(`/api/records?${params}`);
    const body = await res.json();
    if (!res.ok) throw new Error(body.error ? body.error.message : `HTTP ${res.status}`);
    if (seq !== loadSeq) return;
    lastRecords = body.records;
    render(body.records, body.count >= body.limit ? body.limit : null);
  } catch (e) {
    if (seq === loadSeq) setStatus(`Kunde inte hämta historik: ${e.message}`, 'err');
  }
}

function render(records, truncatedAt) {
  let total = 0, dmarc = 0, dkim = 0, spf = 0;
  for (const r of records) {
    total += r.mail_count;
    if (!isFailed(r)) dmarc += r.mail_count;
    if (r.dkim_result === 'pass') dkim += r.mail_count;
    if (r.spf_result === 'pass') spf += r.mail_count;
  }
  $('kpi-total').textContent = nf.format(total);
  $('kpi-dmarc').textContent = pct(dmarc, total);
  $('kpi-dkim').textContent = pct(dkim, total);
  $('kpi-spf').textContent = pct(spf, total);
  $('row-count').textContent =
    `${nf.format(records.length)} poster` + (truncatedAt ? ` (begränsat till ${nf.format(truncatedAt)})` : '');
  renderChart(records);
  renderTable(records);
}

/** Stacked bar chart (pass / fail mail volume per day) drawn as inline SVG. */
function renderChart(records) {
  const el = $('chart');
  const byDay = new Map();
  for (const r of records) {
    const d = byDay.get(r.report_date) || { pass: 0, fail: 0 };
    if (isFailed(r)) d.fail += r.mail_count; else d.pass += r.mail_count;
    byDay.set(r.report_date, d);
  }
  const days = [...byDay.keys()].sort();
  if (!days.length) {
    el.innerHTML = '<div class="empty">Ingen data för valt filter</div>';
    return;
  }
  // Draw in real pixels (viewBox = container size) so text is never stretched.
  const W = Math.max(300, el.clientWidth || 1000), H = 260, padL = 50, padB = 28, padT = 10, padR = 10;
  const max = Math.max(...days.map((d) => byDay.get(d).pass + byDay.get(d).fail), 1);
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const step = plotW / days.length;
  const bw = Math.max(1, Math.min(40, step * 0.7));
  const y = (v) => (v / max) * plotH;
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Staplat stapeldiagram över mejlvolym per dag');
  const add = (tag, attrs, text) => {
    const n = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (text !== undefined) n.textContent = text;
    svg.appendChild(n);
    return n;
  };
  // Y-axis gridlines (0, 50 %, 100 % of max).
  for (const f of [0, 0.5, 1]) {
    const yy = padT + plotH - plotH * f;
    add('line', { x1: padL, x2: W - padR, y1: yy, y2: yy, class: 'axis' });
    add('text', { x: padL - 6, y: yy + 4, 'text-anchor': 'end' }, nf.format(Math.round(max * f)));
  }
  const labelEvery = Math.ceil(days.length / 10);
  days.forEach((d, i) => {
    const v = byDay.get(d);
    const x = padL + i * step + (step - bw) / 2;
    const hp = y(v.pass), hf = y(v.fail);
    const base = padT + plotH;
    const tip = `${d}: ${nf.format(v.pass)} godkända, ${nf.format(v.fail)} underkända`;
    add('rect', { x, y: base - hp, width: bw, height: hp, class: 'bar-pass' }).appendChild(titleNode(ns, tip));
    add('rect', { x, y: base - hp - hf, width: bw, height: hf, class: 'bar-fail' }).appendChild(titleNode(ns, tip));
    if (i % labelEvery === 0) add('text', { x: x + bw / 2, y: H - 8, 'text-anchor': 'middle' }, d.slice(5));
  });
  el.replaceChildren(svg);
}

function titleNode(ns, text) {
  const t = document.createElementNS(ns, 'title');
  t.textContent = text;
  return t;
}

/** Build table rows with textContent only (no innerHTML → no XSS from report data). */
function renderTable(records) {
  const tbody = $('rows');
  const frag = document.createDocumentFragment();
  const MAX_ROWS = 1000;
  for (const r of records.slice(0, MAX_ROWS)) {
    const tr = document.createElement('tr');
    if (isFailed(r)) tr.className = 'failed';
    const cells = [
      [r.report_date], [r.reporting_org], [r.domain], [r.policy], [r.source_ip, 'mono'],
      [nf.format(r.mail_count), 'num'], [r.disposition], [r.dkim_result, 'badge'], [r.spf_result, 'badge'],
      [r.header_from], [r.report_id, 'mono'],
    ];
    for (const [val, cls] of cells) {
      const td = document.createElement('td');
      if (cls === 'badge') {
        const b = document.createElement('span');
        b.className = `badge ${val === 'pass' ? 'pass' : 'fail'}`;
        b.textContent = val || '–';
        td.appendChild(b);
      } else {
        if (cls) td.className = cls;
        td.textContent = val;
      }
      tr.appendChild(td);
    }
    frag.appendChild(tr);
  }
  tbody.replaceChildren(frag);
}

/* ---------- Wiring ---------- */

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

document.addEventListener('DOMContentLoaded', () => {
  const dz = $('dropzone');
  const input = $('file-input');
  dz.addEventListener('click', (e) => { if (e.target.tagName !== 'LABEL') input.click(); });
  dz.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('over'); }));
  dz.addEventListener('drop', (e) => handleFiles([...e.dataTransfer.files]));
  input.addEventListener('change', () => { handleFiles([...input.files]); input.value = ''; });

  $('paste-submit').addEventListener('click', async () => {
    const text = $('xml-text').value.trim();
    if (!text) return setStatus('Klistra in XML först.', 'err');
    const btn = $('paste-submit');
    btn.disabled = true;
    await upload([text]);
    btn.disabled = false;
  });

  document.querySelectorAll('.segmented button').forEach((b) =>
    b.addEventListener('click', () => {
      document.querySelectorAll('.segmented button').forEach((x) => x.classList.toggle('active', x === b));
      state.days = b.dataset.days;
      loadRecords();
    }),
  );
  $('failed-only').addEventListener('change', (e) => { state.failedOnly = e.target.checked; loadRecords(); });
  $('search').addEventListener('input', debounce((e) => { state.q = e.target.value.trim(); loadRecords(); }, 250));

  window.addEventListener('resize', debounce(() => renderChart(lastRecords), 150));

  fetch('/api/version').then((r) => r.json()).then((v) => { $('version').textContent = `v${v.version}`; }).catch(() => {});
  loadRecords();
});
