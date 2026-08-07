/**
 * myssl client.
 *
 * A scan takes seconds rather than milliseconds, so the page opens a
 * server-sent event stream and fills the progress bar as the stages go by,
 * then renders the report when it arrives. Switching the language repaints
 * everything from the report already in memory — no rescan.
 */
'use strict';

const byId = id => document.getElementById(id);
const DASH = '—';

/* ================================================================== *
 * Language
 * ================================================================== */

const I18N = window.I18N;
const SUPPORTED = Object.keys(I18N);
const RTL = new Set(window.RTL_LANGS || []);
const STORAGE_KEY = 'myssl-lang';

function detectLang() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && I18N[saved]) return saved;
  } catch { /* localStorage may be unavailable */ }

  const candidates = navigator.languages?.length ? navigator.languages : [navigator.language || 'en'];
  for (const raw of candidates) {
    const tag = String(raw).toLowerCase();
    if (I18N[tag]) return tag;
    const base = tag.split('-')[0];
    if (I18N[base]) return base;
  }
  return 'en';
}

let LANG = detectLang();
const locale = () => (window.LANG_LOCALES?.[LANG]) || LANG;

function t(key, vars) {
  const dict = I18N[LANG] || I18N.en;
  let s = dict[key] ?? I18N.en[key] ?? key;
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.split('{' + k + '}').join(v);
  return s;
}

/** Translation for a dashed code such as "no-forward-secrecy", or the code itself. */
function tCode(prefix, code) {
  if (!code) return undefined;
  const key = prefix + '_' + String(code).replace(/[-.]/g, '_');
  const dict = I18N[LANG] || I18N.en;
  return dict[key] ?? I18N.en[key] ?? String(code).replace(/-/g, ' ');
}

/* ================================================================== *
 * Rendering helpers
 * ================================================================== */

function set(id, value, state) {
  const n = byId(id);
  if (!n) return;
  const empty = value === undefined || value === null || value === '' ||
                (Array.isArray(value) && !value.length) ||
                (typeof value === 'number' && Number.isNaN(value));
  n.className = 'v' + (empty ? ' muted' : state ? ' ' + state : '');
  n.textContent = empty ? DASH : (Array.isArray(value) ? value.join(', ') : String(value));
}

function setHTML(id, html, state) {
  const n = byId(id);
  if (!n) return;
  n.className = 'v' + (state ? ' ' + state : '');
  n.innerHTML = html;
}

/** Escapes values that end up inside generated HTML. */
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Yes/no with the colour that matches which answer is the good one. */
function flag(id, value, { goodIfTrue = true, unknown } = {}) {
  if (value === undefined || value === null) { set(id, unknown ?? t('v_unknown'), 'muted'); return; }
  const good = value === goodIfTrue;
  set(id, value ? t('v_yes') : t('v_no'), good ? 'ok' : 'warn');
}

function skeletons() {
  document.querySelectorAll('#report .v').forEach(n => {
    n.className = 'v skeleton';
    n.textContent = '';
  });
  ['grade-caps', 'grade-warnings', 'chain-issues', 'chain-list', 'protocol-rows',
    'vuln-list', 'cipher-blocks', 'sim-body', 'h-headers', 'h-cookies'].forEach(id => {
    const node = byId(id);
    if (node) node.innerHTML = '';
  });
  ['bar-protocol', 'bar-kex', 'bar-cipher'].forEach(id => {
    const node = byId(id);
    if (node) node.style.width = '0';
  });
}

function toast(msg) {
  const el = byId('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => el.classList.remove('show'), 1900);
}

async function copyText(text, okMsg) {
  try {
    await navigator.clipboard.writeText(text);
    toast(okMsg || t('toast_copied'));
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); toast(okMsg || t('toast_copied')); }
    catch { toast(t('toast_copy_fail')); }
    ta.remove();
  }
}

function formatDate(iso) {
  if (!iso) return undefined;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  try { return new Intl.DateTimeFormat(locale(), { dateStyle: 'medium' }).format(d); }
  catch { return iso; }
}

function tag(text, kind) {
  const el = document.createElement('span');
  el.className = 'tag' + (kind ? ' ' + kind : '');
  el.textContent = text;
  return el;
}

/* ================================================================== *
 * State
 * ================================================================== */

/** The report currently displayed. */
let REPORT = null;
/** Error from the last scan, if any. */
let LAST_ERROR = null;
/** Host currently displayed (null on the empty start page). */
let TARGET = null;
/** The open event stream, so a new scan can replace a running one. */
let STREAM = null;

const STAGES = ['resolve', 'handshake', 'protocols', 'ciphers', 'keyexchange',
  'certificate', 'features', 'http', 'clients', 'grade'];

/* ================================================================== *
 * Running a scan
 * ================================================================== */

function setProgress(stage, extra) {
  const box = byId('progress');
  box.hidden = false;
  const index = Math.max(0, STAGES.indexOf(stage));
  const percent = Math.round(((index + 1) / STAGES.length) * 100);
  byId('progress-fill').style.width = percent + '%';
  const detail = extra?.version ? ` · ${extra.version}` : '';
  byId('progress-label').textContent = `${tCode('stage', stage)}${detail}`;
}

function scanning(on) {
  byId('btn-scan').disabled = on;
  byId('btn-rescan').disabled = on;
  if (!on) byId('progress').hidden = true;
}

function startScan(host, { refresh = false } = {}) {
  if (!host) return;
  TARGET = host;
  REPORT = null;
  LAST_ERROR = null;

  if (STREAM) { STREAM.close(); STREAM = null; }

  byId('empty').hidden = true;
  byId('report').hidden = false;
  byId('alerts').innerHTML = '';
  byId('search-host').value = host;
  byId('hero-host').textContent = host;
  byId('hero-meta').innerHTML = '';
  byId('grade-badge').className = 'grade-badge pending';
  byId('grade-badge').textContent = '·';
  skeletons();
  scanning(true);
  setProgress('resolve');
  updateSeoMeta();

  // The language is passed along so the report carries readable labels beside
  // its codes — which is what the raw-report card and a downloaded JSON show.
  const url = `/api/stream/${encodeURIComponent(host)}?lang=${encodeURIComponent(LANG)}${
    refresh ? '&refresh=1' : ''}`;
  const stream = new EventSource(url);
  STREAM = stream;

  stream.addEventListener('progress', event => {
    try { const data = JSON.parse(event.data); setProgress(data.stage, data); }
    catch { /* a malformed frame is not worth breaking the scan over */ }
  });

  stream.addEventListener('report', event => {
    try { REPORT = JSON.parse(event.data); }
    catch { LAST_ERROR = { error: 'bad-response' }; }
    stream.close();
    STREAM = null;
    scanning(false);
    render();
  });

  stream.addEventListener('failed', event => {
    try { LAST_ERROR = JSON.parse(event.data); }
    catch { LAST_ERROR = { error: 'scan-failed' }; }
    stream.close();
    STREAM = null;
    scanning(false);
    render();
  });

  stream.onerror = () => {
    if (REPORT || LAST_ERROR) return;
    stream.close();
    STREAM = null;
    scanning(false);
    LAST_ERROR = { error: 'network' };
    render();
  };
}

/* ================================================================== *
 * Rendering
 * ================================================================== */

function render() {
  renderAlerts();
  // Without a report there is nothing to fill the cards with, so the grid stays
  // hidden — including after a language switch on the start page, which is what
  // used to leave a screen of empty cards above the hint.
  if (!REPORT) {
    byId('report').hidden = true;
    byId('empty').hidden = Boolean(TARGET);
    if (LAST_ERROR) {
      byId('grade-badge').className = 'grade-badge g-f';
      byId('grade-badge').textContent = '!';
    }
    return;
  }
  byId('report').hidden = false;
  byId('empty').hidden = true;
  renderHero();
  renderGrade();
  renderCertificate();
  renderChain();
  renderProtocols();
  renderKeyExchange();
  renderFeatures();
  renderHttp();
  renderDns();
  renderVulnerabilities();
  renderCiphers();
  renderSimulation();
  renderRaw();
}

function renderAlerts() {
  const box = byId('alerts');
  box.innerHTML = '';
  const add = (kind, html) => {
    const div = document.createElement('div');
    div.className = 'alert ' + kind;
    div.innerHTML = html;
    box.appendChild(div);
  };

  if (LAST_ERROR) {
    const code = LAST_ERROR.error || 'scan-failed';
    add('bad', `<span aria-hidden="true">✕</span><div><b>${esc(tCode('err', code))}</b>${
      LAST_ERROR.detail ? `<br><code>${esc(LAST_ERROR.detail)}</code>` : ''}</div>`);
    return;
  }
  if (!REPORT) return;

  const cert = REPORT.certificate || {};
  const issues = new Set(cert.issues || []);
  if (issues.has('hostname-mismatch')) {
    add('bad', `<span aria-hidden="true">🚫</span><div>${t('a_name_mismatch', {
      host: esc(REPORT.host), names: esc((cert.leaf?.altNames?.dns || []).slice(0, 5).join(', ')),
    })}</div>`);
  }
  if (issues.has('expired')) {
    add('bad', `<span aria-hidden="true">⌛</span><div>${t('a_expired', {
      date: esc(formatDate(cert.leaf?.notAfter)),
    })}</div>`);
  } else if ((cert.leaf?.daysRemaining ?? 999) < 21) {
    add('warn', `<span aria-hidden="true">⌛</span><div>${t('a_expiring', {
      days: cert.leaf?.daysRemaining,
    })}</div>`);
  }
  if (issues.has('self-signed')) add('bad', `<span aria-hidden="true">✍️</span><div>${t('a_self_signed')}</div>`);
  if (issues.has('incomplete-chain')) add('bad', `<span aria-hidden="true">🔗</span><div>${t('a_incomplete')}</div>`);

  const critical = (REPORT.vulnerabilities || []).filter(
    v => v.status === 'vulnerable' && (v.severity === 'critical' || v.severity === 'high') &&
      !v.id.startsWith('certificate-'));
  for (const finding of critical) {
    add('bad', `<span aria-hidden="true">☢️</span><div><b>${esc(tCode('vuln', finding.id))}</b>${
      finding.cve ? ` <code>${esc(finding.cve)}</code>` : ''}<br>${esc(tCode('vd', finding.id))}</div>`);
  }

  if (!critical.length && !issues.size && REPORT.grade?.grade?.startsWith('A')) {
    add('ok', `<span aria-hidden="true">✓</span><div>${t('a_all_good')}</div>`);
  }
}

function renderHero() {
  const grade = REPORT.grade?.grade || '?';
  const badge = byId('grade-badge');
  badge.textContent = grade;
  badge.className = 'grade-badge g-' + grade[0].toLowerCase();

  byId('hero-host').textContent = `${REPORT.host}${REPORT.port === 443 ? '' : ':' + REPORT.port}`;

  const meta = byId('hero-meta');
  meta.innerHTML = '';
  const chip = (text, kind) => {
    if (!text) return;
    const el = document.createElement('span');
    el.className = 'chip' + (kind ? ' ' + kind : '');
    el.textContent = text;
    meta.appendChild(el);
  };

  chip(REPORT.ip);
  const best = REPORT.grade?.components?.protocol?.best;
  chip(best, best === 'TLS 1.3' ? 'ok' : 'warn');
  chip(REPORT.negotiated?.cipher);
  const days = REPORT.certificate?.leaf?.daysRemaining;
  if (days !== undefined) {
    chip(days < 0 ? t('chip_expired', { days: -days }) : t('chip_expires', { days }),
      days < 0 ? 'bad' : days < 21 ? 'warn' : 'ok');
  }
  chip(REPORT.http?.hsts?.present ? 'HSTS' : null, REPORT.http.hsts.longEnough ? 'ok' : 'warn');
  chip(REPORT.features?.http2 ? 'HTTP/2' : null, 'ok');
  chip(t('chip_time', { ms: REPORT.meta?.elapsedMs }) + (REPORT.meta?.cached ? ' · ' + t('cached') : ''));
}

function renderGrade() {
  const g = REPORT.grade;
  const c = g.components;
  const meter = (barId, valueId, score) => {
    byId(barId).style.width = Math.max(0, Math.min(100, score)) + '%';
    set(valueId, score, score >= 80 ? 'ok' : score >= 50 ? 'warn' : 'bad');
  };
  meter('bar-protocol', 'score-protocol', c.protocol.score);
  meter('bar-kex', 'score-kex', c.keyExchange.score);
  meter('bar-cipher', 'score-cipher', c.cipher.score);

  set('score-total', `${g.score} / 100`);
  set('grade-best', c.protocol.best ? `${c.protocol.best} … ${c.protocol.worst}` : null);
  const weakest = c.keyExchange.weakest;
  set('grade-weakest', weakest
    ? `${tCode('kx', weakest.what.toLowerCase().replace(/ /g, '-'))} · ${weakest.bits} ${t('unit_bit')}`
    : null);

  const caps = byId('grade-caps');
  caps.innerHTML = '';
  for (const cap of g.caps || []) {
    caps.appendChild(tag(`${cap.grade} · ${tCode('cap', cap.reason)}`, 'bad'));
  }
  if (g.reason) caps.appendChild(tag(tCode('cap', g.reason), 'bad'));

  const warnings = byId('grade-warnings');
  warnings.innerHTML = '';
  for (const warning of g.warnings || []) warnings.appendChild(tag(tCode('warn', warning), 'warn'));
  if (!g.caps?.length && !g.warnings?.length && !g.reason) {
    warnings.appendChild(tag(t('no_deductions'), 'ok'));
  }
}

function renderCertificate() {
  const leaf = REPORT.certificate?.leaf;
  if (!leaf) return;

  set('cert-cn', leaf.commonName || leaf.subject);
  set('cert-issuer', [leaf.issuerCommonName, leaf.issuerOrganization].filter(Boolean).join(' · '));
  set('cert-from', formatDate(leaf.notBefore));
  set('cert-to', `${formatDate(leaf.notAfter)} · ${t('days_left', { days: leaf.daysRemaining })}`,
    leaf.daysRemaining < 0 ? 'bad' : leaf.daysRemaining < 21 ? 'warn' : 'ok');
  set('cert-key', `${leaf.keyType} ${leaf.keyBits || ''} · ${leaf.keyStrength} ${t('unit_bit')}`,
    leaf.keyVerdict === 'strong' ? 'ok' : leaf.keyVerdict === 'acceptable' ? undefined : 'bad');
  set('cert-sig', leaf.signatureAlgorithm, leaf.weakSignature ? 'bad' : 'ok');
  set('cert-validation', leaf.validation ? tCode('val', leaf.validation) : null);
  set('cert-sct', leaf.sctCount ? t('sct_count', { n: leaf.sctCount }) : t('v_no'),
    leaf.sctCount ? 'ok' : 'warn');
  flag('cert-muststaple', leaf.mustStaple, { goodIfTrue: true, unknown: t('v_no') });
  set('cert-serial', leaf.serialNumber);
  set('cert-fp', leaf.fingerprints?.sha256?.slice(0, 32) + '…');
  set('cert-names', (leaf.altNames?.dns || []).slice(0, 12).join(', ') +
    ((leaf.altNames?.dns || []).length > 12 ? ` … +${leaf.altNames.dns.length - 12}` : ''));
}

function renderChain() {
  const chain = REPORT.certificate;
  if (!chain) return;

  set('chain-trusted', chain.trusted ? t('v_yes') : `${t('v_no')}${chain.trustError ? ' · ' + chain.trustError : ''}`,
    chain.trusted ? (chain.browserTrusted ? 'ok' : 'warn') : 'bad');
  set('chain-complete', chain.complete ? t('v_yes') : t('v_no'), chain.complete ? 'ok' : 'bad');
  set('chain-anchor', chain.trustAnchor?.replace(/^CN=/, ''));
  set('chain-store', chain.trustStore ? tCode('store', chain.trustStore) : null,
    chain.browserTrusted ? 'ok' : chain.trustStore ? 'warn' : undefined);
  set('chain-host', chain.hostMatch || t('v_no'), chain.hostMatch ? 'ok' : 'bad');

  const stapling = REPORT.features?.ocspStapling;
  set('chain-ocsp', stapling ? t('v_yes') : t('v_no'), stapling ? 'ok' : 'warn');
  const ocsp = chain.ocsp;
  set('chain-revocation', ocsp
    ? `${tCode('ocsp', ocsp.certStatus || ocsp.responseStatus)}${ocsp.nextUpdate ? ' · ' + formatDate(ocsp.nextUpdate) : ''}`
    : t('ocsp_not_checked'),
  ocsp?.certStatus === 'good' ? 'ok' : ocsp?.certStatus === 'revoked' ? 'bad' : 'muted');

  const list = byId('chain-list');
  list.innerHTML = '';
  for (const cert of chain.chain || []) {
    const li = document.createElement('li');
    const name = esc(cert.commonName || cert.subject || '?');
    const meta = [
      cert.keyType && `${cert.keyType} ${cert.keyBits || ''}`.trim(),
      cert.signatureAlgorithm,
      cert.notAfter && `${t('until')} ${formatDate(cert.notAfter)}`,
      cert.selfSigned ? t('self_signed_short') : null,
    ].filter(Boolean).join(' · ');
    li.innerHTML = `<div class="cn">${name}</div><div class="meta">${esc(meta)}</div>`;
    list.appendChild(li);
  }

  const issues = byId('chain-issues');
  issues.innerHTML = '';
  for (const issue of chain.issues || []) issues.appendChild(tag(tCode('issue', issue), 'bad'));
  if (!chain.issues?.length) issues.appendChild(tag(t('no_issues'), 'ok'));
}

function renderProtocols() {
  const box = byId('protocol-rows');
  box.innerHTML = '';

  const rows = [
    { name: 'SSL 2.0', supported: Boolean(REPORT.ssl2?.supported), bad: true },
    ...(REPORT.protocols || []).map(p => ({
      name: p.name,
      supported: p.supported,
      bad: p.name === 'SSL 3.0',
      old: p.name === 'TLS 1.0' || p.name === 'TLS 1.1',
    })),
  ];

  for (const row of rows) {
    const div = document.createElement('div');
    div.className = 'row';
    const state = !row.supported ? (row.bad || row.old ? 'ok' : 'muted')
      : row.bad ? 'bad' : row.old ? 'warn' : 'ok';
    div.innerHTML = `<span class="k">${esc(row.name)}</span>` +
      `<span class="v ${state}">${esc(row.supported ? t('v_supported') : t('v_not_supported'))}</span>`;
    box.appendChild(div);
  }

  const n = REPORT.negotiated || {};
  set('proto-negotiated', [n.protocol, n.cipher].filter(Boolean).join(' · '));
}

function renderKeyExchange() {
  const kex = REPORT.keyExchange || {};
  const groups = kex.groups || [];
  set('kex-groups', groups.length ? groups.map(g => g.name).join(', ') : null,
    groups.length ? 'ok' : undefined);
  set('kex-ephemeral', kex.ephemeralKey
    ? `${kex.ephemeralKey.type} ${kex.ephemeralKey.name || ''} ${kex.ephemeralKey.size} ${t('unit_bit')}`.replace(/\s+/g, ' ')
    : null);
  set('kex-dh', kex.dh ? `${kex.dh.bits} ${t('unit_bit')}` : t('dh_not_offered'),
    !kex.dh ? 'muted' : kex.dh.bits >= 2048 ? 'ok' : 'bad');

  const suites = Object.values(REPORT.ciphers || {}).flatMap(block => block.suites || []);
  const withPfs = suites.filter(s => s.pfs).length;
  set('kex-pfs', suites.length ? t('pfs_ratio', { n: withPfs, total: suites.length }) : null,
    !suites.length ? undefined : withPfs === suites.length ? 'ok' : withPfs ? 'warn' : 'bad');
}

function renderFeatures() {
  const f = REPORT.features || {};
  set('f-alpn', f.alpn);
  flag('f-http2', f.http2);
  flag('f-ocsp', f.ocspStapling);
  const resumption = f.sessionResumption;
  set('f-resumption', resumption?.supported === null ? t('v_unknown')
    : resumption?.supported ? t('v_yes') : t('v_no'),
  resumption?.supported ? 'ok' : 'muted');
  flag('f-tickets', f.sessionTickets);
  flag('f-ems', f.extendedMasterSecret);
  flag('f-etm', f.encryptThenMac);
  flag('f-reneg', f.secureRenegotiation);
  flag('f-client-reneg', f.clientRenegotiation?.supported, { goodIfTrue: false });
  flag('f-compression', f.compression?.supported, { goodIfTrue: false });
  flag('f-fallback', f.fallbackScsv?.supported);
  flag('f-sni', f.sniRequired, { goodIfTrue: true });
  flag('f-clientcert', f.clientCertRequested, { goodIfTrue: false });
}

function renderHttp() {
  const http = REPORT.http || {};
  if (!http.reachable) {
    set('h-status', tCode('err', http.error || 'unreachable'), 'warn');
    return;
  }
  set('h-status', `${http.status}${http.finalStatus !== http.status ? ' → ' + http.finalStatus : ''}`,
    http.finalStatus < 400 ? 'ok' : 'warn');

  const plain = http.plainHttp;
  set('h-redirect', plain?.toHttps ? (plain.direct ? t('redirect_direct') : t('redirect_indirect'))
    : plain?.error ? t('v_unknown') : t('redirect_none'),
  plain?.toHttps ? (plain.direct ? 'ok' : 'warn') : 'warn');

  const hsts = http.hsts || {};
  set('h-hsts', hsts.present ? t('hsts_days', { days: hsts.days }) : t('v_no'),
    hsts.present ? (hsts.longEnough ? 'ok' : 'warn') : 'warn');
  flag('h-hsts-sub', hsts.present ? hsts.includeSubDomains : null);
  flag('h-hsts-preload', hsts.present ? hsts.preload : null);
  flag('h-http3', http.http3);
  set('h-server', http.server);

  const headers = byId('h-headers');
  headers.innerHTML = '';
  const entries = Object.entries(http.headers || {}).filter(([name]) => name !== 'server');
  if (!entries.length) {
    headers.innerHTML = `<div class="empty">${esc(t('no_headers'))}</div>`;
  } else {
    for (const [name, value] of entries) {
      const div = document.createElement('div');
      div.className = 'kv';
      div.innerHTML = `<span class="name">${esc(name)}</span><span class="val">${esc(
        value.length > 160 ? value.slice(0, 160) + '…' : value)}</span>`;
      headers.appendChild(div);
    }
  }

  const cookies = byId('h-cookies');
  cookies.innerHTML = '';
  if (!http.cookies?.length) {
    cookies.innerHTML = `<div class="empty">${esc(t('no_cookies'))}</div>`;
  } else {
    for (const cookie of http.cookies) {
      const flags = [
        cookie.secure ? 'Secure' : `⚠ ${t('no_secure')}`,
        cookie.httpOnly ? 'HttpOnly' : `⚠ ${t('no_httponly')}`,
        cookie.sameSite ? `SameSite=${cookie.sameSite}` : null,
      ].filter(Boolean).join(' · ');
      const div = document.createElement('div');
      div.className = 'kv';
      div.innerHTML = `<span class="name">${esc(cookie.name)}</span><span class="val">${esc(flags)}</span>`;
      cookies.appendChild(div);
    }
  }
}

function renderDns() {
  const dns = REPORT.dns || {};
  const v4 = (dns.addresses || []).filter(a => a.family === 4).map(a => a.address);
  const v6 = (dns.addresses || []).filter(a => a.family === 6).map(a => a.address);
  set('d-a', v4.length ? v4.join(', ') : null);
  set('d-aaaa', v6.length ? v6.join(', ') : t('v_no'), v6.length ? 'ok' : 'muted');
  set('d-ptr', dns.reverse);

  const caa = dns.caa;
  set('d-caa', caa ? [...caa.issue, ...caa.issueWild.map(v => v + ' (wild)')].join(', ') || t('v_none') : t('v_no'),
    caa ? 'ok' : 'muted');
  set('d-caa-match', dns.caaMatchesIssuer === null || dns.caaMatchesIssuer === undefined
    ? DASH : dns.caaMatchesIssuer ? t('v_yes') : t('v_no'),
  dns.caaMatchesIssuer === true ? 'ok' : dns.caaMatchesIssuer === false ? 'warn' : 'muted');
}

const STATUS_SEVERITY = {
  vulnerable: 'bad', possible: 'warn', weak: 'warn', missing: 'warn',
  partial: 'warn', warning: 'warn', mitigated: 'muted', unknown: 'muted', safe: 'ok',
};

function renderVulnerabilities() {
  const box = byId('vuln-list');
  box.innerHTML = '';
  const findings = [...(REPORT.vulnerabilities || [])];
  const order = { vulnerable: 0, possible: 1, weak: 2, missing: 2, partial: 2, warning: 2, mitigated: 3, unknown: 4, safe: 5 };
  findings.sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9));

  for (const finding of findings) {
    const div = document.createElement('div');
    div.className = 'finding';
    const severity = finding.status === 'safe' ? 'ok' : finding.severity;
    div.innerHTML =
      `<span class="sev sev-${esc(severity)}">${esc(finding.status === 'safe' ? t('v_ok') : tCode('sev', finding.severity))}</span>` +
      `<span class="body"><span class="title">${esc(tCode('vuln', finding.id))}` +
      (finding.cve ? ` <span class="cve">${esc(finding.cve)}</span>` : '') +
      `</span><div class="desc">${esc(tCode('vd', finding.id))}</div></span>` +
      `<span class="state v ${STATUS_SEVERITY[finding.status] || ''}">${esc(tCode('st', finding.status))}</span>`;
    box.appendChild(div);
  }
}

function renderCiphers() {
  const box = byId('cipher-blocks');
  box.innerHTML = '';

  for (const [version, block] of Object.entries(REPORT.ciphers || {})) {
    const wrap = document.createElement('div');
    wrap.className = 'cipher-block';

    const head = document.createElement('div');
    head.className = 'cipher-head';
    head.innerHTML = `<span>${esc(version)}</span><span class="order">${
      esc(tCode('order', block.order))} · ${esc(t('suites_count', { n: block.suites.length }))}</span>`;
    wrap.appendChild(head);

    const table = document.createElement('div');
    table.className = 'table-wrap';
    const rows = block.suites.map(suite => {
      const issues = (suite.issues || []).map(i => tCode('ci', i)).join(', ');
      return `<tr>
        <td class="mono">${esc(suite.hex)}</td>
        <td class="mono">${esc(suite.name)}</td>
        <td class="num">${suite.bits ?? ''}</td>
        <td>${suite.pfs ? '✓' : '—'}</td>
        <td>${suite.aead ? '✓' : '—'}</td>
        <td class="${esc(suite.strength)}">${esc(tCode('str', suite.strength))}</td>
        <td>${esc(issues)}</td>
      </tr>`;
    }).join('');
    table.innerHTML = `<table class="table"><thead><tr>
      <th>ID</th><th>${esc(t('th_suite'))}</th><th>${esc(t('th_bits'))}</th>
      <th>${esc(t('th_pfs'))}</th><th>${esc(t('th_aead'))}</th>
      <th>${esc(t('th_strength'))}</th><th>${esc(t('th_notes'))}</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
    wrap.appendChild(table);
    box.appendChild(wrap);
  }
}

function renderSimulation() {
  const body = byId('sim-body');
  body.innerHTML = '';
  for (const sim of REPORT.simulation || []) {
    const tr = document.createElement('tr');
    if (sim.ok) {
      tr.innerHTML = `<td>${esc(sim.client)} <span class="k">${esc(sim.platform)}</span></td>
        <td class="${sim.protocol === 'TLS 1.3' ? 'strong' : sim.protocol === 'TLS 1.2' ? '' : 'legacy'}">${esc(sim.protocol)}</td>
        <td class="mono">${esc(sim.cipher || '')}</td>
        <td class="mono">${esc(sim.group || '')}</td>`;
    } else {
      tr.innerHTML = `<td>${esc(sim.client)} <span class="k">${esc(sim.platform)}</span></td>
        <td class="weak" colspan="3">${esc(t('sim_failed'))} · <span class="mono">${esc(sim.error || '')}</span></td>`;
    }
    body.appendChild(tr);
  }
}

function renderRaw() {
  byId('raw-json').textContent = JSON.stringify(REPORT, null, 2);
}

/* ================================================================== *
 * Language and metadata
 * ================================================================== */

/**
 * The head is filled in by the server for the first paint; this keeps it right
 * afterwards, when the language changes or the page navigates without reloading.
 */
function updateSeoMeta() {
  const title = TARGET ? `${TARGET} — ${t('title_short')}` : t('title');
  const description = t('subtitle');
  const ogLocale = locale().replace('-', '_');
  const url = location.origin + location.pathname;

  document.title = title;
  byId('meta-description')?.setAttribute('content', description);
  byId('og-title')?.setAttribute('content', title);
  byId('og-description')?.setAttribute('content', description);
  byId('og-locale')?.setAttribute('content', ogLocale);
  byId('og-url')?.setAttribute('content', url);
  byId('og-image')?.setAttribute('content', location.origin + '/static/og-image.png');
  byId('twitter-title')?.setAttribute('content', title);
  byId('twitter-description')?.setAttribute('content', description);
  byId('twitter-image')?.setAttribute('content', location.origin + '/static/og-image.png');
  byId('link-canonical')?.setAttribute('href', url);
  // A report is a scan result, not something to leave in an index.
  byId('meta-robots')?.setAttribute('content', TARGET ? 'noindex, follow' : 'index, follow');
}

const EXAMPLES = ['github.com', 'badssl.com', 'expired.badssl.com', 'self-signed.badssl.com'];

function renderExamples() {
  const box = byId('examples');
  box.innerHTML = '';
  for (const host of EXAMPLES) {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = host;
    button.addEventListener('click', () => navigateTo(host));
    box.appendChild(button);
  }
}

function applyLanguage(lang) {
  LANG = lang;
  try { localStorage.setItem(STORAGE_KEY, lang); } catch { /* private browsing */ }

  document.documentElement.lang = lang;
  document.documentElement.dir = RTL.has(lang) ? 'rtl' : 'ltr';
  updateSeoMeta();

  document.querySelectorAll('[data-i18n]').forEach(node => {
    node.textContent = t(node.dataset.i18n);
  });
  byId('lang').value = lang;
  byId('lang').setAttribute('aria-label', t('lang_aria'));
  byId('api-hint').innerHTML = t('api_hint', { origin: esc(location.origin) });
  byId('search-host').setAttribute('aria-label', t('btn_scan'));
  byId('search-host').setAttribute('placeholder', t('ph_host'));

  renderExamples();
  render();
}

/* ================================================================== *
 * Navigation
 * ================================================================== */

function hostFromPath() {
  const segment = decodeURIComponent(location.pathname.replace(/^\/+|\/+$/g, ''));
  return segment && segment !== 'api' ? segment : null;
}

function navigateTo(host) {
  history.pushState({ host }, '', host ? `/${encodeURIComponent(host)}` : '/');
  if (host) startScan(host);
  else showEmpty();
}

function showEmpty() {
  TARGET = null;
  REPORT = null;
  LAST_ERROR = null;
  byId('report').hidden = true;
  byId('empty').hidden = false;
  byId('alerts').innerHTML = '';
  byId('progress').hidden = true;
  byId('hero-host').textContent = t('no_target');
  byId('hero-meta').innerHTML = '';
  byId('grade-badge').className = 'grade-badge pending';
  byId('grade-badge').textContent = '·';
  byId('search-host').value = '';
  updateSeoMeta();
}

function initLanguageSelect() {
  const select = byId('lang');
  const names = window.LANG_NAMES || {};
  for (const code of SUPPORTED) {
    const option = document.createElement('option');
    option.value = code;
    option.textContent = names[code] || code;
    select.appendChild(option);
  }
  select.addEventListener('change', () => applyLanguage(select.value));
}

function initEvents() {
  byId('search-form').addEventListener('submit', event => {
    event.preventDefault();
    const value = byId('search-host').value.trim();
    if (value) navigateTo(value);
  });

  byId('btn-rescan').addEventListener('click', () => {
    if (TARGET) startScan(TARGET, { refresh: true });
  });

  byId('btn-copy-json').addEventListener('click', () => {
    if (!REPORT) return toast(t('toast_nothing'));
    copyText(JSON.stringify(REPORT, null, 2), t('toast_json'));
  });

  byId('btn-save-json').addEventListener('click', () => {
    if (!REPORT) return toast(t('toast_nothing'));
    const blob = new Blob([JSON.stringify(REPORT, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `myssl-${REPORT.host}-${REPORT.port}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast(t('toast_saved'));
  });

  window.addEventListener('popstate', () => {
    const host = hostFromPath();
    if (host) startScan(host);
    else showEmpty();
  });
}

function main() {
  initLanguageSelect();
  initEvents();
  applyLanguage(LANG);

  const host = hostFromPath();
  if (host) startScan(host);
  else showEmpty();
}

main();
