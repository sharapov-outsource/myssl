/**
 * Known weaknesses, derived from what the scan observed.
 *
 * Every verdict here comes from configuration the server volunteered during a
 * normal handshake: which protocols it speaks, which suites it accepts, which
 * extensions it advertises. Nothing is confirmed by attacking the server — no
 * malformed heartbeat, no padding oracle probing, no forced downgrade with real
 * traffic. Where that leaves a genuine doubt (Heartbleed, ROBOT) the finding
 * says so instead of pretending to be sure.
 */

import { describeSuite } from './suites.js';

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * @param {object} data assembled scan results
 * @returns {Array<{id:string,severity:string,status:string,cve?:string,detail?:object}>}
 */
export function assessVulnerabilities(data) {
  const findings = [];
  const add = (id, severity, status, extra = {}) => findings.push({ id, severity, status, ...extra });

  const protocols = new Set(data.protocols.filter(p => p.supported).map(p => p.name));
  const suites = (data.allCiphers || []).map(describeSuite);
  const has = predicate => suites.filter(predicate);
  const feature = data.features || {};
  const cert = data.certificate || {};

  /* ---------------- protocol-level ---------------- */

  add('drown', 'critical', data.ssl2?.supported ? 'vulnerable' : 'safe', {
    cve: 'CVE-2016-0800',
    detail: { ssl2: Boolean(data.ssl2?.supported) },
  });

  const poodle = protocols.has('SSL 3.0') && has(s => s.mode === 'CBC').length > 0;
  add('poodle', 'high', protocols.has('SSL 3.0') ? (poodle ? 'vulnerable' : 'partial') : 'safe', {
    cve: 'CVE-2014-3566',
    detail: { ssl3: protocols.has('SSL 3.0') },
  });

  const cbcOnOld = (protocols.has('TLS 1.0') || protocols.has('SSL 3.0')) &&
    has(s => s.mode === 'CBC').length > 0;
  add('beast', 'low', cbcOnOld ? 'mitigated' : 'safe', {
    cve: 'CVE-2011-3389',
    detail: { tls10: protocols.has('TLS 1.0') },
  });

  /* ---------------- cipher-level ---------------- */

  const exportSuites = has(s => s.export);
  add('freak', 'high', exportSuites.some(s => s.keyExchange === 'RSA') ? 'vulnerable' : 'safe', {
    cve: 'CVE-2015-0204',
    detail: { suites: exportSuites.filter(s => s.keyExchange === 'RSA').map(s => s.name) },
  });

  const dhBits = data.keyExchange?.dh?.bits;
  const logjam = exportSuites.some(s => s.keyExchange === 'DHE' || s.keyExchange === 'DH') ||
    (dhBits !== undefined && dhBits < 1024);
  add('logjam', 'high', logjam ? 'vulnerable' : (dhBits !== undefined && dhBits < 2048 ? 'weak' : 'safe'), {
    cve: 'CVE-2015-4000',
    detail: { dhBits },
  });

  const sweet32 = has(s => s.encryption === '3DES' || s.encryption === 'IDEA' || s.encryption === 'DES');
  add('sweet32', 'medium', sweet32.length ? 'vulnerable' : 'safe', {
    cve: 'CVE-2016-2183',
    detail: { suites: sweet32.map(s => s.name) },
  });

  const rc4 = has(s => s.encryption === 'RC4');
  add('rc4', 'high', rc4.length ? 'vulnerable' : 'safe', {
    cve: 'CVE-2013-2566',
    detail: { suites: rc4.map(s => s.name) },
  });

  const nullOrAnon = has(s => s.encryption === 'NULL' || s.anonymous);
  add('null-anon', 'critical', nullOrAnon.length ? 'vulnerable' : 'safe', {
    detail: { suites: nullOrAnon.map(s => s.name) },
  });

  /* ---------------- extension-level ---------------- */

  add('crime', 'high', feature.compression?.supported === true ? 'vulnerable'
    : feature.compression?.supported === false ? 'safe' : 'unknown', {
    cve: 'CVE-2012-4929',
    detail: feature.compression,
  });

  // The heartbeat extension is a precondition for Heartbleed, not a proof of
  // it: a patched OpenSSL still advertises it. Confirming would mean sending a
  // malformed heartbeat, which this service will not do.
  add('heartbleed', 'critical', feature.heartbeat?.advertised === true ? 'possible' : 'safe', {
    cve: 'CVE-2014-0160',
    detail: { heartbeatExtension: feature.heartbeat?.advertised === true },
  });

  const secureReneg = feature.secureRenegotiation;
  add('insecure-renegotiation', 'high',
    secureReneg === false ? 'vulnerable' : secureReneg === true ? 'safe' : 'unknown', {
      cve: 'CVE-2009-3555',
      detail: { renegotiationInfo: secureReneg },
    });

  add('client-renegotiation-dos', 'medium',
    feature.clientRenegotiation?.supported === true ? 'vulnerable'
      : feature.clientRenegotiation?.supported === false ? 'safe' : 'unknown', {
      detail: feature.clientRenegotiation,
    });

  // ROBOT needs an oracle to be confirmed; RSA key transport is what makes the
  // question worth asking at all.
  const rsaKx = has(s => s.keyExchange === 'RSA' && s.authentication === 'RSA');
  add('robot', 'medium', rsaKx.length ? 'possible' : 'safe', {
    cve: 'CVE-2017-13099',
    detail: { rsaKeyExchangeSuites: rsaKx.length },
  });

  const cbc = has(s => s.mode === 'CBC');
  add('lucky13', 'low', cbc.length ? 'possible' : 'safe', {
    cve: 'CVE-2013-0169',
    detail: { cbcSuites: cbc.length },
  });

  add('downgrade-protection', 'low',
    feature.fallbackScsv?.supported === true ? 'safe'
      : feature.fallbackScsv?.supported === false ? 'vulnerable' : 'unknown', {
      detail: feature.fallbackScsv,
    });

  /* ---------------- forward secrecy and hygiene ---------------- */

  const withPfs = has(s => s.pfs).length;
  add('no-forward-secrecy', 'medium',
    suites.length === 0 ? 'unknown' : withPfs === 0 ? 'vulnerable'
      : withPfs < suites.length ? 'partial' : 'safe', {
      detail: { withPfs, total: suites.length },
    });

  add('weak-dh', 'medium',
    dhBits === undefined ? 'safe' : dhBits < 2048 ? 'vulnerable' : 'safe', {
      detail: { dhBits },
    });

  /* ---------------- certificate ---------------- */

  const certIssues = new Set(cert.issues || []);
  add('certificate-trust', 'critical',
    certIssues.has('not-trusted') || certIssues.has('self-signed') ? 'vulnerable' : 'safe', {
      detail: { trusted: cert.trusted, error: cert.trustError },
    });
  add('certificate-expiry', 'critical',
    certIssues.has('expired') ? 'vulnerable'
      : (cert.leaf?.daysRemaining ?? 999) < 14 ? 'warning' : 'safe', {
      detail: { daysRemaining: cert.leaf?.daysRemaining, notAfter: cert.leaf?.notAfter },
    });
  add('certificate-name', 'critical', certIssues.has('hostname-mismatch') ? 'vulnerable' : 'safe', {
    detail: { hostMatch: cert.hostMatch },
  });
  add('certificate-chain', 'medium', certIssues.has('incomplete-chain') ? 'vulnerable'
    : certIssues.has('chain-out-of-order') ? 'warning' : 'safe', {
    detail: { complete: cert.complete, length: cert.length },
  });
  add('weak-certificate-key', 'high', certIssues.has('weak-key') ? 'vulnerable' : 'safe', {
    detail: { bits: cert.leaf?.keyBits, strength: cert.leaf?.keyStrength },
  });
  add('weak-signature', 'high', certIssues.has('weak-signature-algorithm') ? 'vulnerable' : 'safe', {
    detail: { algorithm: cert.leaf?.signatureAlgorithm },
  });

  /* ---------------- HTTP layer ---------------- */

  const http = data.http || {};
  add('hsts', 'medium', http.hsts?.present
    ? (http.hsts.longEnough ? 'safe' : 'weak')
    : http.reachable ? 'missing' : 'unknown', {
    detail: http.hsts,
  });
  add('http-redirect', 'low',
    http.plainHttp?.toHttps ? 'safe'
      : http.plainHttp?.error ? 'unknown'
        : http.plainHttp ? 'missing' : 'unknown', {
      detail: http.plainHttp,
    });

  return findings;
}

/** The findings that actually went wrong, worst first. */
export function problems(findings) {
  const bad = new Set(['vulnerable', 'possible', 'weak', 'missing', 'partial', 'warning']);
  return findings
    .filter(f => bad.has(f.status))
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}
