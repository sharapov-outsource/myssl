/**
 * The letter grade.
 *
 * This follows the structure Qualys published in the SSL Server Rating Guide:
 * three weighted components (protocol support 30%, key exchange 30%, cipher
 * strength 40%), then a set of caps that pull the result down when something
 * specific is wrong, then A+ for a configuration that also gets HSTS right.
 *
 * It is an independent implementation of a public methodology, updated for what
 * matters today — TLS 1.0/1.1 are treated as legacy, TLS 1.3 as the norm. It is
 * not affiliated with, endorsed by, or guaranteed to agree with Qualys SSL Labs.
 */

import { describeSuite } from './suites.js';
import { GROUP_BITS } from './tls-probe.js';

/** Component scores per protocol version, from the rating guide. */
const PROTOCOL_SCORES = {
  'SSL 2.0': 0,
  'SSL 3.0': 80,
  'TLS 1.0': 90,
  'TLS 1.1': 95,
  'TLS 1.2': 100,
  'TLS 1.3': 100,
};

const LETTERS = [
  [80, 'A'], [65, 'B'], [50, 'C'], [35, 'D'], [20, 'E'], [0, 'F'],
];

function letterFor(score) {
  for (const [threshold, letter] of LETTERS) if (score >= threshold) return letter;
  return 'F';
}

const GRADE_RANK = { 'A+': 0, A: 1, 'A-': 2, B: 3, C: 4, D: 5, E: 6, F: 7, T: 8, M: 9 };

/**
 * Warnings that stand between an otherwise clean configuration and an A+.
 * The rest are worth showing but do not describe a risk on their own — plenty
 * of well-run sites keep RSA key transport around for old clients.
 */
const A_PLUS_BLOCKERS = new Set([
  'no-tls13',
  'trusted-by-extra-root',
  'heartbeat-extension-enabled',
  'client-initiated-renegotiation',
  'no-certificate-transparency',
  'certificate-valid-too-long',
  'compression-unknown',
]);

/** The worse of two grades. */
function worst(a, b) {
  return GRADE_RANK[b] > GRADE_RANK[a] ? b : a;
}

/* ------------------------------------------------------------------ *
 * Components
 * ------------------------------------------------------------------ */

function protocolComponent(protocols, ssl2) {
  const names = protocols.filter(p => p.supported).map(p => p.name);
  if (ssl2) names.unshift('SSL 2.0');
  if (!names.length) return { score: 0, best: null, worst: null, supported: [] };

  const scores = names.map(n => PROTOCOL_SCORES[n] ?? 0);
  // TLS 1.2 and 1.3 score the same, so the version order — not the score —
  // decides which one is named as the best and which as the worst.
  const ordered = [...names].sort(
    (a, b) => Object.keys(PROTOCOL_SCORES).indexOf(a) - Object.keys(PROTOCOL_SCORES).indexOf(b)
  );
  return {
    score: Math.round((Math.max(...scores) + Math.min(...scores)) / 2),
    best: ordered[ordered.length - 1],
    worst: ordered[0],
    supported: names,
  };
}

/** Strength of the weakest key involved in establishing a session, in RSA-equivalent bits. */
function keyExchangeComponent({ certificate, groups, dh, suites }) {
  const parts = [];

  const leaf = certificate?.leaf;
  if (leaf?.keyStrength) parts.push({ what: 'certificate key', bits: rsaEquivalent(leaf.keyStrength) });
  if (dh?.bits) parts.push({ what: 'DH group', bits: dh.bits });

  if (groups?.length) {
    const weakest = Math.min(...groups.map(g => GROUP_BITS[g.name] || 128));
    parts.push({ what: 'EC group', bits: rsaEquivalent(weakest) });
  }

  const anonymous = suites.some(s => s.anonymous);
  if (anonymous) return { score: 0, weakest: { what: 'anonymous key exchange', bits: 0 }, parts };
  if (!parts.length) return { score: 0, weakest: null, parts };

  const weakest = parts.reduce((a, b) => (b.bits < a.bits ? b : a));
  const bits = weakest.bits;
  const score =
    bits === 0 ? 0 :
    bits < 512 ? 20 :
    bits < 1024 ? 40 :
    bits < 2048 ? 80 :
    bits < 4096 ? 90 : 100;

  return { score, weakest, parts };
}

/** Symmetric strength expressed as the RSA modulus size of comparable effort. */
function rsaEquivalent(bits) {
  if (bits >= 256) return 15360;
  if (bits >= 192) return 7680;
  if (bits >= 128) return 3072;
  if (bits >= 112) return 2048;
  if (bits >= 80) return 1024;
  return bits * 8;
}

function cipherComponent(suites) {
  const usable = suites.filter(s => typeof s.bits === 'number');
  if (!usable.length) return { score: 0, strongest: null, weakest: null };

  const scoreOf = bits => (bits === 0 ? 0 : bits < 128 ? 20 : bits < 256 ? 80 : 100);
  const strongest = usable.reduce((a, b) => (b.bits > a.bits ? b : a));
  const weakest = usable.reduce((a, b) => (b.bits < a.bits ? b : a));

  return {
    score: Math.round((scoreOf(strongest.bits) + scoreOf(weakest.bits)) / 2),
    strongest: { name: strongest.name, bits: strongest.bits },
    weakest: { name: weakest.name, bits: weakest.bits },
  };
}

/* ------------------------------------------------------------------ *
 * The grade
 * ------------------------------------------------------------------ */

/**
 * @param {object} data assembled scan results
 * @returns {object} grade, numeric score, the three components and every
 *                   adjustment that was applied, so the result can be explained
 */
export function grade(data) {
  const suites = (data.allCiphers || []).map(describeSuite);
  const protocols = protocolComponent(data.protocols, data.ssl2?.supported);
  const keyExchange = keyExchangeComponent({
    certificate: data.certificate,
    groups: data.keyExchange?.groups,
    dh: data.keyExchange?.dh,
    suites,
  });
  const cipher = cipherComponent(suites);

  const score = Math.round(0.3 * protocols.score + 0.3 * keyExchange.score + 0.4 * cipher.score);
  let letter = letterFor(score);

  const caps = [];
  const warnings = [];
  // Filled in at the end, but declared here because the early returns for an
  // untrusted certificate go through the same finish().
  let blocking = [];
  const cap = (grade, reason) => { caps.push({ grade, reason }); letter = worst(letter, grade); };

  const cert = data.certificate || {};
  const issues = new Set(cert.issues || []);
  const features = data.features || {};
  const hsts = data.http?.hsts;
  const findings = new Map((data.vulnerabilities || []).map(v => [v.id, v]));
  const isVulnerable = id => findings.get(id)?.status === 'vulnerable';

  /* --- trust overrides everything --- */
  if (issues.has('hostname-mismatch')) {
    return finish('M', 'certificate-name-mismatch');
  }
  if (issues.has('expired') || issues.has('not-yet-valid') || issues.has('self-signed') ||
      issues.has('revoked') || issues.has('not-trusted') || issues.has('incomplete-chain') ||
      issues.has('bad-signature')) {
    return finish('T', 'certificate-not-trusted');
  }

  /* --- nothing to grade --- */
  // A certificate problem is still worth reporting from a partial scan: the
  // certificate was read before the target went quiet. Everything the score is
  // built from was not, so there is no score.
  if (data.incomplete) return finish('?', 'scan-incomplete');

  /* --- straight to F --- */
  if (data.ssl2?.supported) cap('F', 'ssl2-supported');
  if (isVulnerable('insecure-renegotiation')) cap('F', 'insecure-renegotiation');
  if (isVulnerable('null-anon')) cap('F', 'null-or-anonymous-suites');
  if (isVulnerable('freak')) cap('F', 'export-suites');
  if (isVulnerable('logjam')) cap('F', 'logjam');
  if (suites.length && suites.every(s => s.encryption === 'RC4')) cap('F', 'rc4-only');

  /* --- capped at C --- */
  if (isVulnerable('crime')) cap('C', 'tls-compression');
  if (isVulnerable('sweet32')) cap('C', 'sweet32-64-bit-block-cipher');
  if (protocols.supported.includes('SSL 3.0')) cap('C', 'ssl3-supported');

  /* --- capped at B --- */
  if (isVulnerable('rc4')) cap('B', 'rc4-supported');
  if (findings.get('no-forward-secrecy')?.status === 'vulnerable') cap('B', 'no-forward-secrecy');
  if (data.keyExchange?.dh?.bits && data.keyExchange.dh.bits < 2048) cap('B', 'weak-dh-group');
  if (protocols.supported.includes('TLS 1.0') || protocols.supported.includes('TLS 1.1')) {
    cap('B', 'legacy-tls-versions');
  }
  if (!protocols.supported.includes('TLS 1.2') && !protocols.supported.includes('TLS 1.3')) {
    cap('C', 'no-modern-tls');
  }

  /* --- warnings: not enough to lower a grade on their own, but they block A+ --- */
  if (!protocols.supported.includes('TLS 1.3')) warnings.push('no-tls13');
  if (findings.get('no-forward-secrecy')?.status === 'partial') warnings.push('some-suites-without-pfs');
  if (features.compression?.supported === null) warnings.push('compression-unknown');
  if (findings.get('heartbleed')?.status === 'possible') warnings.push('heartbeat-extension-enabled');
  if (findings.get('robot')?.status === 'possible') warnings.push('rsa-key-exchange-enabled');
  if (features.clientRenegotiation?.supported === true) warnings.push('client-initiated-renegotiation');
  if (cert.leaf?.sctCount === 0) warnings.push('no-certificate-transparency');
  if (issues.has('over-long-validity')) warnings.push('certificate-valid-too-long');
  if (issues.has('root-included')) warnings.push('root-certificate-sent');
  // Trusted, but only where that root is installed — a browser with nothing
  // added will still refuse the site.
  if (issues.has('trusted-by-extra-root')) warnings.push('trusted-by-extra-root');
  // Stapling can only be expected when the certificate names a responder at
  // all — issuers have been dropping OCSP, and a certificate without an OCSP
  // URL has nothing to staple.
  if (features.ocspStapling === false && cert.leaf?.ocspUrls?.length) {
    warnings.push('no-ocsp-stapling');
  }
  if (cert.leaf?.mustStaple && features.ocspStapling === false) {
    cap('T', 'must-staple-without-stapling');
  }

  /* --- the bonus --- */
  blocking = warnings.filter(w => A_PLUS_BLOCKERS.has(w));
  if (letter === 'A') {
    if (blocking.length) letter = 'A-';
    else if (hsts?.present && hsts.longEnough) letter = 'A+';
  }

  return finish(letter);

  function finish(finalGrade, reason) {
    return {
      grade: finalGrade,
      score,
      reason,
      components: {
        protocol: { ...protocols, weight: 0.3 },
        keyExchange: { ...keyExchange, weight: 0.3 },
        cipher: { ...cipher, weight: 0.4 },
      },
      caps,
      warnings,
      blockingWarnings: blocking,
      hsts: hsts?.present ? { maxAge: hsts.maxAge, longEnough: hsts.longEnough } : null,
      methodology: 'myssl/1.0, structured after the SSL Labs Server Rating Guide',
    };
  }
}
