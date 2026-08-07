/**
 * Certificate and chain analysis.
 *
 * Works on the chain exactly as the server presented it, because the questions
 * that matter — is an intermediate missing, is the order wrong, is the root
 * being sent needlessly — are questions about those bytes, not about the path
 * a library managed to build afterwards. Trust is then established by walking
 * upwards into the stores in `trust.js`, so the verdict does not change with
 * the machine the scanner runs on.
 */

import { X509Certificate, createHash } from 'node:crypto';

import {
  certificateExtensions, parseCertificate, collectUris, collectOids,
  decodeKeyUsage, countSct, parseOcspResponse,
  OID, SIGNATURE_OIDS, POLICY_OIDS, EKU_OIDS,
} from './asn1.js';
import { findAnchor, anchorName, MOZILLA } from './trust.js';

const DAY = 24 * 60 * 60 * 1000;

/** Field size of the curves that actually appear in certificates. */
const CURVE_BITS = {
  prime256v1: 256, secp256r1: 256, secp256k1: 256, secp384r1: 384, secp521r1: 521,
  prime192v1: 192, secp192r1: 192, secp224r1: 224, secp224k1: 224,
  brainpoolP256r1: 256, brainpoolP384r1: 384, brainpoolP512r1: 512,
  ed25519: 255, ed448: 448, x25519: 255, x448: 448,
};

function curveBits(name) {
  if (!name) return undefined;
  if (CURVE_BITS[name]) return CURVE_BITS[name];
  const digits = /(\d{3})/.exec(name);
  return digits ? Number(digits[1]) : undefined;
}

/** Symmetric-equivalent strength, following the usual NIST comparison table. */
export function keyStrength(type, bits, curve) {
  if (type === 'rsa' || type === 'rsa-pss' || type === 'dsa') {
    if (bits >= 15360) return 256;
    if (bits >= 7680) return 192;
    if (bits >= 3072) return 128;
    if (bits >= 2048) return 112;
    if (bits >= 1024) return 80;
    return Math.max(40, Math.round(bits / 20));
  }
  if (type === 'ed25519') return 128;
  if (type === 'ed448') return 224;
  if (type === 'ec') {
    const size = bits || Number((curve || '').replace(/\D/g, '')) || 0;
    if (size >= 512) return 256;
    if (size >= 384) return 192;
    if (size >= 256) return 128;
    if (size >= 224) return 112;
    if (size >= 192) return 96;
    return 80;
  }
  return 0;
}

/** RSA 2048 and P-256 are the floor; anything below is called out. */
function keyVerdict(strength) {
  if (strength >= 128) return 'strong';
  if (strength >= 112) return 'acceptable';
  if (strength >= 80) return 'weak';
  return 'insecure';
}

function subjectField(dn, field) {
  const line = String(dn || '').split('\n').find(l => l.startsWith(field + '='));
  return line ? line.slice(field.length + 1).trim() : undefined;
}

/** "DNS:a.example, DNS:*.example" → ['a.example', '*.example'] */
function altNames(cert) {
  const raw = cert.subjectAltName;
  if (!raw) return { dns: [], ip: [], other: [] };
  const dns = [], ip = [], other = [];
  for (const entry of raw.split(',').map(s => s.trim())) {
    if (entry.startsWith('DNS:')) dns.push(entry.slice(4));
    else if (entry.startsWith('IP Address:')) ip.push(entry.slice(11).trim());
    else if (entry) other.push(entry);
  }
  return { dns, ip, other };
}

/* ------------------------------------------------------------------ *
 * A single certificate
 * ------------------------------------------------------------------ */

export function describeCertificate(der, { position = 0 } = {}) {
  let cert;
  try {
    cert = new X509Certificate(der);
  } catch (err) {
    return { position, error: 'unparsable: ' + err.message };
  }

  const extensions = certificateExtensions(der);
  const parsed = parseCertificate(der);
  const signature = SIGNATURE_OIDS[parsed?.signatureAlgorithmOid] || {
    name: parsed?.signatureAlgorithmOid || 'unknown',
  };

  const key = cert.publicKey;
  const details = key?.asymmetricKeyDetails || {};
  const keyType = key?.asymmetricKeyType;
  const keyBits = details.modulusLength || curveBits(details.namedCurve) ||
    (keyType === 'ed25519' ? 255 : keyType === 'ed448' ? 448 : undefined);
  const strength = keyStrength(keyType, keyBits, details.namedCurve);

  const notBefore = new Date(cert.validFrom);
  const notAfter = new Date(cert.validTo);
  const now = Date.now();

  const policies = extensions.has(OID.certificatePolicies)
    ? collectOids(extensions.get(OID.certificatePolicies).value)
      .map(oid => POLICY_OIDS[oid]).filter(Boolean)
    : [];

  const aia = extensions.has(OID.authorityInfoAccess)
    ? collectUris(extensions.get(OID.authorityInfoAccess).value)
    : [];

  return {
    position,
    subject: cert.subject,
    commonName: subjectField(cert.subject, 'CN'),
    organization: subjectField(cert.subject, 'O'),
    issuer: cert.issuer,
    issuerCommonName: subjectField(cert.issuer, 'CN'),
    issuerOrganization: subjectField(cert.issuer, 'O'),
    serialNumber: cert.serialNumber,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    daysRemaining: Math.floor((notAfter.getTime() - now) / DAY),
    daysValid: Math.round((notAfter.getTime() - notBefore.getTime()) / DAY),
    expired: notAfter.getTime() < now,
    notYetValid: notBefore.getTime() > now,
    keyType: keyType === 'ec' ? `EC ${details.namedCurve || ''}`.trim() : (keyType || 'unknown').toUpperCase(),
    keyBits,
    keyStrength: strength,
    keyVerdict: keyVerdict(strength),
    signatureAlgorithm: signature.name,
    signatureHash: signature.hash,
    weakSignature: Boolean(signature.weak),
    selfSigned: cert.subject === cert.issuer && cert.checkIssued(cert),
    ca: cert.ca,
    altNames: altNames(cert),
    keyUsage: extensions.has(OID.keyUsage) ? decodeKeyUsage(extensions.get(OID.keyUsage).value) : [],
    extendedKeyUsage: (cert.keyUsage || []).map(oid => EKU_OIDS[oid] || oid),
    validation: policies[0],
    sctCount: extensions.has(OID.sct) ? countSct(extensions.get(OID.sct).value) : 0,
    mustStaple: extensions.has(OID.mustStaple),
    ocspUrls: aia.filter(u => /ocsp/i.test(u)),
    caIssuerUrls: aia.filter(u => !/ocsp/i.test(u)),
    crlUrls: extensions.has(OID.crlDistributionPoints)
      ? collectUris(extensions.get(OID.crlDistributionPoints).value) : [],
    fingerprints: {
      sha256: cert.fingerprint256.replace(/:/g, '').toLowerCase(),
      sha1: cert.fingerprint.replace(/:/g, '').toLowerCase(),
      spkiSha256: spkiPin(cert),
    },
    pem: position === 0 ? cert.toString() : undefined,
    _cert: cert,
  };
}

/** The value an HPKP-style pin would carry: base64(SHA-256(SubjectPublicKeyInfo)). */
function spkiPin(cert) {
  try {
    const spki = cert.publicKey.export({ type: 'spki', format: 'der' });
    return createHash('sha256').update(spki).digest('base64');
  } catch {
    return undefined;
  }
}

/* ------------------------------------------------------------------ *
 * The chain
 * ------------------------------------------------------------------ */

/**
 * @param {Buffer[]} derChain  certificates in the order the server sent them
 * @param {object}   options   { host, ocspResponse, nodeVerdict }
 */
export function analyzeChain(derChain, { host, ocspResponse, nodeVerdict } = {}) {
  if (!derChain?.length) {
    return { error: 'no-certificates', chain: [], issues: ['no-certificates'] };
  }

  const chain = derChain.map((der, position) => describeCertificate(der, { position }));
  const leaf = chain[0];
  if (leaf.error) return { error: leaf.error, chain, issues: ['unparsable-certificate'] };

  const issues = [];
  const certs = chain.map(c => c._cert).filter(Boolean);

  /* --- order and completeness --- */
  for (let i = 0; i < certs.length - 1; i++) {
    if (!certs[i].checkIssued(certs[i + 1])) {
      issues.push('chain-out-of-order');
      break;
    }
  }

  const top = certs[certs.length - 1];
  // A self-signed leaf is not a chain that ends in a root — it is a chain that
  // never started, so the flag only applies when a real chain is present.
  const rootIncluded = certs.length > 1 && Boolean(top && top.subject === top.issuer);
  if (rootIncluded) issues.push('root-included');

  const anchored = findAnchor(certs);
  const anchor = anchored?.cert || null;
  const trustStore = anchored?.store || null;
  if (!anchored) issues.push('incomplete-chain');
  // A chain that only ends in an extra store — the Russian national CA, a
  // corporate root — is genuinely trusted, but only by clients carrying that
  // root. Browsers out of the box will still refuse it.
  if (anchored && trustStore !== MOZILLA) issues.push('trusted-by-extra-root');

  /* --- signature validity within the presented chain --- */
  for (let i = 0; i < certs.length - 1; i++) {
    try {
      if (!certs[i].verify(certs[i + 1].publicKey)) issues.push('bad-signature');
    } catch { issues.push('bad-signature'); }
  }

  /* --- dates --- */
  if (leaf.expired) issues.push('expired');
  if (leaf.notYetValid) issues.push('not-yet-valid');
  if (chain.some((c, i) => i > 0 && c.expired)) issues.push('expired-intermediate');

  /* --- host name --- */
  let hostMatch = null;
  if (host) {
    try {
      hostMatch = leaf._cert.checkHost(host, { subject: 'always' }) || null;
    } catch { hostMatch = null; }
    if (!hostMatch) issues.push('hostname-mismatch');
  }

  /* --- key and algorithm strength --- */
  if (leaf.keyVerdict === 'weak' || leaf.keyVerdict === 'insecure') issues.push('weak-key');
  if (chain.some(c => c.weakSignature && !c.selfSigned)) issues.push('weak-signature-algorithm');
  if (leaf.selfSigned) issues.push('self-signed');
  // The CA/Browser Forum caps publicly trusted certificates at 398 days.
  if (leaf.daysValid > 398) issues.push('over-long-validity');
  if (!leaf.sctCount) issues.push('no-sct');

  const ocsp = ocspResponse ? parseOcspResponse(ocspResponse) : null;
  if (ocsp?.certStatus === 'revoked') issues.push('revoked');

  /* --- the verdict --- */
  const trusted = Boolean(anchored) &&
    !issues.includes('expired') && !issues.includes('not-yet-valid') &&
    !issues.includes('bad-signature') && !issues.includes('revoked');
  if (!trusted) issues.push('not-trusted');

  return {
    chain: chain.map(({ _cert, ...rest }) => rest),
    leaf: (({ _cert, ...rest }) => rest)(leaf),
    length: chain.length,
    trusted,
    trustStore,
    // Trusted by a browser with nothing installed — the question most people
    // are actually asking.
    browserTrusted: trusted && trustStore === MOZILLA,
    // Node's own opinion is kept for reference only: it varies with the
    // platform, because some builds consult the operating system store.
    nodeTrusted: nodeVerdict?.authorized ?? null,
    trustError: nodeVerdict?.authorizationError || null,
    trustAnchor: anchorName(anchor),
    hostMatch,
    rootIncluded,
    complete: Boolean(anchored),
    ocsp,
    issues: [...new Set(issues)],
  };
}
