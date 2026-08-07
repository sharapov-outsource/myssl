/**
 * A very small DER reader.
 *
 * Node's X509Certificate covers the common fields but says nothing about
 * signature algorithms, certificate policies, CRL distribution points,
 * Certificate Transparency or must-staple — all of which live in extensions
 * that have to be read out of the raw bytes. Only what this service needs is
 * implemented: definite-length DER, no BER, no streaming.
 */

const MAX_DEPTH = 24;

/** ASN.1 universal tag numbers that appear in certificates. */
export const TAG = {
  BOOLEAN: 0x01, INTEGER: 0x02, BIT_STRING: 0x03, OCTET_STRING: 0x04,
  NULL: 0x05, OID: 0x06, UTF8_STRING: 0x0c, SEQUENCE: 0x30, SET: 0x31,
  PRINTABLE_STRING: 0x13, IA5_STRING: 0x16, UTC_TIME: 0x17, GENERALIZED_TIME: 0x18,
  ENUMERATED: 0x0a,
};

/**
 * Reads one TLV at `offset`.
 * @returns {{tag:number, constructed:boolean, start:number, headerLength:number,
 *            length:number, contentStart:number, end:number}|null}
 */
export function readTlv(buf, offset = 0) {
  if (offset + 2 > buf.length) return null;
  const tag = buf[offset];
  let i = offset + 1;
  let length = buf[i++];

  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || i + count > buf.length) return null;
    length = 0;
    for (let k = 0; k < count; k++) length = (length << 8) | buf[i++];
  }
  const end = i + length;
  if (end > buf.length) return null;

  return {
    tag,
    constructed: Boolean(tag & 0x20),
    start: offset,
    headerLength: i - offset,
    length,
    contentStart: i,
    end,
  };
}

/** Content bytes of the TLV at `offset`. */
export function content(buf, offset = 0) {
  const tlv = readTlv(buf, offset);
  return tlv ? buf.subarray(tlv.contentStart, tlv.end) : null;
}

/** Every direct child of a constructed TLV, as TLV descriptors. */
export function childrenOf(buf, tlv) {
  const out = [];
  let i = tlv.contentStart;
  while (i < tlv.end) {
    const child = readTlv(buf, i);
    if (!child) break;
    out.push(child);
    i = child.end;
  }
  return out;
}

/** Dotted-decimal form of an OID's content bytes. */
export function decodeOid(bytes) {
  if (!bytes?.length) return '';
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let value = 0n;
  for (let i = 1; i < bytes.length; i++) {
    value = (value << 7n) | BigInt(bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      parts.push(value.toString());
      value = 0n;
    }
  }
  return parts.join('.');
}

/** Walks the whole structure, calling `visit(tlv, depth)` for every node. */
export function walk(buf, visit, tlv = readTlv(buf, 0), depth = 0) {
  if (!tlv || depth > MAX_DEPTH) return;
  visit(tlv, depth);
  if (!tlv.constructed) return;
  for (const child of childrenOf(buf, tlv)) walk(buf, visit, child, depth + 1);
}

/** Every OID in the structure, in document order. */
export function collectOids(buf) {
  const oids = [];
  walk(buf, tlv => {
    if (tlv.tag === TAG.OID) oids.push(decodeOid(buf.subarray(tlv.contentStart, tlv.end)));
  });
  return oids;
}

/** Every IA5String (that is how URIs are encoded) in the structure. */
export function collectUris(buf) {
  const uris = [];
  walk(buf, tlv => {
    // Context tag 6 inside GeneralName is a uniformResourceIdentifier.
    if (tlv.tag === TAG.IA5_STRING || tlv.tag === 0x86) {
      const value = buf.subarray(tlv.contentStart, tlv.end).toString('ascii');
      if (/^(https?|ldap):\/\//i.test(value)) uris.push(value);
    }
  });
  return uris;
}

/* ------------------------------------------------------------------ *
 * Certificates
 * ------------------------------------------------------------------ */

/**
 * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 * @returns {{tbs, signatureAlgorithmOid:string}|null}
 */
export function parseCertificate(der) {
  const root = readTlv(der, 0);
  if (!root || root.tag !== TAG.SEQUENCE) return null;
  const parts = childrenOf(der, root);
  if (parts.length < 2) return null;

  const algorithm = childrenOf(der, parts[1])[0];
  return {
    tbs: parts[0],
    signatureAlgorithmOid: algorithm && algorithm.tag === TAG.OID
      ? decodeOid(der.subarray(algorithm.contentStart, algorithm.end))
      : '',
  };
}

/**
 * All X.509 extensions of a certificate.
 * @returns {Map<string, {critical:boolean, value:Buffer}>}
 */
export function certificateExtensions(der) {
  const out = new Map();
  const parsed = parseCertificate(der);
  if (!parsed) return out;

  // TBSCertificate ::= SEQUENCE { [0] version, serialNumber, signature, issuer,
  //                               validity, subject, spki, ..., [3] extensions }
  const fields = childrenOf(der, parsed.tbs);
  const extensionsField = fields.find(f => f.tag === 0xa3);
  if (!extensionsField) return out;

  const sequence = childrenOf(der, extensionsField)[0];
  if (!sequence) return out;

  for (const extension of childrenOf(der, sequence)) {
    const parts = childrenOf(der, extension);
    if (!parts.length || parts[0].tag !== TAG.OID) continue;
    const oid = decodeOid(der.subarray(parts[0].contentStart, parts[0].end));
    const critical = parts.length === 3 && der[parts[1].contentStart] !== 0;
    const valueTlv = parts[parts.length - 1];
    out.set(oid, {
      critical,
      value: Buffer.from(der.subarray(valueTlv.contentStart, valueTlv.end)),
    });
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * OCSP responses
 * ------------------------------------------------------------------ */

const OCSP_RESPONSE_STATUS = {
  0: 'successful', 1: 'malformedRequest', 2: 'internalError',
  3: 'tryLater', 5: 'sigRequired', 6: 'unauthorized',
};

const CERT_STATUS = { 0xa0: 'good', 0xa1: 'revoked', 0x82: 'unknown', 0xa2: 'unknown' };

/** DER time strings look like 231231235959Z (UTC) or 20231231235959Z. */
function parseAsn1Time(tag, bytes) {
  const text = bytes.toString('ascii');
  const m = tag === TAG.UTC_TIME
    ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$/.exec(text)
    : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$/.exec(text);
  if (!m) return undefined;
  const year = tag === TAG.UTC_TIME
    ? (Number(m[1]) >= 50 ? 1900 + Number(m[1]) : 2000 + Number(m[1]))
    : Number(m[1]);
  const date = new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]),
    Number(m[4]), Number(m[5]), Number(m[6] || 0)));
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/**
 * Reads the parts of a stapled OCSP response that matter: was the answer
 * usable, is the certificate good or revoked, and how fresh is it.
 */
export function parseOcspResponse(der) {
  try {
    const root = readTlv(der, 0);
    if (!root) return null;
    const parts = childrenOf(der, root);
    const statusTlv = parts[0];
    const status = statusTlv && statusTlv.length ? der[statusTlv.contentStart] : null;
    const out = {
      responseStatus: OCSP_RESPONSE_STATUS[status] || `status_${status}`,
      certStatus: undefined,
      thisUpdate: undefined,
      nextUpdate: undefined,
      bytes: der.length,
    };
    if (status !== 0) return out;

    // The certificate status is the first context-specific primitive inside a
    // SingleResponse; times follow it as GeneralizedTime values.
    const times = [];
    walk(der, tlv => {
      if (out.certStatus === undefined && CERT_STATUS[tlv.tag] !== undefined && tlv.length <= 32) {
        out.certStatus = CERT_STATUS[tlv.tag];
      }
      if (tlv.tag === TAG.GENERALIZED_TIME || tlv.tag === TAG.UTC_TIME) {
        const value = parseAsn1Time(tlv.tag, der.subarray(tlv.contentStart, tlv.end));
        if (value) times.push(value);
      }
    });
    // producedAt, thisUpdate, nextUpdate — in that order in a basic response.
    if (times.length >= 2) out.thisUpdate = times[1];
    if (times.length >= 3) out.nextUpdate = times[2];
    return out;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * Object identifiers
 * ------------------------------------------------------------------ */

export const OID = {
  keyUsage: '2.5.29.15',
  subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  crlDistributionPoints: '2.5.29.31',
  certificatePolicies: '2.5.29.32',
  authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
  extendedKeyUsage: '2.5.29.37',
  sct: '1.3.6.1.4.1.11129.2.4.2',
  mustStaple: '1.3.6.1.5.5.7.1.24',
  ocspNoCheck: '1.3.6.1.5.5.7.48.1.5',
};

/** Signature algorithm OIDs, named the way people expect to read them. */
export const SIGNATURE_OIDS = {
  '1.2.840.113549.1.1.4': { name: 'md5WithRSAEncryption', hash: 'MD5', key: 'RSA', weak: true },
  '1.2.840.113549.1.1.5': { name: 'sha1WithRSAEncryption', hash: 'SHA-1', key: 'RSA', weak: true },
  '1.2.840.113549.1.1.11': { name: 'sha256WithRSAEncryption', hash: 'SHA-256', key: 'RSA' },
  '1.2.840.113549.1.1.12': { name: 'sha384WithRSAEncryption', hash: 'SHA-384', key: 'RSA' },
  '1.2.840.113549.1.1.13': { name: 'sha512WithRSAEncryption', hash: 'SHA-512', key: 'RSA' },
  '1.2.840.113549.1.1.10': { name: 'rsassaPss', hash: 'PSS', key: 'RSA' },
  '1.2.840.10040.4.3': { name: 'dsaWithSha1', hash: 'SHA-1', key: 'DSA', weak: true },
  '2.16.840.1.101.3.4.3.2': { name: 'dsaWithSha256', hash: 'SHA-256', key: 'DSA' },
  '1.2.840.10045.4.1': { name: 'ecdsaWithSha1', hash: 'SHA-1', key: 'EC', weak: true },
  '1.2.840.10045.4.3.2': { name: 'ecdsaWithSha256', hash: 'SHA-256', key: 'EC' },
  '1.2.840.10045.4.3.3': { name: 'ecdsaWithSha384', hash: 'SHA-384', key: 'EC' },
  '1.2.840.10045.4.3.4': { name: 'ecdsaWithSha512', hash: 'SHA-512', key: 'EC' },
  '1.3.101.112': { name: 'ed25519', hash: 'SHA-512', key: 'Ed25519' },
  '1.3.101.113': { name: 'ed448', hash: 'SHAKE256', key: 'Ed448' },
  '1.2.643.7.1.1.3.2': { name: 'GOST R 34.10-2012 (256)', hash: 'Streebog', key: 'GOST' },
  '1.2.643.7.1.1.3.3': { name: 'GOST R 34.10-2012 (512)', hash: 'Streebog', key: 'GOST' },
};

/** CA/Browser Forum validation levels. */
export const POLICY_OIDS = {
  '2.23.140.1.1': 'EV',
  '2.23.140.1.2.1': 'DV',
  '2.23.140.1.2.2': 'OV',
  '2.23.140.1.2.3': 'IV',
  '2.23.140.1.3': 'EV code signing',
};

/** Extended key usage OIDs. */
export const EKU_OIDS = {
  '1.3.6.1.5.5.7.3.1': 'TLS server',
  '1.3.6.1.5.5.7.3.2': 'TLS client',
  '1.3.6.1.5.5.7.3.3': 'code signing',
  '1.3.6.1.5.5.7.3.4': 'e-mail protection',
  '1.3.6.1.5.5.7.3.8': 'timestamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP signing',
};

const KEY_USAGE_BITS = [
  'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
  'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly',
];

/** KeyUsage is a BIT STRING; this turns it into readable names. */
export function decodeKeyUsage(value) {
  const tlv = readTlv(value, 0);
  if (!tlv || tlv.tag !== TAG.BIT_STRING) return [];
  const bytes = value.subarray(tlv.contentStart + 1, tlv.end); // skip unused-bits count
  const names = [];
  for (let bit = 0; bit < KEY_USAGE_BITS.length; bit++) {
    const byte = bytes[bit >> 3];
    if (byte !== undefined && (byte & (0x80 >> (bit & 7)))) names.push(KEY_USAGE_BITS[bit]);
  }
  return names;
}

/**
 * Counts the signed certificate timestamps embedded in a certificate.
 * The extension holds an opaque list: 2-byte total length, then 2-byte
 * length-prefixed entries.
 */
export function countSct(value) {
  const outer = readTlv(value, 0);
  if (!outer || outer.tag !== TAG.OCTET_STRING) return 0;
  const list = value.subarray(outer.contentStart, outer.end);
  if (list.length < 2) return 0;
  const total = list.readUInt16BE(0);
  let i = 2;
  let count = 0;
  while (i + 2 <= Math.min(2 + total, list.length)) {
    const length = list.readUInt16BE(i);
    i += 2 + length;
    count++;
    if (count > 64) break;
  }
  return count;
}
