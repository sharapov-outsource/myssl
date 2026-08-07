/**
 * A hand-written TLS client that only ever gets as far as the server's first
 * flight of messages.
 *
 * Node's own `tls` module cannot answer the questions this service asks: it
 * will not offer a single cipher suite of our choosing, it hides SSL 3.0
 * entirely, it cannot speak TLS 1.3 cipher-suite-by-cipher-suite, and it never
 * shows the raw certificate chain exactly as the server sent it. So the
 * ClientHello is assembled by hand, written to a plain TCP socket, and the
 * server's answer is parsed up to ServerHelloDone (TLS 1.2 and below) or up to
 * ServerHello (TLS 1.3, where everything after it is already encrypted).
 *
 * Nothing here completes a handshake: no keys are derived and no application
 * data is ever sent. Each probe is one TCP connection that is closed as soon as
 * the interesting bytes have arrived.
 */

import net from 'node:net';
import crypto from 'node:crypto';

import { describeSuite } from './suites.js';
import { pace } from './pace.js';

/* ------------------------------------------------------------------ *
 * Constants
 * ------------------------------------------------------------------ */

export const VERSIONS = {
  'SSL 3.0': 0x0300,
  'TLS 1.0': 0x0301,
  'TLS 1.1': 0x0302,
  'TLS 1.2': 0x0303,
  'TLS 1.3': 0x0304,
};

export const VERSION_NAMES = Object.fromEntries(
  Object.entries(VERSIONS).map(([name, code]) => [code, name])
);

/** Order matters: oldest first, so reports read chronologically. */
export const VERSION_ORDER = ['SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'];

export const NAMED_GROUPS = {
  1: 'sect163k1', 2: 'sect163r1', 3: 'sect163r2', 4: 'sect193r1', 5: 'sect193r2',
  6: 'sect233k1', 7: 'sect233r1', 8: 'sect239k1', 9: 'sect283k1', 10: 'sect283r1',
  11: 'sect409k1', 12: 'sect409r1', 13: 'sect571k1', 14: 'sect571r1',
  15: 'secp160k1', 16: 'secp160r1', 17: 'secp160r2', 18: 'secp192k1', 19: 'secp192r1',
  20: 'secp224k1', 21: 'secp224r1', 22: 'secp256k1',
  23: 'secp256r1', 24: 'secp384r1', 25: 'secp521r1',
  26: 'brainpoolP256r1', 27: 'brainpoolP384r1', 28: 'brainpoolP512r1',
  29: 'x25519', 30: 'x448',
  256: 'ffdhe2048', 257: 'ffdhe3072', 258: 'ffdhe4096', 259: 'ffdhe6144', 260: 'ffdhe8192',
  4587: 'SecP256r1MLKEM768', 4588: 'X25519MLKEM768', 25497: 'X25519Kyber768Draft00',
};

/** Equivalent symmetric strength, used by the rating. */
export const GROUP_BITS = {
  secp256r1: 128, secp384r1: 192, secp521r1: 256,
  x25519: 128, x448: 224,
  brainpoolP256r1: 128, brainpoolP384r1: 192, brainpoolP512r1: 256,
  secp224r1: 112, secp224k1: 112, secp192r1: 96, secp192k1: 96, secp160k1: 80,
  secp160r1: 80, secp160r2: 80, secp256k1: 128,
  ffdhe2048: 112, ffdhe3072: 128, ffdhe4096: 152, ffdhe6144: 176, ffdhe8192: 200,
  X25519MLKEM768: 128, SecP256r1MLKEM768: 128, X25519Kyber768Draft00: 128,
};

/** Groups worth offering, in the order modern clients prefer them. */
export const PROBE_GROUPS = [4588, 29, 23, 24, 25, 30, 256, 257, 258, 259, 260, 26, 27, 28, 22, 21, 19];

/** Groups a real key share can be generated for; everything else gets filler. */
const KEY_SHARE_CURVES = {
  23: { type: 'ec', curve: 'prime256v1' },
  24: { type: 'ec', curve: 'secp384r1' },
  25: { type: 'ec', curve: 'secp521r1' },
  29: { type: 'x25519' },
  30: { type: 'x448' },
};

/** Length in bytes of a finite-field key share, so filler is the right size. */
const FFDHE_SIZES = { 256: 256, 257: 384, 258: 512, 259: 768, 260: 1024 };

export const SIG_ALGS = {
  0x0401: 'rsa_pkcs1_sha256', 0x0501: 'rsa_pkcs1_sha384', 0x0601: 'rsa_pkcs1_sha512',
  0x0403: 'ecdsa_secp256r1_sha256', 0x0503: 'ecdsa_secp384r1_sha384', 0x0603: 'ecdsa_secp521r1_sha512',
  0x0804: 'rsa_pss_rsae_sha256', 0x0805: 'rsa_pss_rsae_sha384', 0x0806: 'rsa_pss_rsae_sha512',
  0x0807: 'ed25519', 0x0808: 'ed448',
  0x0809: 'rsa_pss_pss_sha256', 0x080a: 'rsa_pss_pss_sha384', 0x080b: 'rsa_pss_pss_sha512',
  0x0201: 'rsa_pkcs1_sha1', 0x0203: 'ecdsa_sha1', 0x0202: 'dsa_sha1',
  0x0402: 'dsa_sha256', 0x0502: 'dsa_sha384', 0x0602: 'dsa_sha512',
};

const DEFAULT_SIG_ALGS = [
  0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
  0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b,
  0x0401, 0x0501, 0x0601, 0x0201, 0x0203, 0x0202, 0x0402,
];

export const ALERTS = {
  0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac', 21: 'decryption_failed',
  22: 'record_overflow', 30: 'decompression_failure', 40: 'handshake_failure',
  41: 'no_certificate', 42: 'bad_certificate', 43: 'unsupported_certificate',
  44: 'certificate_revoked', 45: 'certificate_expired', 46: 'certificate_unknown',
  47: 'illegal_parameter', 48: 'unknown_ca', 49: 'access_denied', 50: 'decode_error',
  51: 'decrypt_error', 60: 'export_restriction', 70: 'protocol_version',
  71: 'insufficient_security', 80: 'internal_error', 86: 'inappropriate_fallback',
  90: 'user_canceled', 100: 'no_renegotiation', 109: 'missing_extension',
  110: 'unsupported_extension', 112: 'unrecognized_name',
  113: 'bad_certificate_status_response', 115: 'unknown_psk_identity',
  116: 'certificate_required', 120: 'no_application_protocol',
};

const EXT = {
  serverName: 0x0000, statusRequest: 0x0005, supportedGroups: 0x000a,
  ecPointFormats: 0x000b, signatureAlgorithms: 0x000d, heartbeat: 0x000f,
  alpn: 0x0010, sct: 0x0012, encryptThenMac: 0x0016, extendedMasterSecret: 0x0017,
  sessionTicket: 0x0023, supportedVersions: 0x002b, pskKeyExchangeModes: 0x002d,
  keyShare: 0x0033, renegotiationInfo: 0xff01,
};

/** SHA-256("HelloRetryRequest") — the random value that marks an HRR. */
const HRR_RANDOM = Buffer.from(
  'CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C', 'hex');

const RECORD_HANDSHAKE = 22;
const RECORD_ALERT = 21;
const RECORD_CCS = 20;

/* ------------------------------------------------------------------ *
 * Byte helpers
 * ------------------------------------------------------------------ */

const u8 = v => Buffer.from([v & 0xff]);
const u16 = v => Buffer.from([(v >> 8) & 0xff, v & 0xff]);
const u24 = v => Buffer.from([(v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);

/** Prefixes `body` with its length, written in `lenBytes` bytes. */
function vec(lenBytes, body) {
  const len = lenBytes === 1 ? u8(body.length) : lenBytes === 2 ? u16(body.length) : u24(body.length);
  return Buffer.concat([len, body]);
}

const u16list = values => Buffer.concat(values.map(u16));

/* ------------------------------------------------------------------ *
 * Building the ClientHello
 * ------------------------------------------------------------------ */

function extension(type, body) {
  return Buffer.concat([u16(type), vec(2, body)]);
}

function serverNameExtension(name) {
  // Literal addresses must not appear in SNI, and an empty name is illegal.
  if (!name || net.isIP(name)) return null;
  const entry = Buffer.concat([u8(0), vec(2, Buffer.from(name, 'ascii'))]);
  return extension(EXT.serverName, vec(2, entry));
}

function alpnExtension(protocols) {
  if (!protocols?.length) return null;
  const list = Buffer.concat(protocols.map(p => vec(1, Buffer.from(p, 'ascii'))));
  return extension(EXT.alpn, vec(2, list));
}

/** A key share the server can actually use, or filler of the right length. */
function keyShareEntry(group) {
  const spec = KEY_SHARE_CURVES[group];
  if (spec) {
    let publicKey;
    if (spec.type === 'ec') {
      const ecdh = crypto.createECDH(spec.curve);
      ecdh.generateKeys();
      publicKey = ecdh.getPublicKey();
    } else {
      const { publicKey: key } = crypto.generateKeyPairSync(spec.type);
      // Strip the SPKI wrapper: the raw 32/56-byte point is the last part of it.
      const der = key.export({ type: 'spki', format: 'der' });
      publicKey = der.subarray(der.length - (spec.type === 'x25519' ? 32 : 56));
    }
    return Buffer.concat([u16(group), vec(2, publicKey)]);
  }
  const size = FFDHE_SIZES[group];
  if (!size) return null;
  // A finite-field share is only checked for range, and a random value below
  // the modulus is overwhelmingly likely: the top byte is kept small.
  const filler = crypto.randomBytes(size);
  filler[0] &= 0x7f;
  return Buffer.concat([u16(group), vec(2, filler)]);
}

/**
 * @param {object} o
 * @param {string} o.version        highest version to offer
 * @param {number[]} o.ciphers      suite ids, in the order they are offered
 * @param {string} [o.servername]   SNI, omitted when empty
 * @param {number[]} [o.groups]     supported_groups
 * @param {number[]} [o.keyShares]  groups to send a key share for (TLS 1.3)
 * @param {number[]} [o.sigAlgs]
 * @param {string[]} [o.alpn]
 * @param {number[]} [o.compression] compression methods, [0] = none
 * @param {boolean} [o.fallbackScsv] add TLS_FALLBACK_SCSV
 * @param {boolean} [o.heartbeat]    advertise the heartbeat extension
 * @param {boolean} [o.bare]         no extensions at all (ancient-client mode)
 */
export function buildClientHello(o) {
  const versionCode = VERSIONS[o.version];
  const isTls13 = o.version === 'TLS 1.3';
  const legacyVersion = isTls13 ? VERSIONS['TLS 1.2'] : versionCode;

  const ciphers = [...o.ciphers];
  if (o.fallbackScsv) ciphers.push(0x5600);
  if (!o.bare) ciphers.push(0x00ff); // renegotiation_info as an SCSV, for old servers

  const body = [
    u16(legacyVersion),
    crypto.randomBytes(32),
    // A non-empty session id keeps TLS 1.3 handshakes looking like TLS 1.2 to
    // middleboxes; SSL 3.0 predates that trick and gets an empty one.
    vec(1, o.version === 'SSL 3.0' ? Buffer.alloc(0) : crypto.randomBytes(32)),
    vec(2, u16list(ciphers)),
    vec(1, Buffer.from(o.compression || [0])),
  ];

  if (!o.bare) {
    const groups = o.groups || PROBE_GROUPS;
    const extensions = [
      serverNameExtension(o.servername),
      extension(EXT.renegotiationInfo, vec(1, Buffer.alloc(0))),
      extension(EXT.supportedGroups, vec(2, u16list(groups))),
      extension(EXT.ecPointFormats, vec(1, Buffer.from([0]))),
      extension(EXT.sessionTicket, Buffer.alloc(0)),
      extension(EXT.statusRequest, Buffer.concat([u8(1), u16(0), u16(0)])),
      extension(EXT.sct, Buffer.alloc(0)),
      extension(EXT.extendedMasterSecret, Buffer.alloc(0)),
      extension(EXT.encryptThenMac, Buffer.alloc(0)),
      alpnExtension(o.alpn),
      o.heartbeat ? extension(EXT.heartbeat, u8(1)) : null,
    ];

    if (o.version !== 'SSL 3.0') {
      extensions.push(extension(EXT.signatureAlgorithms, vec(2, u16list(o.sigAlgs || DEFAULT_SIG_ALGS))));
    }

    if (isTls13) {
      extensions.push(extension(EXT.supportedVersions, vec(1, u16list([VERSIONS['TLS 1.3']]))));
      extensions.push(extension(EXT.pskKeyExchangeModes, vec(1, Buffer.from([1]))));
      const shares = (o.keyShares ?? [29]).map(keyShareEntry).filter(Boolean);
      extensions.push(extension(EXT.keyShare, vec(2, Buffer.concat(shares))));
    }

    const present = extensions.filter(Boolean);
    if (present.length) body.push(vec(2, Buffer.concat(present)));
  }

  const handshake = Buffer.concat([u8(1), vec(3, Buffer.concat(body))]);
  // The record version stays low: some old servers reject anything higher.
  const recordVersion = o.version === 'SSL 3.0' ? VERSIONS['SSL 3.0'] : VERSIONS['TLS 1.0'];
  return Buffer.concat([u8(RECORD_HANDSHAKE), u16(recordVersion), vec(2, handshake)]);
}

/* ------------------------------------------------------------------ *
 * Parsing the server's answer
 * ------------------------------------------------------------------ */

function parseExtensions(buf) {
  const out = new Map();
  let i = 0;
  while (i + 4 <= buf.length) {
    const type = buf.readUInt16BE(i);
    const len = buf.readUInt16BE(i + 2);
    if (i + 4 + len > buf.length) break;
    out.set(type, buf.subarray(i + 4, i + 4 + len));
    i += 4 + len;
  }
  return out;
}

function parseServerHello(body) {
  if (body.length < 38) return null;
  const legacyVersion = body.readUInt16BE(0);
  const random = body.subarray(2, 34);
  const sessionIdLen = body[34];
  let i = 35 + sessionIdLen;
  if (body.length < i + 3) return null;
  const cipher = body.readUInt16BE(i);
  const compression = body[i + 2];
  i += 3;

  let extensions = new Map();
  if (body.length >= i + 2) {
    const extLen = body.readUInt16BE(i);
    extensions = parseExtensions(body.subarray(i + 2, i + 2 + extLen));
  }

  const supported = extensions.get(EXT.supportedVersions);
  const version = supported?.length >= 2 ? supported.readUInt16BE(0) : legacyVersion;

  return {
    version, legacyVersion, cipher, compression, extensions,
    helloRetryRequest: random.equals(HRR_RANDOM),
    sessionId: body.subarray(35, 35 + sessionIdLen),
  };
}

/** Certificate message: a list of DER blobs, each with a 3-byte length. */
function parseCertificates(body, tls13) {
  let i = 0;
  if (tls13) i += 1 + body[0];             // certificate_request_context
  if (body.length < i + 3) return [];
  const total = body.readUIntBE(i, 3);
  i += 3;
  const end = Math.min(i + total, body.length);
  const certs = [];
  while (i + 3 <= end) {
    const len = body.readUIntBE(i, 3);
    i += 3;
    if (i + len > end) break;
    certs.push(Buffer.from(body.subarray(i, i + len)));
    i += len;
    if (tls13) {                            // each entry carries its own extensions
      if (i + 2 > end) break;
      i += 2 + body.readUInt16BE(i);
    }
  }
  return certs;
}

/**
 * ServerKeyExchange: the shape depends on the key exchange of the negotiated
 * suite. Only the public parameters are read — that is where the DH modulus
 * size and the chosen curve live.
 */
function parseServerKeyExchange(body, cipherId, version) {
  const kx = describeSuite(cipherId).keyExchange;
  const out = {};
  let offset = -1;
  try {
    if (kx === 'ECDHE' || kx === 'ECDH') {
      if (body[0] !== 3) return { curveType: body[0] };   // explicit curves, effectively extinct
      out.groupId = body.readUInt16BE(1);
      out.group = NAMED_GROUPS[out.groupId] || `unknown(${out.groupId})`;
      const pubLen = body[3];
      out.publicKeyBytes = pubLen;
      offset = 4 + pubLen;
    } else if (kx === 'DHE' || kx === 'DH') {
      const pLen = body.readUInt16BE(0);
      const p = body.subarray(2, 2 + pLen);
      let lead = 0;
      while (lead < p.length && p[lead] === 0) lead++;
      out.dhBits = (p.length - lead) * 8;
      // A well-known modulus is worth naming: reuse means a precomputation
      // attack against it is shared with every other server using it.
      out.dhPrimeFingerprint = crypto.createHash('sha256')
        .update(p.subarray(lead)).digest('hex').slice(0, 16);
      let i = 2 + pLen;
      i += 2 + body.readUInt16BE(i);        // g
      i += 2 + body.readUInt16BE(i);        // Ys
      offset = i;
    } else {
      return out;
    }

    // TLS 1.2 signs with an explicit algorithm; earlier versions do not name it.
    if (version >= VERSIONS['TLS 1.2'] && offset >= 0 && body.length >= offset + 2) {
      const code = body.readUInt16BE(offset);
      out.signatureAlgorithm = SIG_ALGS[code] || `unknown(0x${code.toString(16)})`;
    }
  } catch { /* truncated or unexpected shape — report what was parsed */ }
  return out;
}

/* ------------------------------------------------------------------ *
 * One probe = one TCP connection
 * ------------------------------------------------------------------ */

const MAX_RESPONSE = 512 * 1024;

/**
 * Sends one ClientHello and reads the server's first flight.
 *
 * Never throws: transport problems come back as `{ ok: false, error }`.
 */
export async function probe(opts) {
  const {
    host, ip, port = 443, timeout = 8000, collect = 'full',
  } = opts;

  // Wait for this probe's turn before touching the network.
  await pace();

  return new Promise(resolve => {
    const started = Date.now();
    const result = {
      ok: false, error: null, alert: null,
      version: null, versionName: null, cipher: null, compression: null,
      helloRetryRequest: false, selectedGroup: null,
      certificates: [], ocspResponse: null, clientCertRequested: false,
      keyExchange: {}, extensions: {}, alpn: null, elapsedMs: 0,
    };

    let settled = false;
    let received = Buffer.alloc(0);
    let handshakeBytes = Buffer.alloc(0);
    let sawServerHello = false;

    const socket = net.connect({ host: ip || host, port, allowHalfOpen: false });
    socket.setNoDelay(true);

    const timer = setTimeout(() => finish('timeout'), timeout);

    function finish(error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      if (error && !result.ok && !result.alert) result.error = error;
      result.elapsedMs = Date.now() - started;
      resolve(result);
    }

    socket.on('error', err => finish(err.code || err.message));
    socket.on('close', () => finish('closed'));

    socket.on('connect', () => {
      try {
        socket.write(buildClientHello(opts));
      } catch (err) {
        finish('hello-build: ' + err.message);
      }
    });

    socket.on('data', chunk => {
      received = Buffer.concat([received, chunk]);
      if (received.length > MAX_RESPONSE) return finish('response-too-large');
      try {
        pump();
      } catch (err) {
        finish('parse: ' + err.message);
      }
    });

    /** Splits the stream into records, then into handshake messages. */
    function pump() {
      while (received.length >= 5) {
        const type = received[0];
        const len = received.readUInt16BE(3);
        if (len > 0x4800) return finish('bad-record-length');
        if (received.length < 5 + len) return;
        const payload = received.subarray(5, 5 + len);
        received = received.subarray(5 + len);

        if (type === RECORD_ALERT) {
          if (payload.length >= 2) {
            const [level, description] = payload;
            // A warning about an unknown SNI is not the end of the handshake.
            if (level === 1 && description !== 0) continue;
            result.alert = { level, description, name: ALERTS[description] || `alert_${description}` };
          }
          return finish(null);
        }
        if (type === RECORD_CCS) continue;            // TLS 1.3 middlebox compatibility
        if (type === RECORD_HANDSHAKE) {
          handshakeBytes = Buffer.concat([handshakeBytes, payload]);
          if (readMessages()) return;
          continue;
        }
        // Anything else means this is not a TLS server at all.
        result.error = 'not-tls';
        return finish(null);
      }
    }

    /** @returns true when the probe is finished. */
    function readMessages() {
      while (handshakeBytes.length >= 4) {
        const msgType = handshakeBytes[0];
        const msgLen = handshakeBytes.readUIntBE(1, 3);
        if (handshakeBytes.length < 4 + msgLen) return false;
        const body = handshakeBytes.subarray(4, 4 + msgLen);
        handshakeBytes = handshakeBytes.subarray(4 + msgLen);

        switch (msgType) {
          case 2: {                                   // ServerHello
            const hello = parseServerHello(body);
            if (!hello) { result.error = 'bad-server-hello'; finish(null); return true; }
            sawServerHello = true;
            result.ok = true;
            result.version = hello.version;
            result.versionName = VERSION_NAMES[hello.version] || `0x${hello.version.toString(16)}`;
            result.cipher = hello.cipher;
            result.compression = hello.compression;
            result.sessionIdLength = hello.sessionId.length;
            result.helloRetryRequest = hello.helloRetryRequest;
            readServerExtensions(hello.extensions);

            const tls13 = hello.version === VERSIONS['TLS 1.3'];
            // After a TLS 1.3 ServerHello everything is encrypted, and an HRR
            // ends the flight in every version — there is nothing more to read.
            if (tls13 || hello.helloRetryRequest || collect === 'hello') { finish(null); return true; }
            break;
          }
          case 11:                                    // Certificate
            result.certificates = parseCertificates(body, false);
            break;
          case 12:                                    // ServerKeyExchange
            result.keyExchange = parseServerKeyExchange(body, result.cipher, result.version);
            break;
          case 13:                                    // CertificateRequest
            result.clientCertRequested = true;
            break;
          case 22:                                    // CertificateStatus (stapled OCSP)
            if (body[0] === 1 && body.length > 4) {
              result.ocspResponse = Buffer.from(body.subarray(4, 4 + body.readUIntBE(1, 3)));
            }
            break;
          case 14:                                    // ServerHelloDone
            finish(null);
            return true;
          default:
            break;
        }
      }
      return false;
    }

    function readServerExtensions(extensions) {
      const has = id => extensions.has(id);
      result.extensions = {
        secureRenegotiation: has(EXT.renegotiationInfo),
        extendedMasterSecret: has(EXT.extendedMasterSecret),
        encryptThenMac: has(EXT.encryptThenMac),
        sessionTicket: has(EXT.sessionTicket),
        heartbeat: has(EXT.heartbeat),
        ocspStapling: has(EXT.statusRequest),
        sct: has(EXT.sct),
        ecPointFormats: has(EXT.ecPointFormats),
      };

      const alpn = extensions.get(EXT.alpn);
      if (alpn && alpn.length >= 3) {
        result.alpn = alpn.subarray(3, 3 + alpn[2]).toString('ascii');
      }

      const keyShare = extensions.get(EXT.keyShare);
      if (keyShare && keyShare.length >= 2) {
        result.selectedGroupId = keyShare.readUInt16BE(0);
        result.selectedGroup = NAMED_GROUPS[result.selectedGroupId] || `unknown(${result.selectedGroupId})`;
      }
    }

    socket.on('end', () => {
      if (!settled && !sawServerHello && !result.alert) finish('connection-closed-early');
    });
  });
}

/* ------------------------------------------------------------------ *
 * SSL 2.0
 * ------------------------------------------------------------------ */

const SSL2_CIPHERS = [0x010080, 0x020080, 0x030080, 0x040080, 0x050080, 0x060040, 0x0700c0];

/**
 * SSL 2.0 has a different record format, so it needs its own probe. Support for
 * it is what makes a server vulnerable to DROWN, which is why it is still worth
 * asking twenty-odd years after the protocol was withdrawn.
 */
export async function probeSsl2({ host, ip, port = 443, timeout = 6000 }) {
  await pace();
  return new Promise(resolve => {
    const specs = Buffer.concat(SSL2_CIPHERS.map(c => Buffer.from([c >> 16 & 0xff, c >> 8 & 0xff, c & 0xff])));
    const challenge = crypto.randomBytes(16);
    const payload = Buffer.concat([
      u8(1), u16(0x0002),
      u16(specs.length), u16(0), u16(challenge.length),
      specs, challenge,
    ]);
    // The two-byte SSL 2.0 header carries the length with the high bit set.
    const record = Buffer.concat([u16(payload.length | 0x8000), payload]);

    let settled = false;
    let buf = Buffer.alloc(0);
    const socket = net.connect({ host: ip || host, port });
    const done = value => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      resolve(value);
    };
    const timer = setTimeout(() => done({ supported: false, reason: 'timeout' }), timeout);

    socket.on('error', err => done({ supported: false, reason: err.code || 'error' }));
    socket.on('close', () => done({ supported: false, reason: 'closed' }));
    socket.on('connect', () => socket.write(record));
    socket.on('data', chunk => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 3) return;
      // A modern server answers with a TLS alert record (0x15) or a handshake.
      if (buf[0] === 0x15 || buf[0] === 0x16) return done({ supported: false, reason: 'tls-response' });
      if ((buf[0] & 0x80) === 0) return done({ supported: false, reason: 'not-ssl2' });
      if (buf.length < 11) return;
      const msgType = buf[2];
      if (msgType !== 4) return done({ supported: false, reason: `msg-type-${msgType}` });
      const certLen = buf.readUInt16BE(7);
      const specLen = buf.readUInt16BE(9);
      const ciphers = [];
      const start = 13 + certLen;
      for (let i = start; i + 3 <= start + specLen && i + 3 <= buf.length; i += 3) {
        ciphers.push((buf[i] << 16) | (buf[i + 1] << 8) | buf[i + 2]);
      }
      done({ supported: true, ciphers });
    });
  });
}
