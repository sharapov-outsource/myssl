/**
 * Scanning strategies built on top of the raw prober.
 *
 * The trick behind every enumeration here is the same one sslscan and
 * testssl.sh use: a server picks exactly one suite (or one group) out of what
 * the client offers, so offering everything, removing whatever came back and
 * asking again eventually walks the whole list. Each round is one connection,
 * which is why every loop below has a hard ceiling on rounds.
 */

import {
  probe, VERSIONS, VERSION_ORDER, PROBE_GROUPS, NAMED_GROUPS,
} from './tls-probe.js';
import { describeSuite, allSuiteIds, TLS13_IDS } from './suites.js';

/** ClientHellos larger than this upset old load balancers. */
const CHUNK = 100;
/** Safety net: a broken server must not turn into an endless loop. */
const MAX_ROUNDS = 40;

/** Suites that make sense to offer for a given protocol version. */
export function suitesForVersion(version) {
  if (version === 'TLS 1.3') return [...TLS13_IDS];
  const legacy = allSuiteIds().filter(id => !TLS13_IDS.includes(id));
  if (version === 'TLS 1.2') return legacy;
  // Before TLS 1.2 there are no AEAD suites and no SHA-2 based MACs.
  return legacy.filter(id => {
    const d = describeSuite(id);
    return !d.aead && d.encryption !== 'CHACHA20' && (d.mac === 'SHA' || d.mac === 'MD5');
  });
}

/** Splits a list into chunks small enough for a comfortable ClientHello. */
function chunks(list, size = CHUNK) {
  const out = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}

/** Runs tasks with a ceiling on how many connections are open at once. */
export async function pooled(tasks, limit = 6) {
  const results = new Array(tasks.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, tasks.length) }, async () => {
    while (next < tasks.length) {
      const index = next++;
      results[index] = await tasks[index]();
    }
  });
  await Promise.all(workers);
  return results;
}

/* ------------------------------------------------------------------ *
 * Protocol versions
 * ------------------------------------------------------------------ */

/**
 * Asks for each version separately. A version counts as supported only when the
 * server answers with a ServerHello for that exact version — some servers
 * happily answer a TLS 1.1 request with a TLS 1.2 ServerHello, which means
 * TLS 1.1 is off.
 */
export async function detectProtocols(target) {
  const tasks = VERSION_ORDER.map(version => async () => {
    const result = await probe({
      ...target,
      version,
      ciphers: suitesForVersion(version),
      collect: 'hello',
    });
    // A HelloRetryRequest still means the version is supported — the server
    // only wants a key share for a different group than the one offered.
    const supported = result.ok && result.versionName === version;
    return {
      name: version,
      supported,
      // TLS 1.3 answers an unsupported-version hello with a plain alert; older
      // servers may simply drop the connection.
      reason: supported ? undefined : (result.alert?.name || result.error || 'no-server-hello'),
      cipher: supported ? result.cipher : undefined,
      probe: supported ? result : undefined,
    };
  });
  return pooled(tasks, VERSION_ORDER.length);
}

/* ------------------------------------------------------------------ *
 * Cipher suites
 * ------------------------------------------------------------------ */

/**
 * Walks every suite the server accepts for one protocol version.
 * Returns them in the order the server chose them, which is meaningful when
 * the server enforces its own preference.
 */
export async function enumerateCiphers(target, version) {
  const accepted = [];
  const seen = new Set();
  let connections = 0;

  for (const chunk of chunks(suitesForVersion(version))) {
    let remaining = chunk;
    for (let round = 0; round < MAX_ROUNDS && remaining.length; round++) {
      const result = await probe({ ...target, version, ciphers: remaining, collect: 'hello' });
      connections++;
      if (!result.ok || result.versionName !== version) break;

      const picked = result.cipher;
      // A server that answers with something it was not offered is broken;
      // recording it once and stopping keeps the loop finite.
      if (!remaining.includes(picked)) {
        if (!seen.has(picked)) { accepted.push(picked); seen.add(picked); }
        break;
      }
      if (!seen.has(picked)) { accepted.push(picked); seen.add(picked); }
      remaining = remaining.filter(id => id !== picked);
    }
  }

  return { version, ciphers: accepted, connections };
}

/**
 * Does the server impose its own suite order, or does it take the client's
 * first acceptable one? Offering the same set in two opposite orders answers
 * it: a server with a preference picks the same suite both times.
 */
export async function detectCipherOrder(target, version, ciphers) {
  if (!ciphers || ciphers.length < 2) return 'unknown';
  const forward = ciphers.slice(0, CHUNK);
  const backward = [...forward].reverse();

  const [a, b] = await Promise.all([
    probe({ ...target, version, ciphers: forward, collect: 'hello' }),
    probe({ ...target, version, ciphers: backward, collect: 'hello' }),
  ]);
  if (!a.ok || !b.ok) return 'unknown';
  if (a.cipher === b.cipher) return 'server';
  if (a.cipher === forward[0] && b.cipher === backward[0]) return 'client';
  return 'unknown';
}

/* ------------------------------------------------------------------ *
 * Key exchange
 * ------------------------------------------------------------------ */

/**
 * TLS 1.3: sending no key share at all forces the server to name its preferred
 * group in a HelloRetryRequest. Dropping that group and asking again walks the
 * whole list in the server's own order of preference.
 */
async function enumerateGroups13(target) {
  const found = [];
  let remaining = [...PROBE_GROUPS];

  for (let round = 0; round < 16 && remaining.length; round++) {
    const result = await probe({
      ...target, version: 'TLS 1.3', ciphers: TLS13_IDS,
      groups: remaining, keyShares: [], collect: 'hello',
    });
    if (!result.ok) break;
    const id = result.selectedGroupId;
    if (!id || !remaining.includes(id)) break;
    found.push({ id, name: NAMED_GROUPS[id] || `unknown(${id})` });
    remaining = remaining.filter(g => g !== id);
  }
  return found;
}

/** TLS 1.2 and below: the chosen curve is named in ServerKeyExchange. */
async function enumerateGroups12(target, version) {
  const ecdhe = suitesForVersion(version).filter(id => describeSuite(id).keyExchange === 'ECDHE');
  if (!ecdhe.length) return [];

  const found = [];
  let remaining = [...PROBE_GROUPS].filter(g => g < 256 || g > 260);

  for (let round = 0; round < 16 && remaining.length; round++) {
    const result = await probe({ ...target, version, ciphers: ecdhe, groups: remaining });
    if (!result.ok || !result.keyExchange?.groupId) break;
    const id = result.keyExchange.groupId;
    if (!remaining.includes(id)) break;
    found.push({ id, name: NAMED_GROUPS[id] || `unknown(${id})` });
    remaining = remaining.filter(g => g !== id);
  }
  return found;
}

export async function enumerateGroups(target, versions) {
  if (versions.includes('TLS 1.3')) return enumerateGroups13(target);
  for (const version of ['TLS 1.2', 'TLS 1.1', 'TLS 1.0']) {
    if (versions.includes(version)) return enumerateGroups12(target, version);
  }
  return [];
}

/**
 * Finite-field Diffie-Hellman: the modulus travels in ServerKeyExchange, so its
 * size — the thing Logjam is about — can simply be read off.
 */
export async function detectDhParams(target, versions) {
  for (const version of ['TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0']) {
    if (!versions.includes(version)) continue;
    const dhe = suitesForVersion(version).filter(id => {
      const kx = describeSuite(id).keyExchange;
      return kx === 'DHE' || kx === 'DH';
    });
    if (!dhe.length) continue;

    const result = await probe({ ...target, version, ciphers: dhe });
    if (result.ok && result.keyExchange?.dhBits) {
      return {
        bits: result.keyExchange.dhBits,
        primeFingerprint: result.keyExchange.dhPrimeFingerprint,
        version,
        cipher: result.cipher,
      };
    }
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * Individual features
 * ------------------------------------------------------------------ */

/**
 * TLS_FALLBACK_SCSV: pretend to be a client that has already given up on the
 * server's best version. A server that understands the signal answers with an
 * inappropriate_fallback alert instead of quietly accepting the downgrade.
 */
export async function checkFallbackScsv(target, supported) {
  const versions = VERSION_ORDER.filter(v => supported.includes(v));
  if (versions.length < 2) return { supported: null, reason: 'single-protocol' };

  const lower = versions[versions.length - 2];
  const result = await probe({
    ...target, version: lower, ciphers: suitesForVersion(lower),
    fallbackScsv: true, collect: 'hello',
  });
  if (result.alert?.description === 86) return { supported: true };
  if (result.ok) return { supported: false, negotiated: result.versionName };
  return { supported: null, reason: result.alert?.name || result.error };
}

/**
 * TLS-level compression is what CRIME abuses. Offering DEFLATE and seeing
 * whether the server selects it is the whole test.
 */
export async function checkCompression(target, versions) {
  const version = ['TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0'].find(v => versions.includes(v));
  if (!version) return { supported: false, reason: 'tls13-only' };

  const result = await probe({
    ...target, version, ciphers: suitesForVersion(version),
    compression: [1, 0], collect: 'hello',
  });
  if (!result.ok) return { supported: null, reason: result.alert?.name || result.error };
  return { supported: result.compression === 1 };
}

/**
 * The heartbeat extension is the one Heartbleed lives in. This only checks
 * whether the server advertises it — no malformed heartbeat is ever sent, so
 * the server is never actually attacked.
 */
export async function checkHeartbeat(target, versions) {
  const version = ['TLS 1.2', 'TLS 1.1', 'TLS 1.0'].find(v => versions.includes(v));
  if (!version) return { advertised: false, reason: 'tls13-only' };

  const result = await probe({
    ...target, version, ciphers: suitesForVersion(version),
    heartbeat: true, collect: 'hello',
  });
  if (!result.ok) return { advertised: null, reason: result.alert?.name || result.error };
  return { advertised: Boolean(result.extensions.heartbeat) };
}

/** Does the server insist on SNI, and does it serve a different site without it? */
export async function checkWithoutSni(target, versions) {
  const version = versions.includes('TLS 1.3') ? 'TLS 1.3'
    : ['TLS 1.2', 'TLS 1.1', 'TLS 1.0'].find(v => versions.includes(v));
  if (!version) return null;

  const result = await probe({
    ...target, servername: null, version, ciphers: suitesForVersion(version),
  });
  return {
    handshake: result.ok,
    alert: result.alert?.name,
    certificates: result.certificates,
  };
}

/* ------------------------------------------------------------------ *
 * Handshake simulation
 * ------------------------------------------------------------------ */

const MODERN_GROUPS = [29, 23, 24, 25];
const LEGACY_GROUPS = [23, 24, 25];

/**
 * Approximations of what well-known clients offer. They are close enough to
 * answer the question people actually ask — "can this client still connect?" —
 * without pretending to be a byte-exact replica of each stack.
 */
export const CLIENTS = [
  {
    name: 'Chrome 131', platform: 'Win 11', version: 'TLS 1.3', groups: [4588, 29, 23, 24],
    ciphers: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
  },
  {
    name: 'Firefox 133', platform: 'Win 11', version: 'TLS 1.3', groups: [4588, 29, 23, 24, 25, 256, 257],
    ciphers: [0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a],
  },
  {
    name: 'Safari 18', platform: 'macOS 15', version: 'TLS 1.3', groups: [29, 23, 24, 25],
    ciphers: [0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a],
  },
  {
    name: 'Edge 131', platform: 'Win 11', version: 'TLS 1.3', groups: [4588, 29, 23, 24],
    ciphers: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
  },
  {
    name: 'Android 13', platform: 'Chrome', version: 'TLS 1.3', groups: MODERN_GROUPS,
    ciphers: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
  },
  {
    name: 'iOS 18', platform: 'Safari', version: 'TLS 1.3', groups: MODERN_GROUPS,
    ciphers: [0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f],
  },
  {
    name: 'OpenSSL 3.4', platform: 'CLI', version: 'TLS 1.3', groups: [29, 23, 24, 25, 256, 257, 258],
    ciphers: [0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0x009f, 0x009e, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a],
  },
  {
    name: 'Java 17', platform: 'JVM', version: 'TLS 1.3', groups: MODERN_GROUPS,
    ciphers: [0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f],
  },
  {
    name: 'Java 8u382', platform: 'JVM', version: 'TLS 1.2', groups: LEGACY_GROUPS,
    ciphers: [0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a],
  },
  {
    name: 'Python 3.12', platform: 'requests', version: 'TLS 1.3', groups: MODERN_GROUPS,
    ciphers: [0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f],
  },
  {
    name: 'Android 5.0', platform: 'legacy', version: 'TLS 1.2', groups: LEGACY_GROUPS,
    ciphers: [0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0x000a, 0xc007, 0xc011, 0x0005],
  },
  {
    name: 'Windows 7 / IE 11', platform: 'Schannel', version: 'TLS 1.2', groups: LEGACY_GROUPS,
    ciphers: [0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a, 0xc02c, 0xc02b],
  },
  {
    name: 'Windows XP / IE 8', platform: 'Schannel', version: 'TLS 1.0', groups: LEGACY_GROUPS, bare: true,
    ciphers: [0x0004, 0x0005, 0x000a, 0x0009, 0x0064, 0x0062, 0x0003, 0x0006, 0x0013, 0x0012, 0x0063],
  },
];

/** Runs every client profile and reports what each one would end up with. */
export async function simulateClients(target) {
  const tasks = CLIENTS.map(client => async () => {
    const result = await probe({
      ...target,
      version: client.version,
      ciphers: client.ciphers,
      groups: client.groups,
      keyShares: client.version === 'TLS 1.3' ? [client.groups.includes(29) ? 29 : 23] : undefined,
      bare: client.bare,
      alpn: ['h2', 'http/1.1'],
      collect: 'hello',
    });

    // A client that offers TLS 1.3 also accepts anything older, so a failure
    // here is retried at TLS 1.2 before it counts as "cannot connect".
    if (!result.ok && client.version === 'TLS 1.3') {
      const fallback = await probe({
        ...target, version: 'TLS 1.2', ciphers: client.ciphers,
        groups: client.groups, alpn: ['h2', 'http/1.1'], collect: 'hello',
      });
      if (fallback.ok) return describeSimulation(client, fallback);
    }
    return describeSimulation(client, result);
  });

  return pooled(tasks, 5);
}

function describeSimulation(client, result) {
  if (!result.ok) {
    return {
      client: client.name, platform: client.platform, ok: false,
      error: result.alert?.name || result.error || 'handshake-failed',
    };
  }
  const suite = describeSuite(result.cipher);
  return {
    client: client.name,
    platform: client.platform,
    ok: true,
    protocol: result.versionName,
    cipher: suite.name,
    cipherHex: suite.hex,
    bits: suite.bits,
    pfs: suite.pfs,
    group: result.selectedGroup || result.keyExchange?.group,
    alpn: result.alpn,
  };
}

export { VERSIONS };
