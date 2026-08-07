/**
 * The scan itself: everything the individual probes can find, run in a sensible
 * order and assembled into one report.
 *
 * Design notes:
 *   · Cipher enumeration is sequential inside a protocol version — that is what
 *     preserves the server's own preference order — but the versions run
 *     concurrently, and everything that does not depend on them starts at once.
 *   · Targets are resolved first and checked against private ranges, so this
 *     service cannot be pointed at something inside the network it runs in.
 *   · Progress is reported through a callback, which is what feeds the live
 *     view in the browser.
 */

import net from 'node:net';
import dns from 'node:dns/promises';

import { probe, probeSsl2, VERSION_ORDER } from './tls-probe.js';
import {
  detectProtocols, enumerateCiphers, detectCipherOrder, enumerateGroups,
  detectDhParams, checkFallbackScsv, checkCompression, checkHeartbeat,
  checkWithoutSni, simulateClients, suitesForVersion,
} from './enumerate.js';
import { describeSuite } from './suites.js';
import { analyzeChain } from './cert.js';
import { tlsInspect, checkResumption, checkRenegotiation } from './node-tls.js';
import { probeHttp } from './http-probe.js';
import { probeDns, caaCoversIssuer } from './dns-probe.js';
import { assessVulnerabilities, problems } from './vulns.js';
import { grade } from './grade.js';

const DEFAULT_PORTS = '443,8443,4443,9443,10443,993,995,465,587,636,990,989,5061,8883,2083,2087,2096';

let portCache = { raw: null, set: null };

/**
 * Ports this service is willing to connect to. Read from the environment on
 * demand rather than frozen at import time, so a deployment — or a test that
 * starts its own server on an ephemeral port — can change the list.
 */
export function allowedPorts() {
  const raw = process.env.ALLOWED_PORTS || DEFAULT_PORTS;
  if (portCache.raw !== raw) {
    portCache = {
      raw,
      set: new Set(raw.split(',').map(p => Number(p.trim())).filter(Boolean)),
    };
  }
  return portCache.set;
}

const SCAN_TIMEOUT = Number(process.env.SCAN_TIMEOUT_MS || 60000);
const PROBE_TIMEOUT = Number(process.env.PROBE_TIMEOUT_MS || 8000);

/* Scanning private ranges is refused: a public scanner that can be pointed at
   10.0.0.0/8 is a port scanner for whatever network it happens to run in.
   Tests turn this off to scan a server they started themselves. */
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE_TARGETS === 'true';

/* ------------------------------------------------------------------ *
 * Input validation
 * ------------------------------------------------------------------ */

/** Splits "example.com:8443" into its parts and sanity-checks both. */
export function parseTarget(raw, defaultPort = 443) {
  if (typeof raw !== 'string') return { error: 'invalid-host' };
  let value = raw.trim().toLowerCase();
  if (!value) return { error: 'invalid-host' };

  // A pasted URL is a perfectly reasonable thing to type into the box.
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(value)) {
    try {
      const url = new URL(value);
      value = url.port ? `${url.hostname}:${url.port}` : url.hostname;
    } catch {
      return { error: 'invalid-host' };
    }
  }
  value = value.replace(/\/.*$/, '');

  let host = value;
  let port = defaultPort;

  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(value);
  if (bracketed) {
    host = bracketed[1];
    if (bracketed[2]) port = Number(bracketed[2]);
  } else {
    const parts = value.split(':');
    if (parts.length === 2 && /^\d+$/.test(parts[1])) {
      host = parts[0];
      port = Number(parts[1]);
    } else if (parts.length > 2) {
      host = value;                                   // bare IPv6 literal
    }
  }

  host = host.replace(/\.$/, '');
  if (host.length > 253) return { error: 'invalid-host' };

  const isIp = Boolean(net.isIP(host));
  if (!isIp && !/^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/.test(host)) {
    return { error: 'invalid-host' };
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { error: 'invalid-port' };
  if (!allowedPorts().has(port)) return { error: 'port-not-allowed' };

  return { host, port, isIp };
}

/** Addresses that must never be scanned: they are somebody's internal network. */
export function isPrivateAddress(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224;
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    return lower === '::' || lower === '::1' ||
      lower.startsWith('fe80:') || /^f[cd][0-9a-f]{2}:/.test(lower) ||
      lower.startsWith('ff') ||
      // IPv4-mapped addresses inherit the IPv4 rules.
      (lower.startsWith('::ffff:') && isPrivateAddress(lower.slice(7)));
  }
  return true;
}

/* ------------------------------------------------------------------ *
 * The scan
 * ------------------------------------------------------------------ */

const STAGES = [
  'resolve', 'handshake', 'protocols', 'ciphers', 'keyexchange',
  'certificate', 'features', 'http', 'clients', 'grade',
];

export { STAGES };

/**
 * A scan with a hard ceiling on how long it may take. Individual probes have
 * their own timeouts, so this only catches a pathological target that keeps
 * every single one of them just barely alive.
 *
 * @param {string} rawHost   host, host:port or a pasted URL
 * @param {object} options   { port, onProgress }
 */
export async function scan(rawHost, options = {}) {
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(Object.assign(new Error('scan-timeout'), { code: 'scan-timeout', status: 504 })),
      SCAN_TIMEOUT
    );
  });
  try {
    return await Promise.race([runScan(rawHost, options), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

async function runScan(rawHost, { port: defaultPort = 443, onProgress = () => {} } = {}) {
  const started = Date.now();
  const target = parseTarget(rawHost, defaultPort);
  if (target.error) throw Object.assign(new Error(target.error), { code: target.error, status: 400 });

  const { host, port } = target;
  const progress = (stage, extra = {}) => onProgress({ stage, elapsedMs: Date.now() - started, ...extra });

  const refuse = () => Object.assign(new Error('private-address'), {
    code: 'private-address', status: 403,
  });

  /* ---------------- resolve ---------------- */
  progress('resolve');
  // A literal address is rejected before any lookup, so nothing internal is
  // even resolved on behalf of the caller.
  if (target.isIp && !ALLOW_PRIVATE && isPrivateAddress(host)) throw refuse();

  const dnsInfo = await probeDns(host);
  if (!dnsInfo.addresses.length) {
    throw Object.assign(new Error('dns-failed'), { code: 'dns-failed', status: 502 });
  }
  const ip = dnsInfo.addresses[0].address;
  if (!ALLOW_PRIVATE && isPrivateAddress(ip)) throw refuse();

  const endpoint = { host, ip, port, servername: target.isIp ? undefined : host, timeout: PROBE_TIMEOUT };

  /* ---------------- first handshake ---------------- */
  progress('handshake');
  const node = await tlsInspect(endpoint);
  if (!node.ok) {
    // One retry without SNI covers servers that reject an unknown name outright.
    const bare = await tlsInspect({ ...endpoint, servername: undefined });
    if (!bare.ok) {
      throw Object.assign(new Error('tls-unreachable'), {
        code: 'tls-unreachable', status: 502, detail: node.error,
      });
    }
    Object.assign(node, bare);
  }

  /* ---------------- protocols ---------------- */
  progress('protocols');
  const protocols = await detectProtocols(endpoint);
  const supported = protocols.filter(p => p.supported).map(p => p.name);
  progress('protocols', { done: true, supported });

  /* Everything below only needs the list of supported versions, so the slow
     cipher walk runs alongside the certificate, HTTP and feature checks. */

  /* ---------------- ciphers ---------------- */
  progress('ciphers', { versions: supported });
  const cipherWork = Promise.all(supported.map(async version => {
    const { ciphers, connections } = await enumerateCiphers(endpoint, version);
    const order = await detectCipherOrder(endpoint, version, ciphers);
    progress('ciphers', { version, found: ciphers.length });
    return { version, ciphers, order, connections };
  }));

  /* ---------------- everything else, concurrently ---------------- */
  const featureWork = (async () => {
    progress('features');
    const [ssl2, fallbackScsv, compression, heartbeat, noSni, resumption, renegotiation] =
      await Promise.all([
        probeSsl2(endpoint),
        checkFallbackScsv(endpoint, supported),
        checkCompression(endpoint, supported),
        checkHeartbeat(endpoint, supported),
        checkWithoutSni(endpoint, supported),
        checkResumption(endpoint),
        checkRenegotiation(endpoint),
      ]);
    return { ssl2, fallbackScsv, compression, heartbeat, noSni, resumption, renegotiation };
  })();

  const keyExchangeWork = (async () => {
    progress('keyexchange');
    const [groups, dh] = await Promise.all([
      enumerateGroups(endpoint, supported),
      detectDhParams(endpoint, supported),
    ]);
    return { groups, dh };
  })();

  const httpWork = (async () => {
    progress('http');
    return probeHttp(endpoint);
  })();

  const clientWork = (async () => {
    progress('clients');
    return simulateClients(endpoint);
  })();

  /* The certificate chain is best taken from a TLS 1.2 handshake, where it
     travels in the clear; a TLS 1.3-only server leaves Node's copy as the
     only source. */
  const certWork = (async () => {
    progress('certificate');
    const legacy = ['TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0'].find(v => supported.includes(v));
    let raw = null;
    if (legacy) {
      raw = await probe({ ...endpoint, version: legacy, ciphers: suitesForVersion(legacy) });
    }
    const chain = raw?.certificates?.length ? raw.certificates : node.chain;
    return {
      chain,
      ocspResponse: raw?.ocspResponse || node.ocspResponse || null,
      stapledFrom: raw?.ocspResponse ? 'handshake' : node.ocspResponse ? 'node' : null,
      clientCertRequested: raw?.clientCertRequested || false,
      handshakeExtensions: raw?.extensions || {},
    };
  })();

  const [byVersion, features, keyExchange, http, clients, certRaw] = await Promise.all([
    cipherWork, featureWork, keyExchangeWork, httpWork, clientWork, certWork,
  ]);

  /* ---------------- assemble ---------------- */
  const ciphersByProtocol = {};
  const allCiphers = new Set();
  for (const entry of byVersion) {
    ciphersByProtocol[entry.version] = {
      order: entry.order,
      suites: entry.ciphers.map(id => describeSuite(id)),
    };
    entry.ciphers.forEach(id => allCiphers.add(id));
  }

  const certificate = analyzeChain(certRaw.chain, {
    host: target.isIp ? undefined : host,
    ocspResponse: certRaw.ocspResponse,
    nodeVerdict: node,
  });

  const handshakeExtensions = certRaw.handshakeExtensions || {};
  const assembled = {
    host,
    port,
    ip,
    protocols,
    ssl2: features.ssl2,
    allCiphers: [...allCiphers],
    ciphersByProtocol,
    keyExchange,
    certificate,
    features: {
      compression: features.compression,
      heartbeat: features.heartbeat,
      fallbackScsv: features.fallbackScsv,
      clientRenegotiation: features.renegotiation,
      secureRenegotiation: handshakeExtensions.secureRenegotiation ?? null,
      extendedMasterSecret: handshakeExtensions.extendedMasterSecret ?? null,
      encryptThenMac: handshakeExtensions.encryptThenMac ?? null,
      sessionTickets: handshakeExtensions.sessionTicket ?? null,
      ocspStapling: Boolean(certRaw.ocspResponse),
      sessionResumption: features.resumption,
      alpn: node.alpnProtocol,
      http2: node.alpnProtocol === 'h2',
      sniRequired: features.noSni ? !features.noSni.handshake : null,
      clientCertRequested: certRaw.clientCertRequested,
      ephemeralKey: node.ephemeralKey,
    },
    http,
  };

  assembled.vulnerabilities = assessVulnerabilities(assembled);
  const rating = grade(assembled);

  progress('grade', { grade: rating.grade });

  const caa = dnsInfo.caa;
  return {
    host,
    port,
    ip,
    grade: rating,
    certificate,
    protocols: protocols.map(p => ({ name: p.name, supported: p.supported, reason: p.reason })),
    ssl2: features.ssl2,
    ciphers: ciphersByProtocol,
    keyExchange: {
      groups: keyExchange.groups,
      dh: keyExchange.dh,
      ephemeralKey: node.ephemeralKey,
    },
    features: assembled.features,
    vulnerabilities: assembled.vulnerabilities,
    problems: problems(assembled.vulnerabilities).map(p => ({ id: p.id, severity: p.severity, status: p.status })),
    http,
    dns: {
      ...dnsInfo,
      caaMatchesIssuer: caa
        ? caaCoversIssuer(caa, certificate.leaf?.issuerOrganization, certificate.leaf?.issuerCommonName)
        : null,
    },
    simulation: clients,
    negotiated: {
      protocol: node.protocol,
      cipher: node.cipher,
      standardName: node.cipherStandard,
      alpn: node.alpnProtocol,
    },
    meta: {
      elapsedMs: Date.now() - started,
      connections: byVersion.reduce((sum, v) => sum + v.connections, 0),
      cached: false,
      generatedAt: new Date().toISOString(),
      engine: 'ssltest/1.0',
      truncated: Date.now() - started > SCAN_TIMEOUT,
    },
  };
}

/* ------------------------------------------------------------------ *
 * Cache
 * ------------------------------------------------------------------ */

const TTL_MS = Number(process.env.CACHE_TTL_MS || 10 * 60 * 1000);
const MAX_ENTRIES = Number(process.env.CACHE_MAX || 500);

const cache = new Map();
const inflight = new Map();

export function cacheStats() {
  return { entries: cache.size, max: MAX_ENTRIES, ttlMs: TTL_MS, inflight: inflight.size };
}

function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() > hit.expires) {
    cache.delete(key);
    return null;
  }
  cache.delete(key);
  cache.set(key, hit);
  return hit.value;
}

function cacheSet(key, value) {
  if (cache.size >= MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, { value, expires: Date.now() + TTL_MS });
}

/**
 * Cached scan. Two requests for the same target that arrive together share one
 * scan rather than hammering the server twice.
 */
export async function scanCached(rawHost, { port = 443, refresh = false, onProgress } = {}) {
  const target = parseTarget(rawHost, port);
  if (target.error) throw Object.assign(new Error(target.error), { code: target.error, status: 400 });

  const key = `${target.host}:${target.port}`;
  if (!refresh) {
    const hit = cacheGet(key);
    if (hit) return { ...hit, meta: { ...hit.meta, cached: true } };
    const running = inflight.get(key);
    if (running) return running;
  }

  const run = scan(rawHost, { port, onProgress })
    .then(result => {
      cacheSet(key, result);
      return result;
    })
    .finally(() => inflight.delete(key));

  inflight.set(key, run);
  return run;
}

export { VERSION_ORDER };
