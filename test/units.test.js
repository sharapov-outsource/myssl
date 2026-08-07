/**
 * Unit tests for the parts that have to be right and can be checked without a
 * network: suite parsing, target validation, the DER reader and the rating.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';

import { hasOpenssl, selfSigned } from './helpers.js';

import { describeSuite, allSuiteIds, suiteName, hexId } from '../server/suites.js';
import { parseTarget, isPrivateAddress } from '../server/scan.js';
import { grade } from '../server/grade.js';
import { assessVulnerabilities } from '../server/vulns.js';
import { parseHsts } from '../server/http-probe.js';
import { decodeOid, readTlv, certificateExtensions, OID } from '../server/asn1.js';
import { keyStrength } from '../server/cert.js';

/* ------------------------------------------------------------------ *
 * Cipher suites
 * ------------------------------------------------------------------ */

test('suite properties are derived from the registry name', () => {
  const modern = describeSuite(0xc02f);
  assert.equal(modern.name, 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256');
  assert.equal(modern.keyExchange, 'ECDHE');
  assert.equal(modern.authentication, 'RSA');
  assert.equal(modern.encryption, 'AES');
  assert.equal(modern.bits, 128);
  assert.equal(modern.mode, 'GCM');
  assert.equal(modern.pfs, true);
  assert.equal(modern.aead, true);
  assert.equal(modern.strength, 'strong');
  assert.deepEqual(modern.issues, []);
});

test('TLS 1.3 suites carry no key exchange in the name', () => {
  const suite = describeSuite(0x1303);
  assert.equal(suite.name, 'TLS_CHACHA20_POLY1305_SHA256');
  assert.equal(suite.bits, 256);
  assert.equal(suite.pfs, true);
  assert.equal(suite.strength, 'strong');
});

test('export and anonymous suites come out as insecure', () => {
  const freak = describeSuite(0x0003);
  assert.equal(freak.export, true);
  assert.equal(freak.bits, 40);
  assert.equal(freak.strength, 'insecure');
  assert.ok(freak.issues.includes('export'));

  const anon = describeSuite(0x0034);
  assert.equal(anon.anonymous, true);
  assert.equal(anon.strength, 'insecure');
});

test('3DES counts as 112 effective bits and is flagged for Sweet32', () => {
  const suite = describeSuite(0x000a);
  assert.equal(suite.encryption, '3DES');
  assert.equal(suite.bits, 112);
  assert.ok(suite.issues.includes('sweet32'));
});

test('an unknown suite is reported rather than dropped', () => {
  const suite = describeSuite(0xabcd);
  assert.equal(suite.hex, '0xABCD');
  assert.equal(suite.name, 'UNKNOWN_0xABCD');
  assert.ok(suite.issues.includes('unknown-suite'));
});

test('every registered suite parses into something usable', () => {
  for (const id of allSuiteIds()) {
    const suite = describeSuite(id);
    assert.notEqual(suite.keyExchange, 'unknown', `${suiteName(id)} (${hexId(id)}) has no key exchange`);
    assert.notEqual(suite.encryption, 'unknown', `${suiteName(id)} (${hexId(id)}) has no cipher`);
    assert.equal(typeof suite.bits, 'number', `${suiteName(id)} (${hexId(id)}) has no key length`);
  }
});

/* ------------------------------------------------------------------ *
 * Target parsing
 * ------------------------------------------------------------------ */

test('host names, ports and pasted URLs are accepted', () => {
  assert.deepEqual(parseTarget('example.com'), { host: 'example.com', port: 443, isIp: false });
  assert.deepEqual(parseTarget('EXAMPLE.com:8443'), { host: 'example.com', port: 8443, isIp: false });
  assert.deepEqual(parseTarget('https://example.com/some/path?x=1'),
    { host: 'example.com', port: 443, isIp: false });
  assert.deepEqual(parseTarget('https://example.com:8443/'),
    { host: 'example.com', port: 8443, isIp: false });
  assert.deepEqual(parseTarget('example.com.'), { host: 'example.com', port: 443, isIp: false });
  assert.equal(parseTarget('1.1.1.1').isIp, true);
  assert.equal(parseTarget('[2606:4700:4700::1111]:443').host, '2606:4700:4700::1111');
});

test('junk, unroutable ports and unknown ports are refused', () => {
  assert.equal(parseTarget('').error, 'invalid-host');
  assert.equal(parseTarget('not a host').error, 'invalid-host');
  assert.equal(parseTarget('/etc/passwd').error, 'invalid-host');
  assert.equal(parseTarget('localhost').error, 'invalid-host');
  assert.equal(parseTarget('example.com:0').error, 'invalid-port');
  assert.equal(parseTarget('example.com:70000').error, 'invalid-port');
  assert.equal(parseTarget('example.com:22').error, 'port-not-allowed');
  assert.equal(parseTarget('a'.repeat(300) + '.com').error, 'invalid-host');
});

test('private and reserved ranges are recognised', () => {
  for (const ip of ['10.0.0.1', '127.0.0.1', '192.168.1.1', '172.16.9.9', '169.254.1.1',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', 'fe80::1', 'fd00::1', '::ffff:10.0.0.1']) {
    assert.equal(isPrivateAddress(ip), true, `${ip} should be private`);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '140.82.121.3', '2606:4700:4700::1111']) {
    assert.equal(isPrivateAddress(ip), false, `${ip} should be public`);
  }
});

/* ------------------------------------------------------------------ *
 * DER reading
 * ------------------------------------------------------------------ */

test('object identifiers decode to dotted form', () => {
  assert.equal(decodeOid(Buffer.from('2a864886f70d01010b', 'hex')), '1.2.840.113549.1.1.11');
  assert.equal(decodeOid(Buffer.from('551d0f', 'hex')), '2.5.29.15');
  assert.equal(decodeOid(Buffer.from('2b06010401d679020402', 'hex')), '1.3.6.1.4.1.11129.2.4.2');
});

test('a truncated TLV is rejected instead of read past the end', () => {
  assert.equal(readTlv(Buffer.from([0x30, 0x05, 0x01]), 0), null);
  assert.equal(readTlv(Buffer.from([0x30]), 0), null);
  const ok = readTlv(Buffer.from([0x30, 0x02, 0x05, 0x00]), 0);
  assert.equal(ok.length, 2);
  assert.equal(ok.end, 4);
});

test('extensions are found in a real certificate', { skip: !hasOpenssl() }, () => {
  const { cert, cleanup } = selfSigned();
  try {
    const x509 = new X509Certificate(cert);
    const extensions = certificateExtensions(x509.raw);
    assert.ok(extensions.has(OID.subjectAltName), 'subjectAltName should be present');
    assert.ok(extensions.has(OID.basicConstraints), 'basicConstraints should be present');
  } finally {
    cleanup();
  }
});

/* ------------------------------------------------------------------ *
 * Key strength
 * ------------------------------------------------------------------ */

test('key sizes map to the usual equivalent strengths', () => {
  assert.equal(keyStrength('rsa', 2048), 112);
  assert.equal(keyStrength('rsa', 3072), 128);
  assert.equal(keyStrength('rsa', 1024), 80);
  assert.equal(keyStrength('ec', 256, 'prime256v1'), 128);
  assert.equal(keyStrength('ec', 384, 'secp384r1'), 192);
  assert.equal(keyStrength('ed25519', 255), 128);
});

/* ------------------------------------------------------------------ *
 * Rating
 * ------------------------------------------------------------------ */

/** A configuration that should score top marks, as a starting point to break. */
function goodConfig(overrides = {}) {
  const base = {
    protocols: [
      { name: 'SSL 3.0', supported: false },
      { name: 'TLS 1.0', supported: false },
      { name: 'TLS 1.1', supported: false },
      { name: 'TLS 1.2', supported: true },
      { name: 'TLS 1.3', supported: true },
    ],
    ssl2: { supported: false },
    allCiphers: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc030, 0xcca8],
    keyExchange: { groups: [{ id: 29, name: 'x25519' }], dh: null },
    certificate: {
      issues: [],
      trusted: true,
      leaf: { keyStrength: 128, keyBits: 256, sctCount: 3, daysRemaining: 60, mustStaple: false },
    },
    features: {
      compression: { supported: false },
      heartbeat: { advertised: false },
      fallbackScsv: { supported: true },
      clientRenegotiation: { supported: false },
      secureRenegotiation: true,
      ocspStapling: true,
    },
    http: { reachable: true, hsts: { present: true, maxAge: 31536000, longEnough: true }, plainHttp: { toHttps: true } },
  };
  const config = { ...base, ...overrides };
  config.vulnerabilities = assessVulnerabilities(config);
  return config;
}

test('a scan whose probes were all refused gets no grade at all', () => {
  const config = goodConfig({
    incomplete: true,
    protocols: [
      { name: 'TLS 1.2', supported: false },
      { name: 'TLS 1.3', supported: false },
    ],
    allCiphers: [],
  });
  const result = grade({ ...config, vulnerabilities: assessVulnerabilities(config) });
  // The alternative is what used to happen: 27 points and an E, invented out
  // of connections that never got answered.
  assert.equal(result.grade, '?');
  assert.equal(result.reason, 'scan-incomplete');
});

test('a clean modern configuration reaches A+', () => {
  const result = grade(goodConfig());
  assert.equal(result.grade, 'A+');
  assert.equal(result.components.protocol.best, 'TLS 1.3');
  assert.equal(result.components.protocol.worst, 'TLS 1.2');
  assert.deepEqual(result.caps, []);
});

test('without HSTS the same configuration is only an A', () => {
  const result = grade(goodConfig({
    http: { reachable: true, hsts: { present: false }, plainHttp: { toHttps: true } },
  }));
  assert.equal(result.grade, 'A');
});

test('legacy protocol versions cap the grade at B', () => {
  const config = goodConfig();
  config.protocols[1].supported = true;      // TLS 1.0
  const result = grade({ ...config, vulnerabilities: assessVulnerabilities(config) });
  assert.equal(result.grade, 'B');
  assert.ok(result.caps.some(c => c.reason === 'legacy-tls-versions'));
});

test('SSL 2.0 drops the grade to F', () => {
  const config = goodConfig({ ssl2: { supported: true } });
  const result = grade({ ...config, vulnerabilities: assessVulnerabilities(config) });
  assert.equal(result.grade, 'F');
});

test('an untrusted certificate overrides everything with T', () => {
  const result = grade(goodConfig({
    certificate: {
      issues: ['expired', 'not-trusted'],
      trusted: false,
      leaf: { keyStrength: 128, keyBits: 256, sctCount: 3, daysRemaining: -5 },
    },
  }));
  assert.equal(result.grade, 'T');
  assert.equal(result.reason, 'certificate-not-trusted');
});

test('a name mismatch is reported as M', () => {
  const result = grade(goodConfig({
    certificate: {
      issues: ['hostname-mismatch', 'not-trusted'],
      trusted: false,
      leaf: { keyStrength: 128, keyBits: 256, sctCount: 3, daysRemaining: 60 },
    },
  }));
  assert.equal(result.grade, 'M');
});

test('a Diffie-Hellman group below 1024 bit is a Logjam failure', () => {
  const config = goodConfig({
    keyExchange: { groups: [{ id: 29, name: 'x25519' }], dh: { bits: 768 } },
  });
  const result = grade({ ...config, vulnerabilities: assessVulnerabilities(config) });
  assert.equal(result.grade, 'F');
  assert.ok(result.caps.some(c => c.reason === 'logjam'));
});

test('a 1024-bit group is not broken outright, but still caps at B', () => {
  const config = goodConfig({
    keyExchange: { groups: [{ id: 29, name: 'x25519' }], dh: { bits: 1024 } },
  });
  const result = grade({ ...config, vulnerabilities: assessVulnerabilities(config) });
  assert.equal(result.grade, 'B');
  assert.ok(result.caps.some(c => c.reason === 'weak-dh-group'));
});

test('3DES caps the grade at C', () => {
  const config = goodConfig({
    allCiphers: [0x1301, 0xc02f, 0x000a],
  });
  const result = grade({ ...config, vulnerabilities: assessVulnerabilities(config) });
  assert.equal(result.grade, 'C');
  assert.ok(result.caps.some(c => c.reason === 'sweet32-64-bit-block-cipher'));
});

/* ------------------------------------------------------------------ *
 * HSTS
 * ------------------------------------------------------------------ */

test('HSTS headers are read down to the flags', () => {
  const hsts = parseHsts('max-age=63072000; includeSubDomains; preload');
  assert.equal(hsts.present, true);
  assert.equal(hsts.maxAge, 63072000);
  assert.equal(hsts.includeSubDomains, true);
  assert.equal(hsts.preload, true);
  assert.equal(hsts.longEnough, true);

  const short = parseHsts('max-age=300');
  assert.equal(short.longEnough, false);
  assert.equal(short.includeSubDomains, false);

  assert.equal(parseHsts(undefined).present, false);
});

