/**
 * End-to-end test of the scanner against a TLS server started here.
 *
 * Nothing leaves the machine: a throwaway self-signed certificate is generated,
 * a server is started on the loopback interface, and the scan is pointed at it
 * with the private-address guard lifted for the duration.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';

import { hasOpenssl, selfSigned } from './helpers.js';

const skip = !hasOpenssl() ? 'openssl is not available' : false;

/** Starts a TLS server on a free loopback port and returns it with the port. */
function startServer(options) {
  return new Promise((resolve, reject) => {
    const server = tls.createServer(options, socket => {
      socket.on('error', () => {});
      socket.end('HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok');
    });
    server.on('tlsClientError', () => {});   // failed probes are the point
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

test('a self-signed server is scanned end to end', { skip, timeout: 90000 }, async t => {
  const { key, cert, cleanup } = selfSigned();
  const { server, port } = await startServer({
    key, cert,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES128-SHA',
    honorCipherOrder: true,
  });

  // The guard and the port allowlist are configuration, so the test sets both
  // before the scanner module reads them.
  process.env.ALLOW_PRIVATE_TARGETS = 'true';
  process.env.ALLOWED_PORTS = String(port);
  const { scan } = await import('../server/scan.js');

  t.after(() => {
    server.close();
    cleanup();
    delete process.env.ALLOW_PRIVATE_TARGETS;
    delete process.env.ALLOWED_PORTS;
  });

  const stages = [];
  const report = await scan(`127.0.0.1:${port}`, { onProgress: e => stages.push(e.stage) });

  assert.equal(report.host, '127.0.0.1');
  assert.equal(report.port, port);
  assert.ok(stages.includes('protocols') && stages.includes('grade'), 'progress should be reported');

  /* --- protocols --- */
  const supported = report.protocols.filter(p => p.supported).map(p => p.name);
  assert.deepEqual(supported.sort(), ['TLS 1.2', 'TLS 1.3']);
  assert.equal(report.ssl2.supported, false);

  /* --- cipher suites --- */
  assert.ok(report.ciphers['TLS 1.3'].suites.length >= 1, 'TLS 1.3 suites should be found');
  const names12 = report.ciphers['TLS 1.2'].suites.map(s => s.name);
  assert.ok(names12.includes('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'), names12.join(', '));
  assert.ok(names12.includes('TLS_RSA_WITH_AES_128_CBC_SHA'), names12.join(', '));
  assert.equal(report.ciphers['TLS 1.2'].order, 'server');

  /* --- certificate --- */
  assert.equal(report.certificate.leaf.commonName, 'myssl.local');
  assert.equal(report.certificate.leaf.keyType, 'RSA');
  assert.equal(report.certificate.leaf.keyBits, 2048);
  assert.equal(report.certificate.trusted, false);
  assert.ok(report.certificate.issues.includes('self-signed'));

  /* --- rating --- */
  assert.equal(report.grade.grade, 'T', 'a self-signed certificate cannot be trusted');
  assert.equal(report.grade.reason, 'certificate-not-trusted');

  /* --- findings --- */
  const byId = Object.fromEntries(report.vulnerabilities.map(v => [v.id, v]));
  assert.equal(byId.drown.status, 'safe');
  assert.equal(byId['certificate-trust'].status, 'vulnerable');
  assert.equal(byId['no-forward-secrecy'].status, 'partial');   // AES128-SHA has no PFS

  /* --- simulation --- */
  assert.ok(report.simulation.length > 5);
  assert.ok(report.simulation.some(s => s.ok), 'at least one client should connect');
});

test('a TLS 1.2-only server without forward secrecy is called out', { skip, timeout: 90000 }, async t => {
  const { key, cert, cleanup } = selfSigned();
  const { server, port } = await startServer({
    key, cert,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
    // RSA key transport with CBC only: no ephemeral key exchange anywhere.
    ciphers: 'AES256-SHA:AES128-SHA',
    honorCipherOrder: true,
  });

  process.env.ALLOW_PRIVATE_TARGETS = 'true';
  process.env.ALLOWED_PORTS = String(port);
  const { scan } = await import('../server/scan.js');

  t.after(() => {
    server.close();
    cleanup();
    delete process.env.ALLOW_PRIVATE_TARGETS;
    delete process.env.ALLOWED_PORTS;
  });

  const report = await scan(`127.0.0.1:${port}`);
  const suites = report.ciphers['TLS 1.2'].suites.map(s => s.name);

  assert.ok(suites.includes('TLS_RSA_WITH_AES_128_CBC_SHA'), suites.join(', '));
  assert.ok(suites.every(name => name.startsWith('TLS_RSA_')), suites.join(', '));
  assert.equal(report.protocols.find(p => p.name === 'TLS 1.3').supported, false);

  const findings = Object.fromEntries(report.vulnerabilities.map(v => [v.id, v]));
  assert.equal(findings['no-forward-secrecy'].status, 'vulnerable');
  assert.equal(findings.robot.status, 'possible');
  assert.equal(findings.lucky13.status, 'possible');
  assert.equal(report.keyExchange.groups.length, 0, 'no ECDHE suites, so no groups to report');

  // The certificate is self-signed here too, so T wins over every cipher cap.
  assert.equal(report.grade.grade, 'T');
});
