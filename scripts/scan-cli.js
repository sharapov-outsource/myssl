/**
 * Runs a scan from the command line and prints the report.
 *
 *   npm run scan -- example.com
 *   npm run scan -- example.com:8443 --json
 */

import { scan } from '../server/scan.js';

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const host = args.find(a => !a.startsWith('--'));

if (!host) {
  console.error('usage: npm run scan -- <host[:port]> [--json]');
  process.exit(1);
}

const started = Date.now();
let report;
try {
  report = await scan(host, {
    onProgress: event => {
      if (asJson) return;
      const detail = Object.entries(event)
        .filter(([k]) => k !== 'stage' && k !== 'elapsedMs')
        .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('/') : v}`)
        .join(' ');
      process.stderr.write(`  [${String(event.elapsedMs).padStart(6)}ms] ${event.stage} ${detail}\n`);
    },
  });
} catch (err) {
  console.error(`scan failed: ${err.code || err.message}${err.detail ? ` (${err.detail})` : ''}`);
  process.exit(1);
}

if (asJson) {
  console.log(JSON.stringify(report, null, 2));
  process.exit(0);
}

const { grade, certificate: cert } = report;
const line = (label, value) => console.log(`  ${String(label).padEnd(22)} ${value}`);

console.log(`\n${report.host}:${report.port} (${report.ip})`);
console.log(`\n  GRADE ${grade.grade}   score ${grade.score}` +
  `   protocol ${grade.components.protocol.score}` +
  ` · key exchange ${grade.components.keyExchange.score}` +
  ` · cipher ${grade.components.cipher.score}`);
if (grade.caps.length) console.log(`  capped by: ${grade.caps.map(c => `${c.grade} (${c.reason})`).join(', ')}`);
if (grade.warnings.length) console.log(`  warnings:  ${grade.warnings.join(', ')}`);

console.log('\nCertificate');
line('subject', cert.leaf?.commonName);
line('issuer', cert.leaf?.issuerCommonName);
line('key', `${cert.leaf?.keyType} ${cert.leaf?.keyBits || ''} (${cert.leaf?.keyStrength} bit equivalent)`);
line('signature', cert.leaf?.signatureAlgorithm);
line('valid until', `${cert.leaf?.notAfter} (${cert.leaf?.daysRemaining} days)`);
line('names', cert.leaf?.altNames.dns.slice(0, 6).join(', '));
line('chain', `${cert.length} certificates, trusted=${cert.trusted}, complete=${cert.complete}`);
if (cert.issues.length) line('issues', cert.issues.join(', '));

console.log('\nProtocols');
for (const p of report.protocols) line(p.name, p.supported ? 'yes' : `no (${p.reason})`);
line('SSL 2.0', report.ssl2?.supported ? 'yes' : 'no');

for (const [version, info] of Object.entries(report.ciphers)) {
  console.log(`\nCipher suites — ${version} (${info.order} order)`);
  for (const suite of info.suites) {
    console.log(`  ${suite.hex}  ${suite.name.padEnd(52)} ${String(suite.bits || '').padStart(4)}  ${suite.strength}`);
  }
}

console.log('\nKey exchange');
line('groups', report.keyExchange.groups.map(g => g.name).join(', ') || '—');
line('DH', report.keyExchange.dh ? `${report.keyExchange.dh.bits} bit` : 'not offered');

console.log('\nFeatures');
for (const [key, value] of Object.entries(report.features)) {
  line(key, typeof value === 'object' && value ? JSON.stringify(value) : String(value));
}

console.log('\nFindings');
for (const finding of report.vulnerabilities) {
  if (finding.status === 'safe') continue;
  line(`${finding.severity}/${finding.status}`, `${finding.id}${finding.cve ? ` (${finding.cve})` : ''}`);
}

console.log('\nHandshake simulation');
for (const sim of report.simulation) {
  line(sim.client, sim.ok ? `${sim.protocol} ${sim.cipher}` : `failed: ${sim.error}`);
}

console.log(`\nHTTP: ${report.http.reachable ? report.http.status : report.http.error}` +
  `  HSTS: ${report.http.hsts?.present ? report.http.hsts.header : 'none'}` +
  `  HTTP/2: ${report.features.http2}`);
console.log(`\ndone in ${Date.now() - started} ms, ${report.meta.connections} connections for cipher enumeration\n`);
