/** Bits and pieces shared by the tests. */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** The certificate tests need the openssl binary; without it they are skipped. */
export function hasOpenssl() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * A throwaway self-signed certificate.
 * @param {object} options { subject, days, keyArgs }
 */
export function selfSigned({ subject = '/CN=ssltest.local', days = 2, keyArgs = ['rsa:2048'] } = {}) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'ssltest-'));
  const keyPath = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');

  execFileSync('openssl', [
    'req', '-x509', '-newkey', ...keyArgs, '-nodes',
    '-keyout', keyPath, '-out', certPath, '-days', String(days),
    '-subj', subject,
    '-addext', 'subjectAltName=DNS:ssltest.local,IP:127.0.0.1',
  ], { stdio: 'ignore' });

  return {
    key: readFileSync(keyPath),
    cert: readFileSync(certPath),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}
