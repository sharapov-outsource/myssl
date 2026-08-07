/**
 * Trust anchors.
 *
 * Whether a certificate is trusted must not depend on the machine the scanner
 * happens to run on. Node's own verdict does: on some platforms it consults the
 * operating system store, so the same site can come back trusted on a laptop
 * and untrusted in a container. So the chain is walked here instead, against
 * stores this repository controls:
 *
 *   · `mozilla` — the CA list Node ships with, which is what browsers use;
 *   · everything in `server/roots/` — extra anchors such as the Russian
 *     national CA, which no browser carries. A chain that ends there is
 *     trusted, but reported as trusted only by clients carrying that root.
 *
 * More anchors can be added by dropping a PEM file into `server/roots/`, or by
 * pointing `EXTRA_CA_DIR` somewhere else.
 */

import tls from 'node:tls';
import path from 'node:path';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EXTRA_DIR = process.env.EXTRA_CA_DIR || path.join(__dirname, 'roots');

/** The store browsers agree on. */
export const MOZILLA = 'mozilla';

let index = null;

/** Splits a PEM file — comments and all — into individual certificates. */
function certificatesFrom(pem) {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  const certs = [];
  for (const block of blocks) {
    try {
      certs.push(new X509Certificate(block));
    } catch { /* a certificate that cannot be parsed cannot be an anchor */ }
  }
  return certs;
}

function add(cert, store) {
  const list = index.bySubject.get(cert.subject);
  const entry = { cert, store };
  if (list) list.push(entry);
  else index.bySubject.set(cert.subject, [entry]);
}

/**
 * Builds the index once, on first use: subject → the anchors with that subject.
 * Parsing ~150 certificates is not free, and the result never changes.
 */
function build() {
  index = { bySubject: new Map(), stores: [MOZILLA], counts: { [MOZILLA]: 0 } };

  for (const pem of tls.rootCertificates) {
    try {
      add(new X509Certificate(pem), MOZILLA);
      index.counts[MOZILLA]++;
    } catch { /* skip */ }
  }

  let files = [];
  try {
    files = readdirSync(EXTRA_DIR).filter(name => /\.(pem|crt|cer)$/i.test(name)).sort();
  } catch { /* no extra anchors configured */ }

  for (const file of files) {
    const store = file.replace(/\.(pem|crt|cer)$/i, '');
    let certs = [];
    try {
      certs = certificatesFrom(readFileSync(path.join(EXTRA_DIR, file), 'utf8'));
    } catch { continue; }
    if (!certs.length) continue;
    index.stores.push(store);
    index.counts[store] = certs.length;
    certs.forEach(cert => add(cert, store));
  }

  return index;
}

export function trustIndex() {
  return index || build();
}

export function trustStats() {
  const { counts } = trustIndex();
  return counts;
}

/**
 * Finds the anchor a chain ends at.
 *
 * Walks the presented certificates from the leaf upwards and stops at the first
 * one issued by an anchor whose signature checks out. The Mozilla store is
 * preferred: a chain that ends both there and in an extra store is simply
 * trusted, with no caveat.
 *
 * @param {X509Certificate[]} chain certificates in the order the server sent them
 * @returns {{cert:X509Certificate, store:string, issued:X509Certificate}|null}
 */
export function findAnchor(chain) {
  const { bySubject } = trustIndex();
  let fallback = null;

  for (const cert of chain) {
    for (const { cert: anchor, store } of bySubject.get(cert.issuer) || []) {
      let ok = false;
      try {
        ok = cert.checkIssued(anchor) && cert.verify(anchor.publicKey);
      } catch { ok = false; }
      if (!ok) continue;

      const match = { cert: anchor, store, issued: cert };
      if (store === MOZILLA) return match;
      fallback ??= match;
    }
  }
  return fallback;
}

/** A short, human-readable name for an anchor. */
export function anchorName(cert) {
  if (!cert) return null;
  const cn = cert.subject.split('\n').find(line => line.startsWith('CN='));
  return cn ? cn.slice(3) : cert.subject.split('\n')[0];
}
