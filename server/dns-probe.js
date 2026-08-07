/**
 * Name resolution and the DNS records that have a say in TLS.
 *
 * CAA is the interesting one: it names the certificate authorities allowed to
 * issue for a domain, so a mismatch between it and the certificate on the wire
 * is worth pointing out.
 */

import dns from 'node:dns/promises';
import net from 'node:net';

const TIMEOUT = 5000;

function withTimeout(promise, fallback = null) {
  return Promise.race([
    promise.catch(() => fallback),
    new Promise(resolve => setTimeout(() => resolve(fallback), TIMEOUT)),
  ]);
}

/** Walks up the labels: CAA is inherited from the closest parent that has it. */
async function findCaa(host) {
  const labels = host.split('.');
  for (let i = 0; i < labels.length - 1; i++) {
    const name = labels.slice(i).join('.');
    const records = await withTimeout(dns.resolveCaa(name), null);
    if (records?.length) return { name, records };
  }
  return null;
}

export async function probeDns(host) {
  if (net.isIP(host)) {
    const ptr = await withTimeout(dns.reverse(host), null);
    return {
      literal: true,
      addresses: [{ address: host, family: net.isIP(host) }],
      reverse: ptr?.[0] || null,
      caa: null,
    };
  }

  const [a, aaaa, caa] = await Promise.all([
    withTimeout(dns.resolve4(host), []),
    withTimeout(dns.resolve6(host), []),
    findCaa(host),
  ]);

  const addresses = [
    ...(a || []).map(address => ({ address, family: 4 })),
    ...(aaaa || []).map(address => ({ address, family: 6 })),
  ];

  const reverse = addresses.length
    ? (await withTimeout(dns.reverse(addresses[0].address), null))?.[0] || null
    : null;

  return {
    literal: false,
    addresses,
    reverse,
    caa: caa && {
      name: caa.name,
      // The record shape node returns is { critical, issue|issuewild|iodef }.
      issue: caa.records.filter(r => r.issue !== undefined).map(r => r.issue),
      issueWild: caa.records.filter(r => r.issuewild !== undefined).map(r => r.issuewild),
      iodef: caa.records.filter(r => r.iodef !== undefined).map(r => r.iodef),
    },
  };
}

/**
 * Does the CAA record cover whoever issued the certificate?
 * The comparison is deliberately loose: CAA names an authority domain
 * ("letsencrypt.org"), while the certificate names an organisation.
 */
export function caaCoversIssuer(caa, issuerOrganization = '', issuerCommonName = '') {
  if (!caa || (!caa.issue.length && !caa.issueWild.length)) return null;
  const allowed = [...caa.issue, ...caa.issueWild]
    .map(value => String(value).split(';')[0].trim().toLowerCase())
    .filter(Boolean);
  if (allowed.includes(';')) return false;           // ";" forbids all issuance

  const haystack = `${issuerOrganization} ${issuerCommonName}`.toLowerCase();
  return allowed.some(entry => {
    const core = entry.replace(/\.(com|org|net|io|ru|de)$/i, '').replace(/[.-]/g, ' ');
    return core.split(/\s+/).filter(w => w.length > 3).some(word => haystack.includes(word));
  });
}
