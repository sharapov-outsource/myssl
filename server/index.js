/**
 * myssl — the HTTP layer, which is now almost nothing.
 *
 * Routing, content negotiation, the content security policy, rate limits, the
 * cache, the event stream and the head of the page all live in
 * @sharapov/service-kit. What is left here is the part that is actually about
 * TLS: what a target looks like, how to scan one, and which words to put next
 * to which codes.
 *
 *   GET /                          the page
 *   GET /<host>                    page for a host (JSON for console clients)
 *   GET /<host>?output=json|yaml   data instead of the page
 *   GET /api/<host>                always data
 *   GET /api/stream/<host>         the same scan as server-sent events
 *   GET /healthz                   liveness probe
 *
 * A host may carry a port — `/example.com:8443` or `?port=8443` — which is why
 * `pathFor` and `cacheKey` are spelled out rather than left at their defaults:
 * two ports on one name are two different servers and must not share a report.
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createService, localizeReport } from '@sharapov/service-kit';

import { scan, parseTarget, allowedPorts, STAGES } from './scan.js';
import { trustStats } from './trust.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

/** `example.com` when it answers on 443, `example.com:8443` when it does not. */
const pathLabel = target => (target.port === 443 ? target.host : `${target.host}:${target.port}`);

const service = await createService({
  slug: 'myssl',
  name: 'SSL Test',
  domain: 'myssl.sharapov.biz',
  port: 3024,
  root: ROOT,
  stages: STAGES,

  /* The port may arrive in the path or in the query; the path wins, because
     that is what a shared link carries. */
  parse: (raw, req) => parseTarget(raw, Number(req?.query?.port) || 443),
  pathFor: pathLabel,
  cacheKey: pathLabel,
  run: (target, options) => scan(target.host, { port: target.port, onProgress: options.onProgress }),

  /* The kit knows `unreachable`; a TLS scan fails one step later than that,
     with a host that answers TCP and never completes a handshake. */
  errors: ['tls-unreachable'],
  allowedPorts,

  examples: ['cloudflare.com', 'sharapov.biz', 'badssl.com'],

  usage: {
    usage: {
      port: 'GET /api/<host>:8443     — or ?port=8443',
    },
    allowedPorts: [...allowedPorts()].sort((a, b) => a - b),
  },

  health: () => ({ trustStores: trustStats() }),

  localize: (report, lang) => localizeReport(report, service.i18n, lang, (out, language) => {
    const { tCode } = service.i18n;
    const label = (prefix, code) => tCode(language, prefix, code);

    /* myssl calls its findings `vulnerabilities` and `problems` rather than the
       `flags` the kit labels on its own, so they are labelled here. The codes
       are never replaced: a script reading `.vulnerabilities[].id` keeps
       working, and a human reading the same output gets the words for free. */
    if (Array.isArray(out.vulnerabilities)) {
      out.vulnerabilities = out.vulnerabilities.map(finding => ({
        ...finding,
        name: label('vuln', finding.id),
        description: label('vd', finding.id),
        severityLabel: label('sev', finding.severity),
        statusLabel: label('st', finding.status),
      }));
    }
    if (Array.isArray(out.problems)) {
      out.problems = out.problems.map(problem => ({
        ...problem,
        name: label('vuln', problem.id),
        severityLabel: label('sev', problem.severity),
        statusLabel: label('st', problem.status),
      }));
    }

    const weakest = out.grade?.components?.keyExchange?.weakest;
    if (weakest?.what) {
      weakest.label = label('kx', weakest.what.toLowerCase().replace(/ /g, '-'));
    }

    const cert = out.certificate;
    if (cert) {
      if (Array.isArray(cert.issues)) cert.issueLabels = cert.issues.map(code => label('issue', code));
      if (cert.trustStore) cert.trustStoreLabel = label('store', cert.trustStore);
      if (cert.leaf?.validation) cert.leaf.validationLabel = label('val', cert.leaf.validation);
      if (cert.ocsp?.certStatus) cert.ocsp.certStatusLabel = label('ocsp', cert.ocsp.certStatus);
      if (cert.ocsp?.responseStatus) {
        cert.ocsp.responseStatusLabel = label('ocsp', cert.ocsp.responseStatus);
      }
    }

    for (const block of Object.values(out.ciphers || {})) {
      block.orderLabel = label('order', block.order);
      for (const suite of block.suites || []) {
        suite.strengthLabel = label('str', suite.strength);
        if (Array.isArray(suite.issues)) suite.issueLabels = suite.issues.map(code => label('ci', code));
      }
    }
  }),
});

await service.start();

export { service };
