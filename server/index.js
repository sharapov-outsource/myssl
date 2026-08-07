/**
 * ssltest HTTP server.
 *
 * Routes:
 *   GET /                          the page
 *   GET /<host>                    page for a host (or JSON for console clients)
 *   GET /<host>?output=json|yaml   data instead of the page
 *   GET /api/<host>                always data (JSON by default)
 *   GET /api/stream/<host>         the same scan as server-sent events, with progress
 *   GET /healthz                   liveness probe
 *
 * curl and other console clients get JSON without passing any parameters.
 */

import path from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import rateLimit from '@fastify/rate-limit';
import YAML from 'yaml';

import { scanCached, cacheStats, parseTarget, allowedPorts, STAGES } from './scan.js';
import { pickLang, localizeReport, t, SUPPORTED_LANGS, LANG_NAMES } from './i18n.js';
import { trustStats } from './trust.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const PORT = Number(process.env.PORT || 3024);
const HOST = process.env.HOSTNAME || process.env.HOST || '0.0.0.0';

/* Behind a reverse proxy the client address arrives in a header. Turn this off
   when the server faces the internet directly, otherwise a client can spoof its
   IP and bypass the limits. */
const TRUST_PROXY = process.env.TRUST_PROXY !== 'false';

/* A scan opens dozens of outbound connections, so the number running at once is
   capped hard: beyond it, callers get a 503 rather than a slow queue. */
const MAX_INFLIGHT = Number(process.env.MAX_INFLIGHT || 6);
let inflight = 0;

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
    // Visitor IP addresses are kept out of the logs — only route and status.
    serializers: {
      req: req => ({ method: req.method, url: req.url }),
      res: res => ({ statusCode: res.statusCode }),
    },
  },
  trustProxy: TRUST_PROXY,
  maxParamLength: 300,
  bodyLimit: 8 * 1024,
  disableRequestLogging: process.env.LOG_REQUESTS !== 'true',
});

/* ------------------------------------------------------------------ *
 * Client identification
 * ------------------------------------------------------------------ */

function clientIp(req) {
  if (TRUST_PROXY) {
    for (const header of ['cf-connecting-ip', 'x-real-ip']) {
      const value = req.headers[header];
      if (typeof value === 'string' && value.trim()) return value.trim();
    }
  }
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

/** html | json | yaml | invalid */
function wantedFormat(req) {
  const raw = String(req.query?.output ?? req.query?.format ?? '').toLowerCase().trim();
  if (raw) {
    if (raw === 'json') return 'json';
    if (raw === 'yaml' || raw === 'yml') return 'yaml';
    if (raw === 'html') return 'html';
    return 'invalid';
  }

  const accept = String(req.headers.accept || '');
  if (accept.includes('yaml')) return 'yaml';
  if (/application\/(json|[\w.+-]+\+json)/.test(accept) && !accept.includes('text/html')) return 'json';

  const ua = String(req.headers['user-agent'] || '');
  if (!ua || /^(curl|wget|httpie|python-requests|go-http-client|postmanruntime|okhttp|libwww-perl)/i.test(ua)) {
    return 'json';
  }
  return 'html';
}

/* ------------------------------------------------------------------ *
 * Security headers
 * ------------------------------------------------------------------ */

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  'upgrade-insecure-requests',
].join('; ');

app.addHook('onSend', async (req, reply) => {
  reply.header('content-security-policy', CSP);
  reply.header('x-content-type-options', 'nosniff');
  reply.header('x-frame-options', 'DENY');
  reply.header('referrer-policy', 'strict-origin-when-cross-origin');
  reply.header('permissions-policy', 'geolocation=(), camera=(), microphone=(), payment=(), usb=()');
  reply.header('cross-origin-opener-policy', 'same-origin');
  if (process.env.HSTS === 'true') {
    reply.header('strict-transport-security', 'max-age=31536000; includeSubDomains');
  }
});

/* ------------------------------------------------------------------ *
 * Rate limiting
 * ------------------------------------------------------------------ */

await app.register(rateLimit, {
  global: true,
  max: Number(process.env.RATE_MAX || 120),
  timeWindow: process.env.RATE_WINDOW || '1 minute',
  ban: Number(process.env.RATE_BAN || 8),
  cache: 20000,
  keyGenerator: req => clientIp(req),
  addHeadersOnExceeding: { 'x-ratelimit-limit': true, 'x-ratelimit-remaining': true },
  addHeaders: {
    'x-ratelimit-limit': true, 'x-ratelimit-remaining': true,
    'x-ratelimit-reset': true, 'retry-after': true,
  },
  errorResponseBuilder: (req, ctx) => ({
    statusCode: 429,
    error: 'Too Many Requests',
    message: `Rate limit of ${ctx.max} requests exceeded. Retry in ${Math.ceil(ctx.ttl / 1000)}s.`,
    retryAfterSeconds: Math.ceil(ctx.ttl / 1000),
  }),
});

/** A scan is expensive for us and noticeable for the target, so it is metered. */
const scanLimit = {
  rateLimit: {
    max: Number(process.env.RATE_SCAN_MAX || 12),
    timeWindow: process.env.RATE_SCAN_WINDOW || '1 minute',
  },
};

/* ------------------------------------------------------------------ *
 * Static assets
 * ------------------------------------------------------------------ */

await app.register(fastifyStatic, {
  root: PUBLIC_DIR,
  prefix: '/static/',
  index: false,
  maxAge: '1h',
  immutable: false,
  dotfiles: 'deny',
});

const INDEX_HTML = readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8');

function sendHtml(reply) {
  return reply
    .type('text/html; charset=utf-8')
    .header('cache-control', 'public, max-age=300')
    .send(INDEX_HTML);
}

/* ------------------------------------------------------------------ *
 * Serving data
 * ------------------------------------------------------------------ */

/** Strips undefined so YAML does not emit empty keys. */
function clean(value) {
  if (Array.isArray(value)) return value.map(clean);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (v === undefined) continue;
      out[k] = clean(v);
    }
    return out;
  }
  return value;
}

function sendData(reply, format, payload, { filename, status = 200 } = {}) {
  const body = clean(payload);
  reply.code(status);
  if (format === 'yaml') {
    if (filename) reply.header('content-disposition', `attachment; filename="${filename}.yaml"`);
    return reply
      .type('application/yaml; charset=utf-8')
      .header('cache-control', 'no-store')
      .send(YAML.stringify(body, { lineWidth: 0 }));
  }
  if (filename) reply.header('content-disposition', `attachment; filename="${filename}.json"`);
  return reply
    .type('application/json; charset=utf-8')
    .header('cache-control', 'no-store')
    .send(JSON.stringify(body, null, 2));
}

/** Error codes that have a message of their own; anything else is a scan failure. */
const KNOWN_ERRORS = new Set([
  'invalid-host', 'invalid-port', 'port-not-allowed', 'dns-failed',
  'private-address', 'tls-unreachable', 'scan-timeout', 'busy', 'bad-output',
]);

function errorPayload(err, lang) {
  const code = err.code && KNOWN_ERRORS.has(err.code) ? err.code : 'scan-failed';
  const payload = {
    statusCode: err.status || 502,
    error: code,
    message: t(lang, `err_${code.replace(/-/g, '_')}`),
    detail: err.detail || undefined,
  };
  // The one message that has to name actual values.
  if (code === 'port-not-allowed') {
    payload.allowedPorts = [...allowedPorts()].sort((a, b) => a - b);
  }
  return payload;
}

/** Shared entry point for the data routes. */
async function runScan(req, reply, rawHost, format) {
  const lang = pickLang(req);

  if (inflight >= MAX_INFLIGHT) {
    return sendData(reply, format, errorPayload({ code: 'busy', status: 503 }, lang), { status: 503 });
  }

  inflight++;
  try {
    const report = await scanCached(rawHost, {
      port: Number(req.query?.port) || 443,
      refresh: req.query?.refresh === '1' || req.query?.refresh === 'true',
    });
    const download = req.query?.download === '1' || req.query?.download === 'true';
    return sendData(reply, format, localizeReport(report, lang), {
      filename: download ? `ssltest-${report.host}-${report.port}` : undefined,
    });
  } catch (err) {
    const payload = errorPayload(err, lang);
    if (payload.statusCode >= 500) req.log.error({ err: err.message, host: rawHost }, 'scan failed');
    return sendData(reply, format, payload, { status: payload.statusCode });
  } finally {
    inflight--;
  }
}

/* ------------------------------------------------------------------ *
 * Routes
 * ------------------------------------------------------------------ */

app.get('/healthz', { config: { rateLimit: false } }, async () => ({
  status: 'ok',
  uptime: Math.round(process.uptime()),
  cache: cacheStats(),
  trustStores: trustStats(),
  languages: SUPPORTED_LANGS,
  inflight,
}));

app.get('/robots.txt', { config: { rateLimit: false } }, async (req, reply) =>
  reply.type('text/plain; charset=utf-8').send(
    // Crawlers are welcome on the home page only: walking arbitrary host names
    // would turn every crawl into a burst of outbound scans.
    'User-agent: *\nAllow: /$\nDisallow: /api\nDisallow: /\n'
  )
);

app.get('/favicon.ico', { config: { rateLimit: false } }, async (req, reply) => reply.code(204).send());

/** What a console client sees at the root: how to use the thing. */
const USAGE = {
  service: 'ssltest',
  usage: {
    scan: 'GET /<host>              — full TLS report (JSON for console clients)',
    api: 'GET /api/<host>          — always data',
    yaml: 'GET /api/<host>?output=yaml',
    stream: 'GET /api/stream/<host>   — server-sent events with live progress',
    port: 'GET /api/<host>:8443     — or ?port=8443',
    refresh: 'add ?refresh=1 to bypass the 10-minute cache',
    lang: 'add ?lang=ru to get the labels in another language (Accept-Language is honoured too)',
  },
  allowedPorts: [...allowedPorts()].sort((a, b) => a - b),
  languages: LANG_NAMES,
  stages: STAGES,
};

app.get('/', { config: scanLimit }, async (req, reply) => {
  const format = wantedFormat(req);
  if (format === 'invalid') {
    return sendData(reply, 'json',
      errorPayload({ code: 'bad-output', status: 400 }, pickLang(req)), { status: 400 });
  }
  if (format === 'html') return sendHtml(reply);
  return sendData(reply, format, USAGE);
});

app.get('/api', { config: scanLimit }, async (req, reply) =>
  sendData(reply, wantedFormat(req) === 'yaml' ? 'yaml' : 'json', USAGE));

app.get('/api/:host', { config: scanLimit }, async (req, reply) => {
  const wanted = wantedFormat(req);
  if (wanted === 'invalid') {
    return sendData(reply, 'json',
      errorPayload({ code: 'bad-output', status: 400 }, pickLang(req)), { status: 400 });
  }
  return runScan(req, reply, req.params.host, wanted === 'yaml' ? 'yaml' : 'json');
});

/**
 * The same scan, streamed. A full report takes seconds, and watching the stages
 * go by is much better than staring at a spinner.
 */
app.get('/api/stream/:host', { config: scanLimit }, (req, reply) => {
  const lang = pickLang(req);
  const target = parseTarget(req.params.host, Number(req.query?.port) || 443);
  if (target.error) {
    return sendData(reply, 'json',
      errorPayload({ code: target.error, status: 400 }, lang), { status: 400 });
  }
  if (inflight >= MAX_INFLIGHT) {
    return sendData(reply, 'json', errorPayload({ code: 'busy', status: 503 }, lang), { status: 503 });
  }

  reply.hijack();
  const raw = reply.raw;
  raw.writeHead(200, {
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-store, no-transform',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
    'content-security-policy': CSP,
    'x-content-type-options': 'nosniff',
  });

  let closed = false;
  const send = (event, data) => {
    if (closed || raw.writableEnded) return;
    raw.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  req.raw.on('close', () => { closed = true; });

  // A comment every 15 seconds keeps proxies from closing an idle stream.
  const keepAlive = setInterval(() => { if (!closed) raw.write(': ping\n\n'); }, 15000);

  inflight++;
  send('start', { host: target.host, port: target.port, stages: STAGES });

  scanCached(req.params.host, {
    port: Number(req.query?.port) || 443,
    refresh: req.query?.refresh === '1' || req.query?.refresh === 'true',
    onProgress: event => send('progress', event),
  })
    .then(report => send('report', localizeReport(report, lang)))
    .catch(err => send('failed', errorPayload(err, lang)))
    .finally(() => {
      inflight--;
      clearInterval(keepAlive);
      if (!closed && !raw.writableEnded) raw.end();
    });
});

/** The pretty route: /example.com — a page for browsers, data for everyone else. */
app.get('/:host', { config: scanLimit }, async (req, reply) => {
  const format = wantedFormat(req);
  if (format === 'invalid') {
    return sendData(reply, 'json',
      errorPayload({ code: 'bad-output', status: 400 }, pickLang(req)), { status: 400 });
  }
  if (format === 'html') {
    // The page fetches its own data, so an unknown host still renders and shows
    // the error itself — except for outright junk, which gets a 404.
    const target = parseTarget(req.params.host, Number(req.query?.port) || 443);
    if (target.error === 'invalid-host') {
      return reply.code(404).type('text/html; charset=utf-8').send(NOT_FOUND_HTML);
    }
    return sendHtml(reply);
  }
  return runScan(req, reply, req.params.host, format);
});

const NOT_FOUND_HTML = `<!doctype html><meta charset="utf-8">
<title>404</title>
<style>body{font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#0a0e16;color:#e6ecf5;display:grid;place-items:center;height:100vh;margin:0;text-align:center}
a{color:#38bdf8}code{background:#121a28;padding:2px 6px;border-radius:6px}</style>
<div><h1>404</h1><p>Expected the site root or a host name in the path:<br>
<code>/example.com</code> · <code>/example.com:8443</code></p>
<p><a href="/">Go home</a></p></div>`;

app.setNotFoundHandler({ config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, (req, reply) => {
  if (wantedFormat(req) === 'html') {
    return reply.code(404).type('text/html; charset=utf-8').send(NOT_FOUND_HTML);
  }
  return reply.code(404).send({ statusCode: 404, error: 'Not Found', message: 'Route not found.' });
});

/* ------------------------------------------------------------------ *
 * Startup
 * ------------------------------------------------------------------ */

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, async () => {
    app.log.info(`${signal} received, shutting down`);
    await app.close();
    process.exit(0);
  });
}

try {
  await app.listen({ port: PORT, host: HOST });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

export { app };
