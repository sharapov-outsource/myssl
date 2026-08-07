/**
 * What the site does on top of TLS: HSTS, the redirect from plain HTTP, the
 * usual security headers, cookie flags and which HTTP versions are on offer.
 *
 * One HEAD-like GET is issued and the body is discarded as soon as the headers
 * are in, so nothing large is ever downloaded.
 */

import https from 'node:https';
import http from 'node:http';

const MAX_REDIRECTS = 5;
const MAX_BODY = 8 * 1024;

const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'content-security-policy-report-only',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'cross-origin-embedder-policy',
  'expect-ct',
  'alt-svc',
  'server',
  'x-powered-by',
  'x-aspnet-version',
];

/** One request, following nothing. Never throws. */
function request(url, { timeout = 8000, ip, servername, alpn } = {}) {
  return new Promise(resolve => {
    const target = new URL(url);
    const secure = target.protocol === 'https:';
    const lib = secure ? https : http;

    const options = {
      method: 'GET',
      host: ip || target.hostname,
      servername: servername || target.hostname,
      port: target.port || (secure ? 443 : 80),
      path: target.pathname + target.search,
      headers: {
        host: target.host,
        'user-agent': process.env.OUTBOUND_USER_AGENT || 'ssltest/1.0 (+https://myssl.sharapov.biz)',
        accept: 'text/html,*/*;q=0.8',
        'accept-encoding': 'identity',
        connection: 'close',
      },
      timeout,
      rejectUnauthorized: false,
      ALPNProtocols: alpn,
    };

    const req = lib.request(options, res => {
      let size = 0;
      let body = '';
      res.on('data', chunk => {
        size += chunk.length;
        if (body.length < MAX_BODY) body += chunk.toString('latin1');
        if (size > MAX_BODY) res.destroy();
      });
      const done = () => resolve({
        ok: true,
        status: res.statusCode,
        headers: res.headers,
        alpnProtocol: res.socket?.alpnProtocol || null,
        httpVersion: res.httpVersion,
        body,
      });
      res.on('end', done);
      res.on('close', done);
      res.on('error', done);
    });

    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
    req.on('error', err => resolve({ ok: false, error: err.code || err.message }));
    req.end();
  });
}

/** Strict-Transport-Security, split into the parts that matter for the rating. */
export function parseHsts(value) {
  if (!value) return { present: false };
  const header = Array.isArray(value) ? value[0] : value;
  const maxAge = /max-age\s*=\s*"?(\d+)"?/i.exec(header);
  const seconds = maxAge ? Number(maxAge[1]) : 0;
  return {
    present: true,
    header,
    maxAge: seconds,
    days: Math.round(seconds / 86400),
    includeSubDomains: /includesubdomains/i.test(header),
    preload: /preload/i.test(header),
    // 180 days is the threshold SSL Labs uses before it will hand out an A+.
    longEnough: seconds >= 15552000,
  };
}

function parseCookies(setCookie) {
  const list = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  return list.slice(0, 12).map(raw => {
    const [pair] = raw.split(';');
    const name = pair.split('=')[0].trim();
    const sameSite = /samesite\s*=\s*(\w+)/i.exec(raw);
    return {
      name,
      secure: /;\s*secure/i.test(raw),
      httpOnly: /;\s*httponly/i.test(raw),
      sameSite: sameSite ? sameSite[1] : undefined,
      prefixSecure: name.startsWith('__Secure-') || name.startsWith('__Host-'),
    };
  });
}

/**
 * @param {object} target { host, ip, port, servername }
 */
export async function probeHttp(target) {
  const { host, port = 443, ip, servername } = target;
  const base = `https://${host}${port === 443 ? '' : ':' + port}/`;

  // HTTP/2 is answered by ALPN during the handshake, not here: this request
  // deliberately speaks HTTP/1.1 so the headers can be read the simple way.
  const [first, plain] = await Promise.all([
    request(base, { ip, servername, alpn: ['http/1.1'] }),
    // Only a standard site has anything meaningful on port 80.
    port === 443 ? request(`http://${host}/`, { ip, timeout: 6000 }) : Promise.resolve(null),
  ]);

  if (!first.ok) return { reachable: false, error: first.error };

  /* Follow redirects so the security headers of the page people actually land
     on are the ones being judged. */
  const redirects = [];
  let current = first;
  let currentUrl = base;
  for (let i = 0; i < MAX_REDIRECTS && current.ok && isRedirect(current.status); i++) {
    const location = current.headers.location;
    if (!location) break;
    const next = new URL(location, currentUrl);
    redirects.push({ from: currentUrl, to: next.href, status: current.status });
    if (next.hostname !== host) break;     // leaving the host ends the trail
    currentUrl = next.href;
    current = await request(next.href, { ip, servername });
  }

  const headers = current.ok ? current.headers : first.headers;
  const security = {};
  for (const name of SECURITY_HEADERS) {
    const value = headers[name];
    if (value !== undefined) security[name] = Array.isArray(value) ? value.join(', ') : value;
  }

  const plainRedirect = plain?.ok
    ? {
      status: plain.status,
      location: plain.headers.location || null,
      toHttps: isRedirect(plain.status) && /^https:/i.test(plain.headers.location || ''),
      // A redirect that goes somewhere else first loses the HSTS header on the
      // way, which is why SSL Labs treats it as a weaker setup.
      direct: isRedirect(plain.status) &&
        (plain.headers.location || '').replace(/^https:\/\//i, '').replace(/\/$/, '') ===
        host.replace(/\/$/, ''),
    }
    : plain ? { error: plain.error } : null;

  return {
    reachable: true,
    status: first.status,
    finalStatus: current.ok ? current.status : first.status,
    finalUrl: currentUrl,
    redirects,
    httpVersion: first.httpVersion,
    http3: /h3/.test(String(headers['alt-svc'] || '')),
    hsts: parseHsts(headers['strict-transport-security']),
    headers: security,
    cookies: parseCookies(headers['set-cookie']),
    server: headers.server || null,
    plainHttp: plainRedirect,
  };
}

function isRedirect(status) {
  return status >= 300 && status < 400;
}
