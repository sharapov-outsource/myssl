/**
 * Smoke test: boots the server and exercises its routes.
 *
 * Deliberately avoids scanning anything on the internet — the checks use
 * malformed targets, refused ports and private addresses, all of which are
 * answered locally. That keeps the test deterministic and lets it pass in CI
 * without outbound access. The scanning engine itself is covered by
 * `npm run test:unit`, which scans a TLS server it starts on the loopback.
 */
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 3398;
const base = `http://127.0.0.1:${PORT}`;

const server = spawn(process.execPath, ['server/index.js'], {
  cwd: root,
  env: {
    ...process.env,
    PORT: String(PORT), HOSTNAME: '127.0.0.1', TRUST_PROXY: 'false', LOG_LEVEL: 'warn',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let serverOutput = '';
server.stdout.on('data', d => { serverOutput += d; });
server.stderr.on('data', d => { serverOutput += d; });

const failures = [];
let checks = 0;

function check(name, condition, detail) {
  checks++;
  if (condition) return;
  failures.push(detail ? `${name} — ${detail}` : name);
}

async function waitForServer(attempts = 40) {
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(`${base}/healthz`);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise(r => setTimeout(r, 250));
  }
  throw new Error('server never answered /healthz\n' + serverOutput);
}

async function run() {
  await waitForServer();

  // Health and service routes.
  const health = await (await fetch(`${base}/healthz`)).json();
  check('healthz: status', health.status === 'ok');
  check('healthz: cache stats', typeof health.cache?.entries === 'number');
  const robots = await fetch(`${base}/robots.txt`);
  check('robots.txt', robots.ok);
  check('robots.txt: points at the sitemap', (await robots.text()).includes('Sitemap:'));

  const sitemap = await fetch(`${base}/sitemap.xml`);
  check('sitemap.xml', sitemap.ok);
  check('sitemap.xml: lists the home page', (await sitemap.text()).includes('<loc>'));

  const favicon = await fetch(`${base}/favicon.ico`);
  check('favicon.ico', favicon.ok);
  check('favicon.ico: is an icon', (favicon.headers.get('content-type') || '').includes('icon'));

  // The page for browsers.
  const page = await fetch(`${base}/example.com`, {
    headers: { accept: 'text/html', 'user-agent': 'Mozilla/5.0' },
  });
  const html = await page.text();
  check('html: status', page.status === 200);
  check('html: content-type', (page.headers.get('content-type') || '').includes('text/html'));
  check('html: links app.js', html.includes('/static/app.js'));
  check('html: links i18n.js', html.includes('/static/i18n.js'));

  // The head is filled in per request: no placeholder may survive.
  check('html: no placeholders left', !/%(ORIGIN|URL|ROBOTS|LANG|DIR|TITLE|DESCRIPTION|LOCALE)%/.test(html),
    (html.match(/%[A-Z]+%/) || [])[0]);
  check('html: absolute canonical', html.includes(`<link rel="canonical" href="${base}/example.com"`));
  check('html: report pages are not indexed', html.includes('content="noindex, follow"'));
  check('html: social image', html.includes(`content="${base}/static/og-image.png"`));
  check('html: icons', html.includes('/static/icon.svg') && html.includes('/static/apple-touch-icon.png'));
  check('html: manifest', html.includes('/static/site.webmanifest'));

  // The head is translated by the same dictionary the page uses.
  const russian = await (await fetch(`${base}/`, {
    headers: { accept: 'text/html', 'user-agent': 'Mozilla/5.0', 'accept-language': 'ru-RU,ru;q=0.9' },
  })).text();
  check('html: honours accept-language', russian.includes('<html lang="ru"'));
  check('html: translated title', /<title>SSL Test — подробный/.test(russian), russian.match(/<title>[^<]*/)?.[0]);
  const arabic = await (await fetch(`${base}/`, {
    headers: { accept: 'text/html', 'user-agent': 'Mozilla/5.0', 'accept-language': 'ar' },
  })).text();
  check('html: right-to-left for arabic', arabic.includes('<html lang="ar" dir="rtl"'));
  check('html: home page is indexed', arabic.includes('content="index, follow"'));

  // Console clients get data without asking.
  const usage = await fetch(`${base}/`, { headers: { 'user-agent': 'curl/8.7.1' } });
  check('curl -> json', (usage.headers.get('content-type') || '').includes('json'));
  const usageBody = await usage.json();
  check('usage: describes the api', typeof usageBody.usage?.scan === 'string');
  check('usage: lists allowed ports', Array.isArray(usageBody.allowedPorts) && usageBody.allowedPorts.includes(443));

  // Input validation, all answered before a single packet leaves the box.
  const badHost = await fetch(`${base}/api/not%20a%20host`);
  check('invalid host -> 400', badHost.status === 400, `status ${badHost.status}`);
  check('invalid host: error code', (await badHost.json()).error === 'invalid-host');

  const badPort = await fetch(`${base}/api/example.com:22`);
  check('unlisted port -> 400', badPort.status === 400, `status ${badPort.status}`);
  check('unlisted port: error code', (await badPort.json()).error === 'port-not-allowed');

  const traversal = await fetch(`${base}/api/%2Fetc%2Fpasswd`);
  check('path traversal in the host -> 400', traversal.status === 400, `status ${traversal.status}`);

  for (const target of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254']) {
    const res = await fetch(`${base}/api/${target}`);
    check(`private target ${target} -> 403`, res.status === 403, `status ${res.status}`);
  }

  // Output formats.
  check('output=xml -> 400', (await fetch(`${base}/api/example.com?output=xml`)).status === 400);
  const yaml = await fetch(`${base}/api/10.0.0.1?output=yaml`);
  check('yaml: content-type', (yaml.headers.get('content-type') || '').includes('yaml'));
  check('yaml: body', (await yaml.text()).includes('error: private-address'));

  // Streaming: the same refusal, delivered as an event.
  const stream = await fetch(`${base}/api/stream/example.com:22`);
  check('stream: rejects a bad target before starting', stream.status === 400);

  const liveStream = await fetch(`${base}/api/stream/10.0.0.1`);
  check('stream: content-type', (liveStream.headers.get('content-type') || '').includes('text/event-stream'));
  const streamBody = await liveStream.text();
  check('stream: sends a start event', streamBody.includes('event: start'));
  check('stream: reports the failure', streamBody.includes('event: failed'));
  check('stream: names the reason', streamBody.includes('private-address'));

  // Security headers.
  const csp = page.headers.get('content-security-policy') || '';
  check('csp: script-src self', csp.includes("script-src 'self'"));
  check('csp: frame-ancestors none', csp.includes("frame-ancestors 'none'"));
  check('header nosniff', page.headers.get('x-content-type-options') === 'nosniff');
  check('header X-Frame-Options', page.headers.get('x-frame-options') === 'DENY');
  check('header referrer-policy', Boolean(page.headers.get('referrer-policy')));

  // Static assets and directory traversal protection.
  for (const file of ['styles.css', 'app.js', 'i18n.js', 'sharapov.svg',
    'icon.svg', 'apple-touch-icon.png', 'og-image.png', 'site.webmanifest']) {
    const res = await fetch(`${base}/static/${file}`);
    check(`static ${file}`, res.ok, `status ${res.status}`);
  }
  // The traversal is percent-encoded so the client cannot normalise it away
  // before the request reaches the static handler.
  check('directory traversal blocked',
    [400, 403, 404].includes((await fetch(`${base}/static/..%2Fpackage.json`)).status));

  // 404 for unknown routes.
  check('404 on unknown path',
    (await fetch(`${base}/foo/bar/baz`, { headers: { accept: 'application/json' } })).status === 404);

  // Rate limiting on the scan routes.
  const codes = [];
  for (let i = 0; i < 30; i++) {
    codes.push((await fetch(`${base}/api/10.0.0.1`)).status);
  }
  check('rate limit kicks in', codes.includes(429), `codes: ${[...new Set(codes)].join(',')}`);
}

try {
  await run();
} catch (err) {
  failures.push('exception: ' + err.message);
} finally {
  server.kill('SIGTERM');
}

if (failures.length) {
  console.error(`Smoke test failed (${failures.length} of ${checks}):`);
  failures.forEach(f => console.error('  x ' + f));
  process.exit(1);
}

console.log(`Smoke test passed: ${checks} checks.`);
