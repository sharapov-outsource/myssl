# ssltest

Deep analysis of the TLS configuration of any public server: which protocol
versions it speaks, which cipher suites it accepts and in what order, what its
certificate chain looks like, which known weaknesses its configuration implies,
and a letter grade that says what all of it adds up to.

Built the same way as [myip](https://github.com/sharapov-outsource/myip): one
small Fastify server, no build step, no database, a page that works without a
framework, and the same report available as JSON or YAML for the command line.

**Live:** <https://myssl.sharapov.biz>

```bash
curl https://myssl.sharapov.biz/github.com
```

---

## What it actually does

Node's own `tls` module cannot answer most of the questions this service asks:
it will not offer a single cipher suite of your choosing, it hides SSL 3.0
entirely, it cannot walk TLS 1.3 suites one at a time, and it never shows the
raw certificate chain exactly as the server sent it. So `server/tls-probe.js`
assembles ClientHello messages by hand, writes them to a plain TCP socket and
parses the server's answer up to ServerHelloDone — or up to ServerHello for
TLS 1.3, where everything after it is already encrypted.

No handshake is ever completed by the prober: no keys are derived, no
application data is sent. Each probe is one TCP connection, closed as soon as
the interesting bytes have arrived.

Everything the prober cannot see — the certificate of a TLS 1.3-only server,
ALPN in TLS 1.3, session resumption — is measured with a real handshake in
`server/node-tls.js`. Trust is decided separately, in `server/trust.js`.

### Checks

| Area | What is measured |
| --- | --- |
| Protocols | SSL 2.0, SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3 — each asked for separately |
| Cipher suites | Every accepted suite per protocol version, in the order the server picks them, plus whether the server enforces its own preference |
| Key exchange | Supported groups in the server's preferred order, finite-field DH modulus size, the ephemeral key actually negotiated |
| Certificate | Subject, issuer, validity, key type and strength, signature algorithm, SANs, validation level (DV/OV/EV), Certificate Transparency timestamps, must-staple, serial, fingerprints, SPKI pin |
| Chain | Order, completeness, signatures, trust anchor and which store it came from, extra or missing intermediates, host name match, stapled OCSP status |
| Features | ALPN and HTTP/2, OCSP stapling, session resumption and tickets, extended master secret, encrypt-then-MAC, secure renegotiation, client-initiated renegotiation, TLS compression, `TLS_FALLBACK_SCSV`, whether SNI is required, client certificate requests |
| Weaknesses | DROWN, POODLE, BEAST, FREAK, Logjam, Sweet32, RC4, NULL/anonymous suites, CRIME, Heartbleed (extension check), insecure renegotiation, renegotiation DoS, ROBOT, Lucky 13, missing downgrade protection, missing forward secrecy, weak DH |
| HTTP | Status and redirect chain, HSTS with all its flags, security headers, cookie flags, HTTP/3 advertisement, `Server` header |
| DNS | A, AAAA, reverse DNS, CAA — including whether CAA covers the authority that actually issued the certificate |
| Clients | 13 client profiles (Chrome, Firefox, Safari, Edge, Android, iOS, OpenSSL, Java 8 and 17, Python, Windows 7 and XP) — what each would negotiate, or why it cannot connect |

### What it deliberately does not do

Every verdict comes from configuration the server volunteers during an ordinary
handshake. Nothing is confirmed by attacking the server: no malformed heartbeat,
no padding-oracle probing, no forced downgrade with real traffic. Where that
leaves genuine doubt, the finding says `possible` instead of pretending to be
sure — Heartbleed (the extension may be advertised by a patched OpenSSL) and
ROBOT (RSA key transport is a precondition, not a proof) are the two cases where
this matters most.

Not covered at all: Ticketbleed, Zombie POODLE, GOLDENDOODLE and the other
padding-oracle variants, because detecting them means sending deliberately
malformed records to somebody else's server.

---

## Trust anchors

Whether a certificate is trusted must not depend on the machine the scanner runs
on — and with Node it otherwise does, because some builds consult the operating
system store. So the chain is walked here against stores the repository
controls:

* **`mozilla`** — the CA list Node ships with, which is what browsers use.
* **`server/roots/*.pem`** — extra anchors no browser carries. A chain that ends
  there is reported as trusted, with `trustStore` naming the store and a
  `trusted-by-extra-root` warning that keeps it away from an A+, because a
  browser with nothing installed will still refuse the site.

One extra store ships with the service: the national CA of the Russian Ministry
of Digital Development (Минцифры), which Russian banks and state services use —
`alfabank.ru`, `sberbank.ru` and the like would otherwise come back as **T**.
The certificates are the ministry's own copies, downloaded from the pages it
publishes them on (<https://www.gosuslugi.ru/crt>,
`gu-st.ru/content/Other/doc/russian_trusted_root_ca.cer` and
`russiantrustedca.pem`), and the file records their fingerprints so they can be
checked against that source at any time. The root's fingerprint also matches the
chains alfabank.ru, sberbank.ru and vtb.ru serve, which is an independent check
on the same bytes.

Both the root and the intermediate are included, because the ministry
distributes both for installation and a client that followed those instructions
accepts a server that sends only its leaf.

Adding another anchor is dropping a PEM file into `server/roots/` — a corporate
root, a private CA — or pointing `EXTRA_CA_DIR` somewhere else. The file name
becomes the store id, so add a `store_<name>` translation for it as well;
`npm run check:i18n` will insist.

```json
"certificate": {
  "trusted": true,
  "browserTrusted": false,
  "trustStore": "russian-trusted-ca",
  "trustStoreLabel": "Russian Trusted CA (Минцифры) — only where that root is installed",
  "trustAnchor": "Russian Trusted Root CA"
}
```

---

## The grade

The rating follows the structure Qualys published in the SSL Server Rating
Guide: three weighted components, then caps, then a bonus.

```
score = 0.30 × protocol support
      + 0.30 × key exchange
      + 0.40 × cipher strength
```

* **Protocol support** — the average of the best and the worst version on offer.
  SSL 2.0 scores 0, SSL 3.0 80, TLS 1.0 90, TLS 1.1 95, TLS 1.2 and 1.3 100.
* **Key exchange** — driven by the weakest key involved: the certificate key,
  the DH group and the EC group, compared in RSA-equivalent bits.
* **Cipher strength** — the average of the strongest and weakest accepted suite.

`≥ 80 → A`, `≥ 65 → B`, `≥ 50 → C`, `≥ 35 → D`, `≥ 20 → E`, otherwise `F`.

Then the caps apply — SSL 2.0, insecure renegotiation, NULL/anonymous or export
suites and Logjam drop the result to **F**; TLS compression, Sweet32 and SSL 3.0
cap it at **C**; RC4, no forward secrecy, a sub-2048-bit DH group and TLS 1.0/1.1
cap it at **B**. A certificate that browsers will not trust overrides everything
with **T**, and a name mismatch with **M**.

Finally, an **A** with HSTS of at least 180 days becomes **A+**, provided none of
the warnings that describe a real risk are present — no TLS 1.3, the heartbeat
extension, client-initiated renegotiation, no Certificate Transparency, or a
certificate valid for more than 398 days. Those turn an **A** into **A-**
instead. The remaining warnings (RSA key transport, suites without forward
secrecy, a needlessly sent root, no OCSP stapling) are reported but do not stand
in the way of an A+: plenty of well-run sites keep them for old clients.

This is an independent implementation of a public methodology, updated for what
matters today. It is not affiliated with, endorsed by, or guaranteed to agree
with Qualys SSL Labs.

---

## API

Everything the page shows is available as data. Console clients (curl, wget,
httpie, …) get JSON without asking.

```bash
curl https://myssl.sharapov.biz/example.com              # full report
curl https://myssl.sharapov.biz/api/example.com          # the same, explicitly
curl https://myssl.sharapov.biz/api/example.com:8443     # a different port
curl "https://myssl.sharapov.biz/api/example.com?output=yaml"
curl "https://myssl.sharapov.biz/api/example.com?refresh=1"     # bypass the cache
curl "https://myssl.sharapov.biz/api/example.com?download=1"    # as an attachment
curl "https://myssl.sharapov.biz/api/example.com?lang=ru"       # labels in Russian
```

### Readable output

The report is built out of machine codes — `sweet32`, `legacy-tls-versions`,
`trusted-by-extra-root` — which is right for a data format and unreadable in a
terminal. So every code is accompanied by a label, in any of the twelve
interface languages. The codes never move or change, so scripts keep working:

```bash
curl -s "https://myssl.sharapov.biz/api/badssl.com?lang=de" |
  jq -r '.vulnerabilities[] | select(.status != "safe") |
         "\(.severityLabel)\t\(.statusLabel)\t\(.name) — \(.description)"'
```

```
mittel   verwundbar   Sweet32 — 64-Bit-Blockchiffren (3DES, IDEA, DES) geben …
kritisch möglich      Heartbleed — Die Heartbeat-Erweiterung ist aktiv. …
```

Labelled fields: `vulnerabilities[].name` / `.description` / `.severityLabel` /
`.statusLabel`, `grade.caps[].label`, `grade.warningLabels`,
`certificate.issueLabels`, `certificate.trustStoreLabel`,
`certificate.leaf.validationLabel`, `certificate.ocsp.certStatusLabel`,
`ciphers[…].orderLabel` and each suite's `strengthLabel` / `issueLabels`.
The language used is echoed back in `meta.language`.

The language comes from `?lang=`, or from `Accept-Language`, or falls back to
English — error messages included.

`?output=json` and `?output=yaml` work on every address — the pretty route, the
`/api` route and the root.

| Route | Purpose |
| --- | --- |
| `GET /` | the page (JSON usage summary for console clients) |
| `GET /<host>` | report — page for browsers, data for everyone else |
| `GET /api/<host>` | always data |
| `GET /api/stream/<host>` | the same scan as server-sent events, with progress |
| `GET /healthz` | liveness, cache statistics, scans in flight |

Query parameters: `output=json|yaml|html`, `port=`, `refresh=1`, `download=1`,
`lang=` (any of the twelve languages).

### Live progress

A scan takes seconds, so the page follows it over SSE rather than waiting:

```bash
curl -N https://myssl.sharapov.biz/api/stream/example.com
```

```
event: start
data: {"host":"example.com","port":443,"stages":["resolve","handshake", …]}

event: progress
data: {"stage":"ciphers","elapsedMs":912,"version":"TLS 1.2","found":18}

event: report
data: { …the full report… }
```

Events: `start`, `progress`, `report`, `failed`.

### Shape of a report

```jsonc
{
  "host": "github.com", "port": 443, "ip": "140.82.121.3",
  "grade": {
    "grade": "A-", "score": 93,
    "components": { "protocol": {…}, "keyExchange": {…}, "cipher": {…} },
    "caps": [], "warnings": ["some-suites-without-pfs", "no-ocsp-stapling"]
  },
  "certificate": { "leaf": {…}, "chain": […], "trusted": true, "issues": [] },
  "protocols":  [{ "name": "TLS 1.3", "supported": true }, …],
  "ciphers":    { "TLS 1.3": { "order": "server", "suites": [{ "hex": "0x1301", … }] } },
  "keyExchange": { "groups": [{ "id": 29, "name": "x25519" }], "dh": null },
  "features":   { "http2": true, "ocspStapling": false, … },
  "vulnerabilities": [{ "id": "sweet32", "severity": "medium", "status": "safe", "cve": "…" }],
  "http":       { "hsts": {…}, "headers": {…}, "cookies": […] },
  "dns":        { "addresses": […], "caa": {…} },
  "simulation": [{ "client": "Chrome 131", "protocol": "TLS 1.3", "cipher": "…" }],
  "meta":       { "elapsedMs": 4749, "connections": 25, "cached": false }
}
```

---

## Running it

```bash
npm install
npm start          # http://localhost:3024
npm run dev        # same, restarts on change
```

From the command line, without the server:

```bash
npm run scan -- github.com
npm run scan -- example.com:8443 --json
```

### Docker

```bash
docker build -t ssltest .
docker run --rm -p 3024:3024 ssltest
```

The image runs as a non-root user, needs no writable filesystem, and is deployed
by `.github/workflows/deploy.yml` — build, push to GHCR, pull and restart over
SSH, with a health check before the run is called green.

### Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `3024` | listening port |
| `HOSTNAME` | `0.0.0.0` | listening address |
| `TRUST_PROXY` | `true` | read the client address from `X-Forwarded-For` / `CF-Connecting-IP`. Turn **off** when the server faces the internet directly, or clients can spoof their address and bypass the limits |
| `HSTS` | — | set to `true` to send `Strict-Transport-Security` |
| `MAX_INFLIGHT` | `6` | scans allowed to run at once; beyond it callers get a 503 |
| `RATE_MAX` / `RATE_WINDOW` | `120` / `1 minute` | global rate limit per client |
| `RATE_SCAN_MAX` / `RATE_SCAN_WINDOW` | `12` / `1 minute` | rate limit on the scan routes |
| `ALLOWED_PORTS` | 443, 8443, 993, 995, 465, … | ports that may be scanned |
| `SCAN_TIMEOUT_MS` | `60000` | hard ceiling for one scan |
| `PROBE_TIMEOUT_MS` | `8000` | timeout for a single connection |
| `CACHE_TTL_MS` | `600000` | how long a report is reused |
| `CACHE_MAX` | `500` | reports kept in memory |
| `EXTRA_CA_DIR` | `server/roots` | directory of extra trust anchors, in PEM |
| `ALLOW_PRIVATE_TARGETS` | `false` | allow scanning private ranges. Only for tests — leaving this on turns the service into a port scanner for whatever network it runs in |
| `LOG_LEVEL` | `info` | pino level |

### Being a good citizen

A scan opens several dozen connections to the target within a few seconds. To
keep that from becoming a nuisance:

* private, loopback, link-local and reserved ranges are refused, and a literal
  address is checked before any lookup happens;
* only well-known TLS ports may be scanned;
* per-client rate limits and a global ceiling on concurrent scans;
* results are cached for ten minutes, and two requests for the same target that
  arrive together share one scan;
* `robots.txt` allows the home page only, so a crawler cannot turn a walk of the
  site into a burst of outbound scans.

Scan only servers you are allowed to test.

---

## Tests

```bash
npm test            # syntax, translations, unit tests, smoke test
npm run test:unit   # includes two end-to-end scans of a local TLS server
npm run smoke       # boots the HTTP server and exercises its routes
```

The end-to-end tests generate a throwaway self-signed certificate with `openssl`,
start a TLS server on the loopback interface and scan it, so the full pipeline —
protocol detection, cipher walking, certificate analysis, findings, grading — is
covered without touching the network. They skip themselves if `openssl` is not
on the path.

---

## Translations

Twelve languages: English, Russian, Spanish, Chinese, Hindi, Arabic (with the
layout mirrored), Portuguese, French, German, Japanese, Turkish and Ukrainian.
`public/i18n.js` holds one object per language; to add one, copy `en`, translate
the values and register the code in `LANG_NAMES` and `LANG_LOCALES`.

That one file serves both sides: the page reads it as a script, and the server
evaluates it in a sandbox to label the API output, so a translation can never be
right in the browser and missing in the JSON.

`npm run check:i18n` fails on any key that drifts apart — including the codes
built at runtime, which it reads out of `server/vulns.js`, `server/grade.js`,
`server/cert.js` and the file names in `server/roots/`, so a new finding, a new
rating cap or a new trust store cannot ship untranslated.

---

## Layout

```
server/
  index.js        Fastify: routes, output formats, SSE, rate limits, headers
  scan.js         orchestration, caching, target validation, progress events
  tls-probe.js    hand-written ClientHello/ServerHello over a raw socket
  enumerate.js    scanning strategies built on the prober
  suites.js       cipher suite registry; properties derived from the names
  node-tls.js     the checks that need a real handshake
  trust.js        trust anchors: the Mozilla list plus anything in roots/
  roots/          extra trust anchors in PEM, one store per file
  cert.js         certificate and chain analysis
  i18n.js         labels for the API, read from the page's own dictionary
  asn1.js         a very small DER reader for what X509Certificate hides
  http-probe.js   HSTS, redirects, security headers, cookies
  dns-probe.js    A, AAAA, PTR, CAA
  vulns.js        known weaknesses, derived from the observed configuration
  grade.js        the letter grade
public/           the page: no framework, no build step
scripts/          CLI scan, smoke test, translation check
test/             unit tests and end-to-end scans of a local server
```

## Licence

MIT.
