# myssl

**Русская версия — [ниже](#русская-версия).**

A service that analyses how a server speaks TLS: which protocol versions it
accepts, which cipher suites and in what order, what its certificate chain looks
like, which known weaknesses its configuration implies, and a letter grade that
says what all of it adds up to. Works both as a page and as an API.

```
https://myssl.sharapov.biz                         the page
https://myssl.sharapov.biz/example.com             report for a host
https://myssl.sharapov.biz/example.com:8443        a different port
https://myssl.sharapov.biz/example.com?output=json data instead of the page
https://myssl.sharapov.biz/api/example.com?output=yaml
```

Built the same way as [myip](https://github.com/sharapov-outsource/myip): one
small Fastify server, no build step, no database, a page that works without a
framework.

## What it checks

| Section | Contents |
| --- | --- |
| Protocols | SSL 2.0, SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3 — each asked for separately |
| Cipher suites | Every accepted suite per protocol version, in the order the server picks them, plus whether the server enforces its own preference |
| Key exchange | Supported groups in the server's preferred order, finite-field DH modulus size, the ephemeral key actually negotiated |
| Certificate | Subject, issuer, validity, key type and strength, signature algorithm, SANs, validation level (DV/OV/EV), Certificate Transparency, must-staple, serial, fingerprints, SPKI pin |
| Chain | Order, completeness, signatures, trust anchor and the store it came from, missing or superfluous intermediates, host name match, stapled OCSP status |
| Features | ALPN and HTTP/2, OCSP stapling, session resumption and tickets, extended master secret, encrypt-then-MAC, secure renegotiation, client-initiated renegotiation, TLS compression, `TLS_FALLBACK_SCSV`, whether SNI is required, client certificate requests |
| Weaknesses | DROWN, POODLE, BEAST, FREAK, Logjam, Sweet32, RC4, NULL/anonymous suites, CRIME, Heartbleed, insecure renegotiation, renegotiation DoS, ROBOT, Lucky 13, missing downgrade protection, missing forward secrecy, weak DH |
| HTTP | Status and redirect chain, HSTS with all its flags, security headers, cookie flags, HTTP/3 advertisement, `Server` header |
| DNS | A, AAAA, reverse DNS, CAA — including whether CAA covers the authority that actually issued the certificate |
| Clients | 13 client profiles (Chrome, Firefox, Safari, Edge, Android, iOS, OpenSSL, Java 8 and 17, Python, Windows 7 and XP) — what each would negotiate, or why it cannot connect |

## How it works

Node's own `tls` module cannot answer most of these questions: it will not offer
a single cipher suite of your choosing, it hides SSL 3.0 entirely, it cannot walk
TLS 1.3 suites one at a time, and it never shows the raw certificate chain
exactly as the server sent it. So `server/tls-probe.js` assembles ClientHello
messages by hand, writes them to a plain TCP socket and parses the server's
answer up to ServerHelloDone — or up to ServerHello for TLS 1.3, where everything
after it is already encrypted.

No handshake is ever completed by the prober: no keys are derived, no application
data is sent. Each probe is one TCP connection, closed as soon as the interesting
bytes have arrived. Everything the prober cannot see — the certificate of a
TLS 1.3-only server, ALPN in TLS 1.3, session resumption — is measured with a
real handshake in `server/node-tls.js`.

Cipher enumeration works the way sslscan and testssl.sh do it: a server picks one
suite out of what the client offers, so offering everything, removing whatever
came back and asking again walks the whole list. Groups are enumerated the same
way — in TLS 1.3 by sending no key share at all, which makes the server name its
preferred group in a HelloRetryRequest.

### What it deliberately does not do

Every verdict comes from configuration the server volunteers during an ordinary
handshake. Nothing is confirmed by attacking the server: no malformed heartbeat,
no padding-oracle probing, no forced downgrade with real traffic. Where that
leaves genuine doubt the finding says `possible` instead of pretending to be
sure — Heartbleed (a patched OpenSSL still advertises the extension) and ROBOT
(RSA key transport is a precondition, not a proof) are the two cases where this
matters most.

## Trust anchors

Whether a certificate is trusted must not depend on the machine the scanner runs
on — and with Node it otherwise does, because some builds consult the operating
system store. So the chain is walked against stores this repository controls:

* **`mozilla`** — the CA list Node ships with, which is what browsers use.
* **`server/roots/*.pem`** — extra anchors no browser carries. A chain that ends
  there is reported as trusted, with `trustStore` naming the store and a
  `trusted-by-extra-root` warning that keeps it away from an A+, because a
  browser with nothing installed will still refuse the site.

One extra store ships with the service: the national CA of the Russian Ministry
of Digital Development (Минцифры), which Russian banks and state services use —
`alfabank.ru`, `sberbank.ru` and the like would otherwise come back as **T**. The
certificates are the ministry's own copies, downloaded from
<https://www.gosuslugi.ru/crt>, and the file records their fingerprints so they
can be checked against that source at any time. The root's fingerprint also
matches the chains alfabank.ru, sberbank.ru and vtb.ru serve, which is an
independent check on the same bytes. Both the root and the intermediate are
included, because the ministry distributes both for installation.

Adding another anchor is dropping a PEM file into `server/roots/` — a corporate
root, a private CA — or pointing `EXTRA_CA_DIR` somewhere else. The file name
becomes the store id, so add a `store_<name>` translation for it as well;
`npm run check:i18n` will insist.

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
* **Key exchange** — driven by the weakest key involved: the certificate key, the
  DH group and the EC group, compared in RSA-equivalent bits.
* **Cipher strength** — the average of the strongest and weakest accepted suite.

`≥ 80 → A`, `≥ 65 → B`, `≥ 50 → C`, `≥ 35 → D`, `≥ 20 → E`, otherwise `F`.

Then the caps apply — SSL 2.0, insecure renegotiation, NULL/anonymous or export
suites and Logjam drop the result to **F**; TLS compression, Sweet32 and SSL 3.0
cap it at **C**; RC4, no forward secrecy, a sub-2048-bit DH group and TLS 1.0/1.1
cap it at **B**. A certificate that browsers will not trust overrides everything
with **T**, and a name mismatch with **M**.

Finally, an **A** with HSTS of at least 180 days becomes **A+**, provided none of
the warnings that describe a real risk are present — no TLS 1.3, the heartbeat
extension, client-initiated renegotiation, no Certificate Transparency, a
certificate valid for more than 398 days, or trust that depends on an extra root.
Those turn an **A** into **A-** instead. The remaining warnings (RSA key
transport, suites without forward secrecy, a needlessly sent root, no OCSP
stapling) are reported but do not stand in the way of an A+: plenty of well-run
sites keep them for old clients.

This is an independent implementation of a public methodology, updated for what
matters today. It is not affiliated with, endorsed by, or guaranteed to agree
with Qualys SSL Labs.

## API

Everything the page shows is available as data. Console clients (curl, wget,
httpie, …) get JSON without asking.

```bash
curl https://myssl.sharapov.biz/example.com               # full report
curl https://myssl.sharapov.biz/api/example.com           # the same, explicitly
curl https://myssl.sharapov.biz/api/example.com:8443      # a different port
curl "https://myssl.sharapov.biz/api/example.com?output=yaml"
curl "https://myssl.sharapov.biz/api/example.com?refresh=1"    # bypass the cache
curl "https://myssl.sharapov.biz/api/example.com?download=1"   # as an attachment
curl "https://myssl.sharapov.biz/api/example.com?lang=ru"      # labels in Russian
```

| Route | Purpose |
| --- | --- |
| `GET /` | the page (JSON usage summary for console clients) |
| `GET /<host>` | report — page for browsers, data for everyone else |
| `GET /api/<host>` | always data |
| `GET /api/stream/<host>` | the same scan as server-sent events, with progress |
| `GET /healthz` | liveness, cache statistics, trust stores, scans in flight |

Query parameters: `output=json|yaml|html`, `port=`, `refresh=1`, `download=1`,
`lang=`. Both output formats work on every address — the pretty route, the `/api`
route and the root.

### Readable output

The report is built out of machine codes — `sweet32`, `legacy-tls-versions`,
`trusted-by-extra-root` — which is right for a data format and unreadable in a
terminal. So every code is accompanied by a label, in any of the twelve interface
languages. The codes never move or change, so scripts keep working:

```bash
curl -s "https://myssl.sharapov.biz/api/badssl.com?lang=de" |
  jq -r '.vulnerabilities[] | select(.status != "safe") |
         "\(.severityLabel)\t\(.statusLabel)\t\(.name) — \(.description)"'
```

```
mittel    verwundbar   Sweet32 — 64-Bit-Blockchiffren (3DES, IDEA, DES) geben …
kritisch  möglich      Heartbleed — Die Heartbeat-Erweiterung ist aktiv. …
```

Labelled fields: `vulnerabilities[].name` / `.description` / `.severityLabel` /
`.statusLabel`, `grade.caps[].label`, `grade.warningLabels`,
`certificate.issueLabels`, `certificate.trustStoreLabel`,
`certificate.leaf.validationLabel`, `certificate.ocsp.certStatusLabel`,
`ciphers[…].orderLabel` and each suite's `strengthLabel` / `issueLabels`. The
language used is echoed back in `meta.language`.

The language comes from `?lang=`, or from `Accept-Language`, or falls back to
English — error messages included.

### Live progress

A scan takes seconds, so the page follows it over server-sent events rather than
waiting:

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
    "grade": "A+", "score": 93,
    "components": { "protocol": {…}, "keyExchange": {…}, "cipher": {…} },
    "caps": [], "warnings": ["some-suites-without-pfs"], "warningLabels": […]
  },
  "certificate": { "leaf": {…}, "chain": […], "trusted": true,
                   "browserTrusted": true, "trustStore": "mozilla", "issues": [] },
  "protocols":  [{ "name": "TLS 1.3", "supported": true }, …],
  "ciphers":    { "TLS 1.3": { "order": "server", "suites": [{ "hex": "0x1301", … }] } },
  "keyExchange": { "groups": [{ "id": 29, "name": "x25519" }], "dh": null },
  "features":   { "http2": true, "ocspStapling": false, … },
  "vulnerabilities": [{ "id": "sweet32", "severity": "medium", "status": "safe", … }],
  "http":       { "hsts": {…}, "headers": {…}, "cookies": […] },
  "dns":        { "addresses": […], "caa": {…} },
  "simulation": [{ "client": "Chrome 131", "protocol": "TLS 1.3", "cipher": "…" }],
  "meta":       { "elapsedMs": 4749, "connections": 25, "cached": false, "language": "en" }
}
```

## Languages

Twelve languages: English, Russian, Spanish, Chinese, Hindi, Arabic (with the
layout mirrored), Portuguese, French, German, Japanese, Turkish and Ukrainian.
The page picks one from `localStorage`, then from the browser's language list;
the switcher in the header overrides it.

`public/i18n.js` holds one object per language. To add one, copy `en`, translate
the values and register the code in `LANG_NAMES` and `LANG_LOCALES`. That one
file serves both sides: the page reads it as a script, and the server evaluates
it in a sandbox to label the API output, so a translation can never be right in
the browser and missing in the JSON.

`npm run check:i18n` fails on any key that drifts apart — including the codes
built at runtime, which it reads out of `server/vulns.js`, `server/grade.js`,
`server/cert.js` and the file names in `server/roots/`, so a new finding, a new
rating cap or a new trust store cannot ship untranslated.

## Running

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

With Docker:

```bash
docker build -t myssl .
docker run --rm -p 3024:3024 myssl
```

The image runs as a non-root user and needs no writable filesystem.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `3024` | listening port |
| `HOSTNAME` | `0.0.0.0` | listening address |
| `TRUST_PROXY` | `true` | read the client address from `X-Forwarded-For` / `CF-Connecting-IP` |
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
| `ALLOW_PRIVATE_TARGETS` | `false` | allow scanning private ranges |
| `LOG_LEVEL` | `info` | pino level |

**Enable `TRUST_PROXY` only behind a reverse proxy.** If the server faces the
internet directly, a client can put any address in the header and slip past the
rate limits.

**Leave `ALLOW_PRIVATE_TARGETS` off.** It exists for the tests, which scan a TLS
server they start on the loopback themselves; in production it turns the service
into a port scanner for whatever network it runs in.

## Load protection

A scan opens several dozen connections to the target within a few seconds. To
keep that from becoming a nuisance to anyone:

* private, loopback, link-local and reserved ranges are refused, and a literal
  address is checked before any lookup happens;
* only well-known TLS ports may be scanned;
* per-client rate limits, plus a global ceiling on concurrent scans — beyond it
  callers get a 503 rather than a slow queue;
* results are cached for ten minutes, and two requests for the same target that
  arrive together share one scan;
* every probe has its own timeout and every enumeration loop a hard ceiling on
  rounds, so a broken server cannot hold a scan open;
* `robots.txt` allows the home page only, so a crawler cannot turn a walk of the
  site into a burst of outbound scans.

Scan only servers you are allowed to test.

## Deployment

`.github/workflows/deploy.yml` runs on every push to `main`: checks, then a
Docker image to GHCR, then a pull and restart over SSH with a health check before
the run is called green.

The deploy job needs `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`,
`GHCR_USERNAME` and `GHCR_TOKEN` as secrets or variables, and optionally
`DEPLOY_PORT`. The container is started read-only, with `no-new-privileges`, a
memory and PID limit, and bound to `127.0.0.1` for a reverse proxy to pick up.

## Tests

```bash
npm test            # syntax, translations, unit tests, smoke test
npm run test:unit   # includes two end-to-end scans of a local TLS server
npm run smoke       # boots the HTTP server and exercises its routes
```

The end-to-end tests generate a throwaway self-signed certificate with `openssl`,
start a TLS server on the loopback interface and scan it, so the whole pipeline —
protocol detection, cipher walking, certificate analysis, findings, grading — is
covered without touching the network. They skip themselves if `openssl` is not on
the path.

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
  asn1.js         a very small DER reader for what X509Certificate hides
  http-probe.js   HSTS, redirects, security headers, cookies
  dns-probe.js    A, AAAA, PTR, CAA
  vulns.js        known weaknesses, derived from the observed configuration
  grade.js        the letter grade
  i18n.js         labels for the API, read from the page's own dictionary
public/           the page: no framework, no build step
scripts/          CLI scan, smoke test, translation check
test/             unit tests and end-to-end scans of a local server
```

## Limitations

* Ticketbleed, Zombie POODLE, GOLDENDOODLE and the other padding-oracle variants
  are not covered, because detecting them means sending deliberately malformed
  records to somebody else's server.
* Revocation is read from a stapled OCSP response when there is one; no OCSP
  request and no CRL download is made.
* One address is scanned per host — the rest are listed but not visited.
* Client profiles are approximations of what those clients offer, close enough to
  answer whether they can still connect, not byte-exact replicas.
* Certificate Transparency is counted, not verified against the logs.

## License

MIT.

---

## Русская версия

Сервис, который разбирает, как сервер работает по TLS: какие версии протокола он
принимает, какие шифронаборы и в каком порядке, как выглядит цепочка
сертификатов, какие известные слабости следуют из его настроек и какая в итоге
получается оценка. Работает и как страница, и как API.

```
https://myssl.sharapov.biz                         страница
https://myssl.sharapov.biz/example.com             отчёт по хосту
https://myssl.sharapov.biz/example.com:8443        другой порт
https://myssl.sharapov.biz/example.com?output=json данные вместо страницы
https://myssl.sharapov.biz/api/example.com?output=yaml
```

Сделан так же, как [myip](https://github.com/sharapov-outsource/myip): один
небольшой сервер на Fastify, без сборки, без базы, страница без фреймворков.

### Что проверяется

| Раздел | Содержимое |
| --- | --- |
| Протоколы | SSL 2.0, SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3 — каждая версия запрашивается отдельно |
| Шифронаборы | Все принимаемые наборы по каждой версии, в порядке выбора сервера, и есть ли у сервера собственный приоритет |
| Обмен ключами | Поддерживаемые группы в порядке предпочтения сервера, размер модуля классического DH, согласованный эфемерный ключ |
| Сертификат | Субъект, издатель, срок действия, тип и стойкость ключа, алгоритм подписи, SAN, уровень проверки (DV/OV/EV), Certificate Transparency, must-staple, серийный номер, отпечатки, SPKI-пин |
| Цепочка | Порядок, полнота, подписи, корень доверия и хранилище, из которого он взят, недостающие и лишние промежуточные, совпадение имени хоста, прикреплённый OCSP |
| Возможности | ALPN и HTTP/2, OCSP stapling, возобновление сессий и тикеты, extended master secret, encrypt-then-MAC, безопасное пересогласование, пересогласование по инициативе клиента, сжатие TLS, `TLS_FALLBACK_SCSV`, обязательность SNI, запрос клиентского сертификата |
| Слабости | DROWN, POODLE, BEAST, FREAK, Logjam, Sweet32, RC4, наборы NULL и анонимные, CRIME, Heartbleed, небезопасное пересогласование, DoS через пересогласование, ROBOT, Lucky 13, отсутствие защиты от понижения, отсутствие прямой секретности, слабый DH |
| HTTP | Статус и цепочка редиректов, HSTS со всеми флагами, заголовки безопасности, флаги кук, объявление HTTP/3, заголовок `Server` |
| DNS | A, AAAA, обратная зона, CAA — включая то, покрывает ли CAA центр, который на самом деле выпустил сертификат |
| Клиенты | 13 профилей (Chrome, Firefox, Safari, Edge, Android, iOS, OpenSSL, Java 8 и 17, Python, Windows 7 и XP) — что согласует каждый или почему не подключится |

### Как это устроено

Штатный модуль `tls` в Node на большинство этих вопросов ответить не может: он не
предложит один выбранный шифронабор, полностью скрывает SSL 3.0, не умеет
перебирать наборы TLS 1.3 по одному и никогда не показывает цепочку ровно в том
виде, в каком её прислал сервер. Поэтому `server/tls-probe.js` собирает
сообщения ClientHello вручную, пишет их в обычный TCP-сокет и разбирает ответ
сервера до ServerHelloDone — или до ServerHello в TLS 1.3, где всё дальнейшее уже
зашифровано.

Прощупыватель никогда не доводит рукопожатие до конца: ключи не выводятся,
прикладные данные не отправляются. Каждая проба — одно TCP-соединение, которое
закрывается, как только пришли нужные байты. Всё, что прощупыватель увидеть не
может — сертификат сервера, работающего только по TLS 1.3, ALPN в TLS 1.3,
возобновление сессий, — измеряется настоящим рукопожатием в
`server/node-tls.js`.

Перебор шифронаборов устроен так же, как в sslscan и testssl.sh: сервер выбирает
один набор из предложенных, поэтому достаточно предложить всё, убрать выбранное и
спросить снова — так обходится весь список. Группы перебираются тем же приёмом, а
в TLS 1.3 — отправкой пустого key share, после которой сервер сам называет
предпочитаемую группу в HelloRetryRequest.

#### Чего сервис намеренно не делает

Любой вывод получен из настроек, которые сервер сообщает сам при обычном
рукопожатии. Ничего не подтверждается атакой: ни некорректного heartbeat, ни
зондирования оракула дополнения, ни принудительного понижения версии настоящим
трафиком. Там, где из-за этого остаётся сомнение, находка честно говорит
«возможно», а не делает вид, что уверена: так обстоит дело с Heartbleed
(пропатченный OpenSSL тоже объявляет расширение) и ROBOT (обмен ключами через RSA
— предпосылка, а не доказательство).

### Корни доверия

Доверие к сертификату не должно зависеть от машины, на которой запущен сканер, —
а в Node зависит, потому что некоторые сборки обращаются к системному хранилищу.
Поэтому цепочка строится по хранилищам, которые контролирует репозиторий:

* **`mozilla`** — список УЦ, который поставляется с Node; именно им пользуются
  браузеры;
* **`server/roots/*.pem`** — дополнительные корни, которых нет ни в одном
  браузере. Цепочка, заканчивающаяся здесь, считается доверенной, поле
  `trustStore` называет хранилище, а предупреждение `trusted-by-extra-root` не
  даёт получить A+: браузер без доустановки корня сайт всё равно не откроет.

Одно такое хранилище идёт в комплекте — национальный УЦ Минцифры России, которым
пользуются банки и госсервисы: без него `alfabank.ru`, `sberbank.ru` и подобные
получали бы **T**. Сертификаты взяты из копий самого министерства, скачанных с
<https://www.gosuslugi.ru/crt>; в файле записаны их отпечатки, чтобы в любой
момент можно было сверить. Отпечаток корня совпадает и с цепочками, которые
отдают alfabank.ru, sberbank.ru и vtb.ru, — это независимая проверка тех же
байтов. Включены и корневой, и промежуточный: министерство раздаёт для установки
оба.

Добавить свой корень — положить PEM-файл в `server/roots/` (корпоративный,
частный УЦ) или указать другой каталог в `EXTRA_CA_DIR`. Имя файла становится
идентификатором хранилища, так что нужен и перевод `store_<имя>` —
`npm run check:i18n` об этом напомнит.

### Оценка

Оценка построена по структуре методики SSL Server Rating Guide от Qualys: три
взвешенные составляющие, затем ограничения, затем бонус.

```
балл = 0,30 × поддержка протоколов
     + 0,30 × обмен ключами
     + 0,40 × стойкость шифров
```

* **Поддержка протоколов** — среднее между лучшей и худшей предлагаемой версией.
  SSL 2.0 даёт 0, SSL 3.0 — 80, TLS 1.0 — 90, TLS 1.1 — 95, TLS 1.2 и 1.3 — 100.
* **Обмен ключами** — по самому слабому задействованному ключу: ключ сертификата,
  группа DH и группа EC, приведённые к эквиваленту RSA в битах.
* **Стойкость шифров** — среднее между самым сильным и самым слабым из принятых
  наборов.

`≥ 80 → A`, `≥ 65 → B`, `≥ 50 → C`, `≥ 35 → D`, `≥ 20 → E`, иначе `F`.

Дальше действуют ограничения: SSL 2.0, небезопасное пересогласование, наборы NULL
и анонимные, экспортные наборы и Logjam опускают результат до **F**; сжатие TLS,
Sweet32 и SSL 3.0 ограничивают его буквой **C**; RC4, отсутствие прямой
секретности, группа DH меньше 2048 бит и TLS 1.0/1.1 — буквой **B**. Сертификат,
которому браузеры не доверяют, перекрывает всё оценкой **T**, а несовпадение
имени — оценкой **M**.

Наконец, **A** с HSTS не короче 180 дней превращается в **A+** — если нет ни
одного предупреждения, которое описывает настоящий риск: не включён TLS 1.3,
включено расширение heartbeat, разрешено пересогласование клиентом, нет
Certificate Transparency, сертификат выдан более чем на 398 дней или доверие
держится на дополнительном корне. Такие предупреждения превращают **A** в **A−**.
Остальные (обмен ключами через RSA, часть наборов без прямой секретности, лишний
корневой сертификат, отсутствие OCSP stapling) показываются, но получить A+ не
мешают: их держат у себя многие хорошо настроенные сайты ради старых клиентов.

Это независимая реализация публичной методики, обновлённая под сегодняшние
требования. Она не связана с Qualys SSL Labs, не одобрена ими и не обязана
совпадать с их результатом.

### API

Всё, что показывает страница, доступно как данные. Консольные клиенты (curl,
wget, httpie и прочие) получают JSON без каких-либо параметров.

```bash
curl https://myssl.sharapov.biz/example.com               # полный отчёт
curl https://myssl.sharapov.biz/api/example.com           # то же самое явно
curl https://myssl.sharapov.biz/api/example.com:8443      # другой порт
curl "https://myssl.sharapov.biz/api/example.com?output=yaml"
curl "https://myssl.sharapov.biz/api/example.com?refresh=1"    # мимо кэша
curl "https://myssl.sharapov.biz/api/example.com?download=1"   # файлом
curl "https://myssl.sharapov.biz/api/example.com?lang=ru"      # подписи по-русски
```

| Маршрут | Назначение |
| --- | --- |
| `GET /` | страница (для консольных клиентов — краткая справка по API в JSON) |
| `GET /<хост>` | отчёт: страница для браузера, данные для всех остальных |
| `GET /api/<хост>` | всегда данные |
| `GET /api/stream/<хост>` | тот же скан как server-sent events, с прогрессом |
| `GET /healthz` | живость, статистика кэша, хранилища доверия, сканы в работе |

Параметры запроса: `output=json|yaml|html`, `port=`, `refresh=1`, `download=1`,
`lang=`. Оба формата вывода работают на любом адресе — и на «красивом» маршруте,
и на `/api`, и на корне.

#### Читаемый вывод

Отчёт собран из машинных кодов — `sweet32`, `legacy-tls-versions`,
`trusted-by-extra-root`. Для формата данных это правильно, а в терминале
нечитаемо, поэтому рядом с каждым кодом идёт подпись на любом из двенадцати
языков интерфейса. Сами коды никуда не деваются и не меняются, так что скрипты
продолжают работать:

```bash
curl -s "https://myssl.sharapov.biz/api/badssl.com?lang=ru" |
  jq -r '.vulnerabilities[] | select(.status != "safe") |
         "\(.severityLabel)\t\(.statusLabel)\t\(.name) — \(.description)"'
```

```
средний   уязвим     Sweet32 — 64-битные блочные шифры (3DES, IDEA, DES) …
критично  возможно   Heartbleed — Расширение heartbeat включено. …
```

Поля с подписями: `vulnerabilities[].name` / `.description` / `.severityLabel` /
`.statusLabel`, `grade.caps[].label`, `grade.warningLabels`,
`certificate.issueLabels`, `certificate.trustStoreLabel`,
`certificate.leaf.validationLabel`, `certificate.ocsp.certStatusLabel`,
`ciphers[…].orderLabel`, а у каждого набора — `strengthLabel` и `issueLabels`.
Использованный язык возвращается в `meta.language`.

Язык берётся из `?lang=`, иначе из `Accept-Language`, иначе английский — включая
тексты ошибок.

#### Прогресс в реальном времени

Скан занимает несколько секунд, поэтому страница следит за ним через
server-sent events, а не ждёт молча:

```bash
curl -N https://myssl.sharapov.biz/api/stream/example.com
```

```
event: start
data: {"host":"example.com","port":443,"stages":["resolve","handshake", …]}

event: progress
data: {"stage":"ciphers","elapsedMs":912,"version":"TLS 1.2","found":18}

event: report
data: { …полный отчёт… }
```

События: `start`, `progress`, `report`, `failed`.

#### Структура отчёта

```jsonc
{
  "host": "github.com", "port": 443, "ip": "140.82.121.3",
  "grade": {
    "grade": "A+", "score": 93,
    "components": { "protocol": {…}, "keyExchange": {…}, "cipher": {…} },
    "caps": [], "warnings": ["some-suites-without-pfs"], "warningLabels": […]
  },
  "certificate": { "leaf": {…}, "chain": […], "trusted": true,
                   "browserTrusted": true, "trustStore": "mozilla", "issues": [] },
  "protocols":  [{ "name": "TLS 1.3", "supported": true }, …],
  "ciphers":    { "TLS 1.3": { "order": "server", "suites": [{ "hex": "0x1301", … }] } },
  "keyExchange": { "groups": [{ "id": 29, "name": "x25519" }], "dh": null },
  "features":   { "http2": true, "ocspStapling": false, … },
  "vulnerabilities": [{ "id": "sweet32", "severity": "medium", "status": "safe", … }],
  "http":       { "hsts": {…}, "headers": {…}, "cookies": […] },
  "dns":        { "addresses": […], "caa": {…} },
  "simulation": [{ "client": "Chrome 131", "protocol": "TLS 1.3", "cipher": "…" }],
  "meta":       { "elapsedMs": 4749, "connections": 25, "cached": false, "language": "ru" }
}
```

### Языки

Двенадцать языков: английский, русский, испанский, китайский, хинди, арабский (с
зеркальной вёрсткой), португальский, французский, немецкий, японский, турецкий и
украинский. Страница берёт язык из `localStorage`, затем из списка языков
браузера; переключатель в шапке всё это перекрывает.

В `public/i18n.js` лежит по объекту на язык. Чтобы добавить ещё один, скопируйте
`en`, переведите значения и зарегистрируйте код в `LANG_NAMES` и `LANG_LOCALES`.
Один и тот же файл обслуживает обе стороны: страница подключает его как скрипт, а
сервер исполняет его в песочнице, чтобы подписать вывод API, — так перевод не
может оказаться правильным в браузере и отсутствующим в JSON.

`npm run check:i18n` падает на любом расхождении ключей — включая коды, которые
собираются во время работы: скрипт вычитывает их из `server/vulns.js`,
`server/grade.js`, `server/cert.js` и имён файлов в `server/roots/`, поэтому новая
находка, новое ограничение оценки или новое хранилище доверия не уедут без
перевода.

### Запуск

```bash
npm install
npm start          # http://localhost:3024
npm run dev        # то же самое, с перезапуском при изменениях
```

Из командной строки, без сервера:

```bash
npm run scan -- github.com
npm run scan -- example.com:8443 --json
```

В Docker:

```bash
docker build -t myssl .
docker run --rm -p 3024:3024 myssl
```

Образ запускается под непривилегированным пользователем, писать на диск ему не
нужно.

### Настройки

| Переменная | По умолчанию | Значение |
| --- | --- | --- |
| `PORT` | `3024` | порт |
| `HOSTNAME` | `0.0.0.0` | адрес прослушивания |
| `TRUST_PROXY` | `true` | брать адрес клиента из `X-Forwarded-For` / `CF-Connecting-IP` |
| `HSTS` | — | `true`, чтобы отдавать `Strict-Transport-Security` |
| `MAX_INFLIGHT` | `6` | сколько сканов может идти одновременно; сверх того — 503 |
| `RATE_MAX` / `RATE_WINDOW` | `120` / `1 minute` | общий лимит запросов на клиента |
| `RATE_SCAN_MAX` / `RATE_SCAN_WINDOW` | `12` / `1 minute` | лимит на маршруты сканирования |
| `ALLOWED_PORTS` | 443, 8443, 993, 995, 465, … | порты, которые разрешено проверять |
| `SCAN_TIMEOUT_MS` | `60000` | жёсткий потолок на один скан |
| `PROBE_TIMEOUT_MS` | `8000` | таймаут одного соединения |
| `CACHE_TTL_MS` | `600000` | сколько живёт результат в кэше |
| `CACHE_MAX` | `500` | сколько отчётов держать в памяти |
| `EXTRA_CA_DIR` | `server/roots` | каталог с дополнительными корнями в PEM |
| `ALLOW_PRIVATE_TARGETS` | `false` | разрешить проверку приватных диапазонов |
| `LOG_LEVEL` | `info` | уровень логов pino |

**`TRUST_PROXY` включайте только за обратным прокси.** Если сервер смотрит в
интернет напрямую, клиент подставит в заголовок любой адрес и обойдёт лимиты.

**`ALLOW_PRIVATE_TARGETS` оставьте выключенным.** Он существует для тестов,
которые сканируют TLS-сервер, поднятый ими же на петле; в бою он превращает
сервис в сканер портов той сети, где он запущен.

### Защита от нагрузки

Один скан открывает к цели несколько десятков соединений за считаные секунды.
Чтобы это никому не мешало:

* приватные, петлевые, link-local и зарезервированные диапазоны отклоняются, а
  адрес, заданный литералом, проверяется ещё до какого-либо резолва;
* проверять можно только общеизвестные порты TLS;
* лимиты на клиента плюс общий потолок одновременных сканов — сверх него клиент
  получает 503, а не медленную очередь;
* результаты кэшируются на десять минут, а два одновременных запроса по одной
  цели делят один скан;
* у каждой пробы свой таймаут, у каждого цикла перебора — жёсткий предел числа
  раундов, так что сломанный сервер не удержит скан открытым;
* `robots.txt` разрешает только главную страницу, чтобы обход краулером не
  превращался во всплеск исходящих сканов.

Проверяйте только те серверы, которые вам разрешено проверять.

### Развёртывание

`.github/workflows/deploy.yml` отрабатывает на каждый пуш в `main`: проверки,
затем сборка образа в GHCR, затем `docker pull` и перезапуск по SSH с проверкой
здоровья до того, как запуск будет признан успешным.

Для деплоя нужны секреты или переменные `DEPLOY_HOST`, `DEPLOY_USER`,
`DEPLOY_SSH_KEY`, `GHCR_USERNAME`, `GHCR_TOKEN` и, при необходимости,
`DEPLOY_PORT`. Контейнер запускается только для чтения, с `no-new-privileges`,
ограничениями по памяти и числу процессов, и слушает `127.0.0.1` — дальше его
подхватывает обратный прокси.

### Тесты

```bash
npm test            # синтаксис, переводы, модульные тесты, smoke
npm run test:unit   # включая два сквозных скана локального TLS-сервера
npm run smoke       # поднимает HTTP-сервер и проходит по его маршрутам
```

Сквозные тесты создают одноразовый самоподписанный сертификат через `openssl`,
поднимают TLS-сервер на петлевом интерфейсе и сканируют его — так вся цепочка от
определения протоколов до подсчёта оценки проверяется без выхода в сеть. Если
`openssl` в системе нет, тесты пропускают сами себя.

### Ограничения

* Ticketbleed, Zombie POODLE, GOLDENDOODLE и прочие варианты оракула дополнения
  не проверяются: чтобы их обнаружить, нужно слать заведомо некорректные записи
  на чужой сервер.
* Отзыв читается из прикреплённого OCSP-ответа, если он есть; запрос к OCSP и
  скачивание CRL не выполняются.
* На хост сканируется один адрес — остальные перечисляются, но не проверяются.
* Профили клиентов — приближения того, что предлагают эти клиенты: достаточно
  точные, чтобы ответить, подключатся ли они, но не побайтовые копии.
* Метки Certificate Transparency считаются, но не сверяются с логами.

### Лицензия

MIT.
