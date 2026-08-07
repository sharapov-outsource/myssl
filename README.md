# myssl

**Русская версия — [ниже](#русская-версия).**

TLS configuration scanner. Reports which protocol versions and cipher suites a
server accepts, what its certificate chain looks like, which known weaknesses
follow from that configuration, and an overall grade. Works as a page and as an
API.

```
https://myssl.sharapov.biz                         the page
https://myssl.sharapov.biz/example.com             report for a host
https://myssl.sharapov.biz/example.com:8443        a different port
https://myssl.sharapov.biz/example.com?output=json data instead of the page
https://myssl.sharapov.biz/api/example.com?output=yaml
```

## What it checks

| Section | Contents |
| --- | --- |
| Protocols | SSL 2.0, SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3 — each requested separately |
| Cipher suites | Every accepted suite per protocol version, in the order the server picks them, and whether the server enforces its own preference |
| Key exchange | Supported groups in the server's preferred order, finite-field DH modulus size, the negotiated ephemeral key |
| Certificate | Subject, issuer, validity, key type and strength, signature algorithm, SANs, validation level (DV/OV/EV), Certificate Transparency, must-staple, serial, fingerprints, SPKI pin |
| Chain | Order, completeness, signatures, trust anchor and its store, missing or superfluous intermediates, host name match, stapled OCSP status |
| Features | ALPN and HTTP/2, OCSP stapling, session resumption and tickets, extended master secret, encrypt-then-MAC, secure renegotiation, client-initiated renegotiation, TLS compression, `TLS_FALLBACK_SCSV`, whether SNI is required, client certificate requests |
| Weaknesses | DROWN, POODLE, BEAST, FREAK, Logjam, Sweet32, RC4, NULL/anonymous suites, CRIME, Heartbleed, insecure renegotiation, renegotiation DoS, ROBOT, Lucky 13, missing downgrade protection, missing forward secrecy, weak DH |
| HTTP | Status and redirect chain, HSTS with all its flags, security headers, cookie flags, HTTP/3 advertisement, `Server` header |
| DNS | A, AAAA, reverse DNS, CAA — including whether CAA covers the authority that issued the certificate |
| Clients | 13 client profiles (Chrome, Firefox, Safari, Edge, Android, iOS, OpenSSL, Java 8 and 17, Python, Windows 7 and XP) — what each would negotiate, or why it cannot connect |

A scan takes 5–20 seconds and opens a few dozen TCP connections to the target.

## How the scanner works

ClientHello messages are assembled by hand and written to a plain TCP socket
(`server/tls-probe.js`). A TLS library cannot offer a single cipher suite of your
choosing, cannot reach SSL 3.0, cannot walk TLS 1.3 suites one at a time, and
does not expose the chain exactly as the server sent it.

* No handshake is completed by the prober: no keys are derived, no application
  data is sent. Each probe is one connection, closed after the server's first
  flight — ServerHelloDone, or ServerHello for TLS 1.3.
* Cipher suites are enumerated by offering everything, removing whatever came
  back, and asking again. Groups the same way; in TLS 1.3 by sending no key
  share, which makes the server name its preferred group in a HelloRetryRequest.
* What the prober cannot see — the certificate of a TLS 1.3-only server, ALPN in
  TLS 1.3, session resumption — is measured with a real handshake
  (`server/node-tls.js`).
* Nothing is confirmed by attacking the server: no malformed heartbeat, no
  padding-oracle probing, no forced downgrade. Findings that cannot be settled
  that way are reported as `possible` rather than `vulnerable` — Heartbleed and
  ROBOT are the two such cases.

## Trust anchors

The chain is walked against stores in this repository, not against the host's
system store, so the verdict does not change with the machine:

* **`mozilla`** — the CA list Node ships with, which is what browsers use.
* **`server/roots/*.pem`** — extra anchors. A chain ending there is reported as
  trusted, with `trustStore` naming the store and a `trusted-by-extra-root`
  warning that keeps it below A+.

One extra store ships with the service: the national CA of the Russian Ministry
of Digital Development (Минцифры), used by Russian banks and state services —
without it `alfabank.ru`, `sberbank.ru` and the like are reported as **T**. The
certificates are the ministry's own copies from <https://www.gosuslugi.ru/crt>;
the file records their fingerprints. The root is
`D26D2D0231B7C39F92CC738512BA54103519E4405D68B5BD703E9788CA8ECF31`, which also
matches the chains those banks serve.

To add an anchor, drop a PEM file into `server/roots/` or point `EXTRA_CA_DIR`
elsewhere. The file name becomes the store id, so add a `store_<name>`
translation too — `npm run check:i18n` requires it.

```json
"certificate": {
  "trusted": true,
  "browserTrusted": false,
  "trustStore": "russian-trusted-ca",
  "trustAnchor": "Russian Trusted Root CA"
}
```

## The grade

```
score = 0.30 × protocol support
      + 0.30 × key exchange
      + 0.40 × cipher strength
```

* **Protocol support** — average of the best and worst version on offer.
  SSL 2.0 scores 0, SSL 3.0 80, TLS 1.0 90, TLS 1.1 95, TLS 1.2 and 1.3 100.
* **Key exchange** — the weakest key involved: certificate key, DH group, EC
  group, compared in RSA-equivalent bits.
* **Cipher strength** — average of the strongest and weakest accepted suite.

`≥ 80 → A`, `≥ 65 → B`, `≥ 50 → C`, `≥ 35 → D`, `≥ 20 → E`, otherwise `F`.

Caps: SSL 2.0, insecure renegotiation, NULL/anonymous or export suites and
Logjam → **F**; TLS compression, Sweet32, SSL 3.0 → **C**; RC4, no forward
secrecy, DH below 2048 bit, TLS 1.0/1.1 → **B**. An untrusted certificate
overrides everything with **T**, a name mismatch with **M**.

**A+** requires an A, HSTS of at least 180 days, and none of these warnings: no
TLS 1.3, heartbeat extension, client-initiated renegotiation, no Certificate
Transparency, validity over 398 days, trust that depends on an extra root. Those
give **A-** instead. Other warnings (RSA key transport, some suites without
forward secrecy, a needlessly sent root, no OCSP stapling) are reported but do
not block an A+.

The rating follows the structure of the Qualys SSL Server Rating Guide. It is an
independent implementation, not affiliated with Qualys and not guaranteed to
agree with SSL Labs.

## API

Console clients (curl, wget, httpie, …) get JSON without asking for it.

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
`lang=`. Both output formats work on every address.

### Labels

Every machine code in the report comes with a readable label in any of the
twelve interface languages. The codes themselves never change, so scripts keep
working:

```bash
curl -s "https://myssl.sharapov.biz/api/badssl.com?lang=de" |
  jq -r '.vulnerabilities[] | select(.status != "safe") |
         "\(.severityLabel)\t\(.statusLabel)\t\(.name)"'
```

Labelled fields: `vulnerabilities[].name` / `.description` / `.severityLabel` /
`.statusLabel`, `grade.caps[].label`, `grade.warningLabels`,
`certificate.issueLabels`, `certificate.trustStoreLabel`,
`certificate.leaf.validationLabel`, `certificate.ocsp.certStatusLabel`,
`ciphers[…].orderLabel`, and each suite's `strengthLabel` / `issueLabels`.
The language used comes back in `meta.language`.

Language selection: `?lang=`, then `Accept-Language`, then English. Error
messages included.

### Live progress

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
| `PUBLIC_ORIGIN` | — | fixed origin for canonical and social URLs; taken from the request otherwise |
| `HSTS` | — | `true` to send `Strict-Transport-Security` |
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

**Enable `TRUST_PROXY` only behind a reverse proxy.** Facing the internet
directly, a client can put any address in the header and slip past the limits.

**Leave `ALLOW_PRIVATE_TARGETS` off.** It exists for the tests, which scan a TLS
server they start on the loopback; in production it turns the service into a port
scanner for whatever network it runs in.

## Load protection

* private, loopback, link-local and reserved ranges are refused, and a literal
  address is checked before any lookup;
* only well-known TLS ports may be scanned;
* per-client rate limits and a global ceiling on concurrent scans;
* results are cached for ten minutes, and two requests for the same target that
  arrive together share one scan;
* every probe has a timeout and every enumeration loop a ceiling on rounds;
* `robots.txt` allows the home page only, and report pages carry `noindex`.

Scan only servers you are allowed to test.

## Deployment

`.github/workflows/deploy.yml` runs on every push to `main`: checks, a Docker
image to GHCR, then a pull and restart over SSH with a health check before the
run is called green.

Required secrets or variables: `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`,
`GHCR_USERNAME`, `GHCR_TOKEN`, optionally `DEPLOY_PORT`. The container runs
read-only, with `no-new-privileges`, memory and PID limits, bound to
`127.0.0.1` for a reverse proxy.

## Tests

```bash
npm test            # syntax, translations, unit tests, smoke test
npm run test:unit   # includes two end-to-end scans of a local TLS server
npm run smoke       # boots the HTTP server and exercises its routes
```

The end-to-end tests generate a self-signed certificate with `openssl`, start a
TLS server on the loopback and scan it, covering the pipeline from protocol
detection to grading without touching the network. They skip themselves if
`openssl` is missing.

## Languages

Twelve: English, Russian, Spanish, Chinese, Hindi, Arabic (layout mirrored),
Portuguese, French, German, Japanese, Turkish, Ukrainian.

`public/i18n.js` holds one object per language and is the only dictionary: the
page loads it as a script, the server evaluates it in a sandbox to label API
output and to fill in the page title, description and `lang` per request. To add
a language, copy `en`, translate the values, register the code in `LANG_NAMES`
and `LANG_LOCALES`.

`npm run check:i18n` fails on any key that drifts apart, including runtime codes
read from `server/vulns.js`, `server/grade.js`, `server/cert.js` and the file
names in `server/roots/`.

## Design

The page follows the sharapov.biz design system: warm paper ground with an
indigo wash, graphite ink, one accent colour used sparingly, Geist for display
type, Inter for body, JetBrains Mono for everything technical. The dark theme is
the same palette turned over.

Fonts are served from `public/fonts` rather than a CDN, so `font-src` stays
`'self'` and the page makes no third-party request for them. `scripts/make-icons.js`
regenerates the raster icons and the social preview from the same mark as
`public/icon.svg`.

## Layout

```
server/
  index.js        Fastify: routes, output formats, SSE, rate limits, headers, page rendering
  scan.js         orchestration, caching, target validation, progress events
  tls-probe.js    hand-written ClientHello/ServerHello over a raw socket
  enumerate.js    scanning strategies built on the prober
  suites.js       cipher suite registry; properties derived from the names
  node-tls.js     the checks that need a real handshake
  trust.js        trust anchors: the Mozilla list plus anything in roots/
  roots/          extra trust anchors in PEM, one store per file
  cert.js         certificate and chain analysis
  asn1.js         a small DER reader for what X509Certificate does not expose
  http-probe.js   HSTS, redirects, security headers, cookies
  dns-probe.js    A, AAAA, PTR, CAA
  vulns.js        known weaknesses, derived from the observed configuration
  grade.js        the letter grade
  i18n.js         labels for the API and the page head
public/           the page, icons and self-hosted fonts; no framework, no build step
scripts/          CLI scan, smoke test, translation check, icon generator
test/             unit tests and end-to-end scans of a local server
```

## Limitations

* Ticketbleed, Zombie POODLE, GOLDENDOODLE and other padding-oracle variants are
  not covered: detecting them requires sending malformed records.
* Revocation is read from a stapled OCSP response when present; no OCSP request
  and no CRL download is made.
* One address is scanned per host; the rest are listed but not visited.
* Client profiles approximate what those clients offer — enough to answer
  whether they can connect, not byte-exact replicas.
* Certificate Transparency timestamps are counted, not verified against logs.

## License

MIT.

---

## Русская версия

Сканер конфигурации TLS. Показывает, какие версии протокола и шифронаборы
принимает сервер, как выглядит цепочка сертификатов, какие известные слабости
следуют из этих настроек, и выставляет общую оценку. Работает как страница и как
API.

```
https://myssl.sharapov.biz                         страница
https://myssl.sharapov.biz/example.com             отчёт по хосту
https://myssl.sharapov.biz/example.com:8443        другой порт
https://myssl.sharapov.biz/example.com?output=json данные вместо страницы
https://myssl.sharapov.biz/api/example.com?output=yaml
```

### Что проверяется

| Раздел | Содержимое |
| --- | --- |
| Протоколы | SSL 2.0, SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3 — каждая версия запрашивается отдельно |
| Шифронаборы | Все принимаемые наборы по каждой версии, в порядке выбора сервера, и есть ли у сервера собственный приоритет |
| Обмен ключами | Поддерживаемые группы в порядке предпочтения сервера, размер модуля классического DH, согласованный эфемерный ключ |
| Сертификат | Субъект, издатель, срок действия, тип и стойкость ключа, алгоритм подписи, SAN, уровень проверки (DV/OV/EV), Certificate Transparency, must-staple, серийный номер, отпечатки, SPKI-пин |
| Цепочка | Порядок, полнота, подписи, корень доверия и его хранилище, недостающие и лишние промежуточные, совпадение имени хоста, прикреплённый OCSP |
| Возможности | ALPN и HTTP/2, OCSP stapling, возобновление сессий и тикеты, extended master secret, encrypt-then-MAC, безопасное пересогласование, пересогласование по инициативе клиента, сжатие TLS, `TLS_FALLBACK_SCSV`, обязательность SNI, запрос клиентского сертификата |
| Слабости | DROWN, POODLE, BEAST, FREAK, Logjam, Sweet32, RC4, наборы NULL и анонимные, CRIME, Heartbleed, небезопасное пересогласование, DoS через пересогласование, ROBOT, Lucky 13, отсутствие защиты от понижения, отсутствие прямой секретности, слабый DH |
| HTTP | Статус и цепочка редиректов, HSTS со всеми флагами, заголовки безопасности, флаги кук, объявление HTTP/3, заголовок `Server` |
| DNS | A, AAAA, обратная зона, CAA — включая то, покрывает ли CAA центр, выпустивший сертификат |
| Клиенты | 13 профилей (Chrome, Firefox, Safari, Edge, Android, iOS, OpenSSL, Java 8 и 17, Python, Windows 7 и XP) — что согласует каждый или почему не подключится |

Скан занимает 5–20 секунд и открывает к цели несколько десятков TCP-соединений.

### Как работает сканер

Сообщения ClientHello собираются вручную и пишутся в обычный TCP-сокет
(`server/tls-probe.js`). Библиотечный клиент не позволяет предложить один
выбранный шифронабор, не умеет в SSL 3.0, не перебирает наборы TLS 1.3 по одному
и не отдаёт цепочку ровно в том виде, в каком её прислал сервер.

* Прощупыватель не доводит рукопожатие до конца: ключи не выводятся, прикладные
  данные не отправляются. Каждая проба — одно соединение, закрываемое после
  первой порции ответа сервера: ServerHelloDone или ServerHello для TLS 1.3.
* Шифронаборы перебираются так: предложить всё, убрать выбранное, спросить снова.
  Группы — тем же приёмом, а в TLS 1.3 отправкой пустого key share, после которой
  сервер сам называет предпочитаемую группу в HelloRetryRequest.
* То, что прощупыватель увидеть не может — сертификат сервера только с TLS 1.3,
  ALPN в TLS 1.3, возобновление сессий, — измеряется настоящим рукопожатием
  (`server/node-tls.js`).
* Ничего не подтверждается атакой на сервер: ни некорректного heartbeat, ни
  зондирования оракула дополнения, ни принудительного понижения версии. Находки,
  которые иначе не проверить, помечаются как «возможно», а не «уязвим» — это
  случай Heartbleed и ROBOT.

### Корни доверия

Цепочка строится по хранилищам из репозитория, а не по системному хранилищу
машины, поэтому вердикт не зависит от того, где запущен сканер:

* **`mozilla`** — список УЦ, поставляемый с Node; им пользуются браузеры.
* **`server/roots/*.pem`** — дополнительные корни. Цепочка, заканчивающаяся
  здесь, считается доверенной, поле `trustStore` называет хранилище, а
  предупреждение `trusted-by-extra-root` не даёт подняться до A+.

Одно такое хранилище идёт в комплекте — национальный УЦ Минцифры России, которым
пользуются банки и госсервисы: без него `alfabank.ru`, `sberbank.ru` и подобные
получают **T**. Сертификаты — копии самого министерства с
<https://www.gosuslugi.ru/crt>, их отпечатки записаны в файле. Отпечаток корня —
`D26D2D0231B7C39F92CC738512BA54103519E4405D68B5BD703E9788CA8ECF31`, он же
совпадает с цепочками, которые отдают эти банки.

Чтобы добавить свой корень, положите PEM-файл в `server/roots/` или укажите
другой каталог в `EXTRA_CA_DIR`. Имя файла становится идентификатором хранилища,
поэтому нужен и перевод `store_<имя>` — `npm run check:i18n` это требует.

```json
"certificate": {
  "trusted": true,
  "browserTrusted": false,
  "trustStore": "russian-trusted-ca",
  "trustAnchor": "Russian Trusted Root CA"
}
```

### Оценка

```
балл = 0,30 × поддержка протоколов
     + 0,30 × обмен ключами
     + 0,40 × стойкость шифров
```

* **Поддержка протоколов** — среднее между лучшей и худшей предлагаемой версией.
  SSL 2.0 даёт 0, SSL 3.0 — 80, TLS 1.0 — 90, TLS 1.1 — 95, TLS 1.2 и 1.3 — 100.
* **Обмен ключами** — по самому слабому ключу: ключ сертификата, группа DH,
  группа EC, приведённые к эквиваленту RSA в битах.
* **Стойкость шифров** — среднее между самым сильным и самым слабым набором.

`≥ 80 → A`, `≥ 65 → B`, `≥ 50 → C`, `≥ 35 → D`, `≥ 20 → E`, иначе `F`.

Ограничения: SSL 2.0, небезопасное пересогласование, наборы NULL и анонимные,
экспортные наборы, Logjam → **F**; сжатие TLS, Sweet32, SSL 3.0 → **C**; RC4,
отсутствие прямой секретности, DH меньше 2048 бит, TLS 1.0/1.1 → **B**.
Недоверенный сертификат перекрывает всё оценкой **T**, несовпадение имени — **M**.

**A+** требует A, HSTS не короче 180 дней и отсутствия предупреждений: не включён
TLS 1.3, расширение heartbeat, пересогласование клиентом, нет Certificate
Transparency, срок действия больше 398 дней, доверие через дополнительный корень.
С ними получается **A−**. Остальные предупреждения (обмен ключами через RSA,
часть наборов без прямой секретности, лишний корневой сертификат, отсутствие OCSP
stapling) показываются, но A+ не мешают.

Оценка построена по структуре методики Qualys SSL Server Rating Guide. Это
независимая реализация, не связанная с Qualys и не обязанная совпадать с
результатом SSL Labs.

### API

Консольные клиенты (curl, wget, httpie и прочие) получают JSON без параметров.

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
| `GET /` | страница (для консольных клиентов — справка по API в JSON) |
| `GET /<хост>` | отчёт: страница для браузера, данные для всех остальных |
| `GET /api/<хост>` | всегда данные |
| `GET /api/stream/<хост>` | тот же скан как server-sent events, с прогрессом |
| `GET /healthz` | живость, статистика кэша, хранилища доверия, сканы в работе |

Параметры: `output=json|yaml|html`, `port=`, `refresh=1`, `download=1`, `lang=`.
Оба формата вывода работают на любом адресе.

#### Подписи

У каждого машинного кода в отчёте есть читаемая подпись на любом из двенадцати
языков интерфейса. Сами коды не меняются, поэтому скрипты продолжают работать:

```bash
curl -s "https://myssl.sharapov.biz/api/badssl.com?lang=ru" |
  jq -r '.vulnerabilities[] | select(.status != "safe") |
         "\(.severityLabel)\t\(.statusLabel)\t\(.name)"'
```

Поля с подписями: `vulnerabilities[].name` / `.description` / `.severityLabel` /
`.statusLabel`, `grade.caps[].label`, `grade.warningLabels`,
`certificate.issueLabels`, `certificate.trustStoreLabel`,
`certificate.leaf.validationLabel`, `certificate.ocsp.certStatusLabel`,
`ciphers[…].orderLabel`, у каждого набора — `strengthLabel` и `issueLabels`.
Использованный язык возвращается в `meta.language`.

Выбор языка: `?lang=`, затем `Accept-Language`, затем английский. Тексты ошибок
тоже.

#### Прогресс в реальном времени

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

Образ запускается под непривилегированным пользователем, запись на диск ему не
нужна.

### Настройки

| Переменная | По умолчанию | Значение |
| --- | --- | --- |
| `PORT` | `3024` | порт |
| `HOSTNAME` | `0.0.0.0` | адрес прослушивания |
| `TRUST_PROXY` | `true` | брать адрес клиента из `X-Forwarded-For` / `CF-Connecting-IP` |
| `PUBLIC_ORIGIN` | — | фиксированный origin для canonical и ссылок в соцсети; иначе берётся из запроса |
| `HSTS` | — | `true`, чтобы отдавать `Strict-Transport-Security` |
| `MAX_INFLIGHT` | `6` | сколько сканов идёт одновременно; сверх того — 503 |
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

**`ALLOW_PRIVATE_TARGETS` оставьте выключенным.** Он нужен тестам, которые
сканируют TLS-сервер, поднятый ими же на петле; в бою он превращает сервис в
сканер портов той сети, где он запущен.

### Защита от нагрузки

* приватные, петлевые, link-local и зарезервированные диапазоны отклоняются, а
  адрес-литерал проверяется до какого-либо резолва;
* проверять можно только общеизвестные порты TLS;
* лимиты на клиента и общий потолок одновременных сканов;
* результаты кэшируются на десять минут, два одновременных запроса по одной цели
  делят один скан;
* у каждой пробы свой таймаут, у каждого цикла перебора — предел числа раундов;
* `robots.txt` разрешает только главную, у страниц отчётов стоит `noindex`.

Проверяйте только те серверы, которые вам разрешено проверять.

### Развёртывание

`.github/workflows/deploy.yml` отрабатывает на каждый пуш в `main`: проверки,
сборка образа в GHCR, затем `docker pull` и перезапуск по SSH с проверкой
здоровья до признания запуска успешным.

Нужны секреты или переменные `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`,
`GHCR_USERNAME`, `GHCR_TOKEN` и, при необходимости, `DEPLOY_PORT`. Контейнер
запускается только для чтения, с `no-new-privileges`, ограничениями по памяти и
числу процессов, слушает `127.0.0.1` — дальше обратный прокси.

### Тесты

```bash
npm test            # синтаксис, переводы, модульные тесты, smoke
npm run test:unit   # включая два сквозных скана локального TLS-сервера
npm run smoke       # поднимает HTTP-сервер и проходит по его маршрутам
```

Сквозные тесты создают самоподписанный сертификат через `openssl`, поднимают
TLS-сервер на петлевом интерфейсе и сканируют его — вся цепочка от определения
протоколов до подсчёта оценки проверяется без выхода в сеть. Без `openssl` тесты
пропускают себя.

### Языки

Двенадцать: английский, русский, испанский, китайский, хинди, арабский
(с зеркальной вёрсткой), португальский, французский, немецкий, японский,
турецкий, украинский.

`public/i18n.js` содержит по объекту на язык и является единственным словарём:
страница подключает его как скрипт, сервер исполняет его в песочнице, чтобы
подписать вывод API и подставить в голову страницы заголовок, описание и `lang`
на язык запроса. Чтобы добавить язык, скопируйте `en`, переведите значения,
зарегистрируйте код в `LANG_NAMES` и `LANG_LOCALES`.

`npm run check:i18n` падает на любом расхождении ключей, включая коды, которые
вычитываются из `server/vulns.js`, `server/grade.js`, `server/cert.js` и имён
файлов в `server/roots/`.

### Оформление

Страница следует дизайн-системе sharapov.biz: тёплая бумага с индиговым
подсветом, графитовые чернила, один акцентный цвет в малых дозах, Geist для
заголовков, Inter для текста, JetBrains Mono для всего технического. Тёмная тема
— та же палитра наизнанку.

Шрифты отдаются из `public/fonts`, а не с CDN, поэтому `font-src` остаётся
`'self'` и страница не делает за ними сторонних запросов.
`scripts/make-icons.js` пересобирает растровые иконки и превью для соцсетей из
того же знака, что и `public/icon.svg`.

### Структура

```
server/
  index.js        Fastify: маршруты, форматы вывода, SSE, лимиты, заголовки, отдача страницы
  scan.js         оркестрация, кэш, валидация цели, события прогресса
  tls-probe.js    самодельный ClientHello/ServerHello поверх сырого сокета
  enumerate.js    стратегии перебора поверх прощупывателя
  suites.js       реестр шифронаборов; свойства выводятся из названий
  node-tls.js     проверки, которым нужно настоящее рукопожатие
  trust.js        корни доверия: список Mozilla плюс всё из roots/
  roots/          дополнительные корни в PEM, файл на хранилище
  cert.js         разбор сертификата и цепочки
  asn1.js         небольшой DER-ридер для того, что не отдаёт X509Certificate
  http-probe.js   HSTS, редиректы, заголовки безопасности, куки
  dns-probe.js    A, AAAA, PTR, CAA
  vulns.js        известные слабости, выведенные из наблюдаемых настроек
  grade.js        итоговая оценка
  i18n.js         подписи для API и головы страницы
public/           страница, иконки и локальные шрифты; без фреймворков и сборки
scripts/          скан из консоли, smoke-тест, проверка переводов, генератор иконок
test/             модульные тесты и сквозные сканы локального сервера
```

### Ограничения

* Ticketbleed, Zombie POODLE, GOLDENDOODLE и прочие варианты оракула дополнения
  не проверяются: для их обнаружения нужно слать некорректные записи.
* Отзыв читается из прикреплённого OCSP-ответа, если он есть; запрос к OCSP и
  скачивание CRL не выполняются.
* На хост сканируется один адрес, остальные перечисляются, но не проверяются.
* Профили клиентов — приближения того, что предлагают эти клиенты: достаточно
  точные, чтобы ответить, подключатся ли они, но не побайтовые копии.
* Метки Certificate Transparency считаются, но не сверяются с логами.

### Лицензия

MIT.
