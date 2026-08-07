/**
 * Verifies that every translation dictionary is consistent: the same set of keys,
 * an endonym and a locale for each language, and placeholders such as {name}
 * matching the English reference. Also checks that every key the markup and the
 * client ask for actually exists.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import vm from 'node:vm';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const context = { window: {} };
vm.createContext(context);
vm.runInContext(readFileSync(path.join(root, 'public/i18n.js'), 'utf8'), context);

const { I18N, LANG_NAMES, LANG_LOCALES, RTL_LANGS } = context.window;
const problems = [];

if (!I18N || !Object.keys(I18N).length) {
  console.error('i18n.js did not define window.I18N');
  process.exit(1);
}

const reference = Object.keys(I18N.en);
const placeholders = s => [...String(s).matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort().join(',');

for (const [lang, dict] of Object.entries(I18N)) {
  for (const key of reference) {
    if (!(key in dict)) problems.push(`${lang}: missing key ${key}`);
    else if (typeof dict[key] !== 'string') problems.push(`${lang}.${key}: value is not a string`);
    else if (!dict[key].trim()) problems.push(`${lang}.${key}: empty string`);
    else if (placeholders(dict[key]) !== placeholders(I18N.en[key])) {
      problems.push(`${lang}.${key}: placeholders "${placeholders(dict[key])}" != "${placeholders(I18N.en[key])}"`);
    }
  }
  for (const key of Object.keys(dict)) {
    if (!reference.includes(key)) problems.push(`${lang}: unexpected key ${key}`);
  }
  if (!LANG_NAMES?.[lang]) problems.push(`${lang}: no entry in LANG_NAMES`);
  if (!LANG_LOCALES?.[lang]) problems.push(`${lang}: no entry in LANG_LOCALES`);
}

for (const lang of RTL_LANGS || []) {
  if (!I18N[lang]) problems.push(`RTL_LANGS points at a missing language: ${lang}`);
}

/* Keys the markup expects to exist. */
const html = readFileSync(path.join(root, 'public/index.html'), 'utf8');
for (const m of html.matchAll(/data-i18n="([^"]+)"/g)) {
  if (!reference.includes(m[1])) problems.push(`index.html references a missing key: ${m[1]}`);
}

/* Keys the client asks for by name: t('key') and t("key"). */
const app = readFileSync(path.join(root, 'public/app.js'), 'utf8');
for (const m of app.matchAll(/\bt\(\s*'([a-z0-9_]+)'/gi)) {
  if (!reference.includes(m[1])) problems.push(`app.js references a missing key: ${m[1]}`);
}

/**
 * Keys built at runtime from a prefix and a code, as tCode('vuln', id) does.
 * Every code the server can emit has to have a translation, otherwise the
 * interface silently falls back to a raw identifier.
 */
const CODES = {
  stage: ['resolve', 'handshake', 'protocols', 'ciphers', 'keyexchange', 'certificate',
    'features', 'http', 'clients', 'grade'],
  err: ['invalid-host', 'invalid-port', 'port-not-allowed', 'dns-failed', 'private-address',
    'tls-unreachable', 'scan-timeout', 'scan-failed', 'busy', 'bad-output', 'network',
    'bad-response', 'unreachable', 'timeout'],
  sev: ['critical', 'high', 'medium', 'low', 'info'],
  st: ['vulnerable', 'safe', 'possible', 'unknown', 'partial', 'missing', 'weak',
    'warning', 'mitigated'],
  order: ['server', 'client', 'unknown'],
  str: ['strong', 'legacy', 'weak', 'insecure'],
  kx: ['certificate-key', 'dh-group', 'ec-group', 'anonymous-key-exchange'],
  ocsp: ['good', 'revoked', 'unknown', 'successful', 'malformedRequest', 'internalError',
    'tryLater', 'sigRequired', 'unauthorized'],
  val: ['DV', 'OV', 'EV', 'IV'],
  // One per trust store: the Mozilla list plus every file in server/roots/.
  store: ['mozilla', ...readdirSync(path.join(root, 'server/roots'))
    .filter(name => /\.(pem|crt|cer)$/i.test(name))
    .map(name => name.replace(/\.(pem|crt|cer)$/i, ''))],
  ci: ['export', 'anonymous', 'no-encryption', 'rc4', 'sweet32', 'des', 'rc2', 'idea',
    'md5-mac', 'no-pfs', 'cbc', 'short-key', 'unknown-suite'],
};

/* The remaining code lists live in the server modules, so they are read from
   there: a new finding or a new cap must not go untranslated. */
const source = file => readFileSync(path.join(root, file), 'utf8');

const vulnIds = [...source('server/vulns.js').matchAll(/add\('([a-z0-9-]+)'/g)].map(m => m[1]);
CODES.vuln = vulnIds;
CODES.vd = vulnIds;

CODES.cap = [...source('server/grade.js').matchAll(/cap\('[A-Z+]+',\s*'([a-z0-9-]+)'/g)].map(m => m[1])
  .concat([...source('server/grade.js').matchAll(/finish\('[A-Z]',\s*'([a-z0-9-]+)'/g)].map(m => m[1]));
CODES.warn = [...source('server/grade.js').matchAll(/warnings\.push\('([a-z0-9-]+)'/g)].map(m => m[1]);
CODES.issue = [...source('server/cert.js').matchAll(/issues\.push\('([a-z0-9-]+)'/g)].map(m => m[1]);

for (const [prefix, codes] of Object.entries(CODES)) {
  if (!codes.length) problems.push(`no codes found for the "${prefix}" prefix — has a source file moved?`);
  for (const code of new Set(codes)) {
    const key = `${prefix}_${code.replace(/[-.]/g, '_')}`;
    if (!reference.includes(key)) problems.push(`missing translation for a runtime code: ${key}`);
  }
}

if (problems.length) {
  console.error('Translation problems found:');
  problems.forEach(p => console.error('  · ' + p));
  process.exit(1);
}

console.log(`Translations are consistent: ${Object.keys(I18N).length} languages x ${reference.length} keys.`);
