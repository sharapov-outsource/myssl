/**
 * Translations for the API.
 *
 * The report the scanner produces is all machine codes — `sweet32`,
 * `legacy-tls-versions`, `trusted-by-extra-root`. That is right for a data
 * format, but unreadable in a terminal, so the JSON and YAML output carries a
 * readable label beside every code.
 *
 * The labels come from the very same dictionary the page uses: `public/i18n.js`
 * is evaluated here in a sandbox instead of being duplicated, so a translation
 * can never be right in the browser and missing in the API. `check-i18n.js`
 * loads it the same way.
 */

import path from 'node:path';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function load() {
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(
    readFileSync(path.join(__dirname, '..', 'public', 'i18n.js'), 'utf8'),
    sandbox,
    { timeout: 5000, filename: 'i18n.js' }
  );
  return sandbox.window;
}

const dictionaries = load();

export const I18N = dictionaries.I18N || { en: {} };
export const LANG_NAMES = dictionaries.LANG_NAMES || {};
export const LANG_LOCALES = dictionaries.LANG_LOCALES || {};
export const RTL_LANGS = dictionaries.RTL_LANGS || [];
export const SUPPORTED_LANGS = Object.keys(I18N);
export const DEFAULT_LANG = I18N.en ? 'en' : SUPPORTED_LANGS[0];

/** Interface strings may carry markup; API labels must not. */
function plain(value) {
  return String(value).replace(/<[^>]+>/g, '');
}

export function t(lang, key, vars) {
  const dict = I18N[lang] || I18N[DEFAULT_LANG];
  let value = dict?.[key] ?? I18N[DEFAULT_LANG]?.[key];
  if (value === undefined) return undefined;
  if (vars) for (const [name, replacement] of Object.entries(vars)) {
    value = value.split('{' + name + '}').join(replacement);
  }
  return plain(value);
}

/** Label for a dashed code, as `tCode('vuln', 'no-forward-secrecy')`. */
export function tCode(lang, prefix, code) {
  if (code === undefined || code === null || code === '') return undefined;
  return t(lang, `${prefix}_${String(code).replace(/[-.]/g, '_')}`) ||
    String(code).replace(/-/g, ' ');
}

/**
 * The language to answer in: an explicit `?lang=`, otherwise the best match
 * from Accept-Language, otherwise English.
 */
export function pickLang(req) {
  const wanted = String(req?.query?.lang || '').toLowerCase().trim();
  if (SUPPORTED_LANGS.includes(wanted)) return wanted;

  const header = String(req?.headers?.['accept-language'] || '');
  for (const part of header.split(',')) {
    const tag = part.split(';')[0].trim().toLowerCase();
    if (!tag) continue;
    if (SUPPORTED_LANGS.includes(tag)) return tag;
    const base = tag.split('-')[0];
    if (SUPPORTED_LANGS.includes(base)) return base;
  }
  return DEFAULT_LANG;
}

/* ------------------------------------------------------------------ *
 * Labelling a report
 * ------------------------------------------------------------------ */

/**
 * Returns a copy of the report with readable labels added next to the codes.
 * The codes themselves are never replaced or removed: a script that reads
 * `.vulnerabilities[].id` keeps working, and a human reading the same output
 * gets `name` and `description` for free.
 *
 * The cached report is shared between languages, so nothing here mutates it.
 */
export function localizeReport(report, lang = DEFAULT_LANG) {
  if (!report || typeof report !== 'object') return report;
  const out = structuredClone(report);
  const label = (prefix, code) => tCode(lang, prefix, code);

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

  if (out.grade) {
    if (Array.isArray(out.grade.caps)) {
      out.grade.caps = out.grade.caps.map(cap => ({ ...cap, label: label('cap', cap.reason) }));
    }
    if (Array.isArray(out.grade.warnings)) {
      out.grade.warningLabels = out.grade.warnings.map(code => label('warn', code));
    }
    if (out.grade.reason) out.grade.reasonLabel = label('cap', out.grade.reason);
    if (out.grade.components?.keyExchange?.weakest?.what) {
      out.grade.components.keyExchange.weakest.label =
        label('kx', out.grade.components.keyExchange.weakest.what.toLowerCase().replace(/ /g, '-'));
    }
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

  out.meta = { ...out.meta, language: lang };
  return out;
}

/** The same treatment for an error payload. */
export function localizeError(payload, lang = DEFAULT_LANG, extra = {}) {
  return {
    ...payload,
    message: t(lang, `err_${String(payload.error).replace(/-/g, '_')}`) || payload.message,
    ...extra,
  };
}
