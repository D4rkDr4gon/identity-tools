/**
 * Minimal EN/ES switch.
 *
 * The HTML is written in English (that is what gets indexed). Elements marked
 * with data-i18n="key" get their Spanish text from the registered dictionary;
 * the English original is kept in data-en so switching back is lossless.
 *
 *   data-i18n="key"       → textContent
 *   data-i18n-html="key"  → innerHTML (only for our own strings with <code>)
 *   data-i18n-ph="key"    → placeholder
 *   data-href-es="/es/"   → href when the page is in Spanish
 *
 * Dynamic output uses tr('English', 'Español').
 */
import { updateLabels } from './theme.js';

const KEY = 'lang';
const root = document.documentElement;

const shared = {
  'nav.tools': 'Herramientas',
  'nav.portfolio': 'Portfolio',
  'footer.privacy': 'Todo se ejecuta en tu navegador. Nada de lo que pegás se envía a ningún lado.',
  'footer.source': 'Código fuente',
  'common.privacy': 'Se procesa localmente, en tu navegador',
  'common.input': 'Entrada',
  'common.result': 'Resultado',
  'common.clear': 'Limpiar',
  'common.sample': 'Ejemplo',
  'common.copy': 'Copiar',
  'common.tools': 'Herramientas',
};

let dict = { ...shared };

export function lang() {
  return root.lang === 'es' ? 'es' : 'en';
}

export function tr(en, es) {
  return lang() === 'es' ? es : en;
}

export function register(pageDict) {
  dict = { ...shared, ...pageDict };
}

function swap(el, attr, key, setter, getter) {
  if (el.dataset[attr] === undefined) el.dataset[attr] = getter();
  const value = lang() === 'es' && dict[key] !== undefined ? dict[key] : el.dataset[attr];
  setter(value);
}

export function applyLang() {
  const es = lang() === 'es';

  document.querySelectorAll('[data-i18n]').forEach((el) =>
    swap(el, 'en', el.dataset.i18n, (v) => (el.textContent = v), () => el.textContent));
  document.querySelectorAll('[data-i18n-html]').forEach((el) =>
    swap(el, 'en', el.dataset.i18nHtml, (v) => (el.innerHTML = v), () => el.innerHTML));
  document.querySelectorAll('[data-i18n-ph]').forEach((el) =>
    swap(el, 'enPh', el.dataset.i18nPh, (v) => (el.placeholder = v), () => el.placeholder));
  document.querySelectorAll('[data-href-es]').forEach((el) => {
    if (el.dataset.hrefEn === undefined) el.dataset.hrefEn = el.getAttribute('href');
    el.setAttribute('href', es ? el.dataset.hrefEs : el.dataset.hrefEn);
  });

  if (dict._title) {
    if (root.dataset.titleEn === undefined) root.dataset.titleEn = document.title;
    document.title = es ? dict._title : root.dataset.titleEn;
  }

  document.querySelectorAll('.lang-toggle').forEach((btn) => {
    btn.textContent = es ? 'EN' : 'ES';
    const label = es ? 'English' : 'Español';
    btn.setAttribute('aria-label', label);
    btn.setAttribute('title', label);
  });

  updateLabels();
  document.dispatchEvent(new CustomEvent('langchange'));
}

export function initLang() {
  document.querySelectorAll('.lang-toggle').forEach((btn) =>
    btn.addEventListener('click', () => {
      root.lang = lang() === 'es' ? 'en' : 'es';
      try {
        localStorage.setItem(KEY, root.lang);
      } catch {
        /* storage unavailable */
      }
      applyLang();
    }),
  );
  applyLang();
}
