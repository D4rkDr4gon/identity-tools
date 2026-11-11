/**
 * Theme toggle (light / dark) — same behaviour and storage key as lcampassi.com.
 *
 * The initial theme is applied by an inline script in <head> to avoid a
 * flash; this module only wires up the toggle buttons.
 */

const KEY = 'theme';
const root = document.documentElement;
const media = window.matchMedia('(prefers-color-scheme: dark)');

function current() {
  return root.dataset.theme || (media.matches ? 'dark' : 'light');
}

function apply(theme) {
  root.dataset.theme = theme;
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* storage unavailable: keep it for this page only */
  }
  updateLabels();
}

export function updateLabels() {
  const dark = current() === 'dark';
  document.querySelectorAll('.theme-toggle').forEach((btn) => {
    const lang = root.lang === 'en' ? 'en' : 'es';
    const label = dark
      ? lang === 'en' ? 'Switch to light mode' : 'Cambiar a modo claro'
      : lang === 'en' ? 'Switch to dark mode' : 'Cambiar a modo oscuro';
    btn.setAttribute('aria-label', label);
    btn.setAttribute('title', label);
  });
}

export function initTheme() {
  document.querySelectorAll('.theme-toggle').forEach((btn) => {
    btn.addEventListener('click', () => apply(current() === 'dark' ? 'light' : 'dark'));
  });
  media.addEventListener?.('change', updateLabels);
  updateLabels();
}
