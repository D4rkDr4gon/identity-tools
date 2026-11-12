/**
 * Page bootstrap + small helpers shared by every tool.
 */
import { initTheme } from './theme.js';
import { initLang, register, tr } from './i18n.js';

export function initPage(dict = {}) {
  register(dict);
  initTheme();
  initLang();

  // Mark the "Tools" link as current on the hub only.
  const hub = document.querySelector('.nav-links a[href="/identity-tools/"]');
  if (hub && /\/identity-tools\/(index\.html)?$/.test(location.pathname)) {
    hub.setAttribute('aria-current', 'page');
  }

  // <button data-copy="#target"> copies the target's value or text.
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-copy]');
    if (!btn) return;
    const el = document.querySelector(btn.dataset.copy);
    if (!el) return;
    const text = 'value' in el ? el.value : el.textContent;
    try {
      await navigator.clipboard.writeText(text);
      flash(btn, tr('Copied', 'Copiado'));
    } catch {
      flash(btn, tr('Copy failed', 'No se pudo copiar'));
    }
  });
}

function flash(btn, text) {
  const label = btn.querySelector('span') || btn;
  const prev = label.textContent;
  label.textContent = text;
  setTimeout(() => (label.textContent = prev), 1200);
}

export function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Pretty-printed JSON with keys highlighted (output is HTML-escaped). */
export function jsonHtml(value) {
  return JSON.stringify(value, null, 2)
    .split('\n')
    .map((line) => {
      const m = line.match(/^(\s*)("(?:[^"\\]|\\.)*")(:\s?)(.*)$/);
      return m ? `${m[1]}<span class="k">${esc(m[2])}</span>${m[3]}${esc(m[4])}` : esc(line);
    })
    .join('\n');
}

export function b64ToBytes(b64) {
  let s = b64.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToUtf8(bytes) {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

/** "2026-11-11 14:03:22 UTC" + local time, for timestamps in results. */
export function fmtDate(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return '—';
  const utc = date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  return utc;
}

export function fmtLocal(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return '';
  return date.toLocaleString(tr('en-GB', 'es-AR'), { dateStyle: 'medium', timeStyle: 'medium' });
}

/** "in 3 h 12 min" / "2 d ago" relative to now. */
export function relative(date) {
  const diff = date.getTime() - Date.now();
  const abs = Math.abs(diff);
  const units = [
    [86400000, tr('d', 'd')],
    [3600000, 'h'],
    [60000, 'min'],
    [1000, 's'],
  ];
  const parts = [];
  let rest = abs;
  for (const [ms, label] of units) {
    const n = Math.floor(rest / ms);
    if (n) parts.push(`${n} ${label}`);
    rest -= n * ms;
    if (parts.length === 2) break;
  }
  const span = parts.join(' ') || '0 s';
  return diff >= 0 ? tr(`in ${span}`, `en ${span}`) : tr(`${span} ago`, `hace ${span}`);
}

/** Debounced input listener. */
export function onInput(el, fn, ms = 150) {
  let t;
  el.addEventListener('input', () => {
    clearTimeout(t);
    t = setTimeout(fn, ms);
  });
}

// ── Notes and tabs (shared result widgets) ───────────────

export const ICON = { bad: 'fa-circle-xmark', warn: 'fa-triangle-exclamation', info: 'fa-circle-info', ok: 'fa-circle-check' };

/** notes: [{ level, text } | { level, html }] → <ul class="notes"> */
export function notesHtml(notes) {
  return `<ul class="notes">${notes
    .map((n) => `<li class="${n.level}"><i class="fas ${ICON[n.level]}"></i><span>${n.html ?? esc(n.text)}</span></li>`)
    .join('')}</ul>`;
}

/**
 * Tabbed panels inside `container`. Returns a render function that takes
 * [{ id, label, html }] and remembers the selected tab across re-renders.
 */
export function tabs(container) {
  let active = null;
  container.addEventListener('click', (e) => {
    const tab = e.target.closest('.tab');
    if (!tab || !container.contains(tab)) return;
    active = tab.dataset.tab;
    container.querySelectorAll('.tab').forEach((t) => t.setAttribute('aria-selected', String(t === tab)));
    container.querySelectorAll('.tab-panel').forEach((p) => (p.hidden = p.dataset.panel !== active));
  });
  return (list) => {
    if (!list.some((t) => t.id === active)) active = list[0].id;
    const head = list
      .map((t) => `<button class="tab" role="tab" type="button" data-tab="${t.id}" aria-selected="${t.id === active}">${esc(t.label)}</button>`)
      .join('');
    const body = list
      .map((t) => `<div class="tab-panel" role="tabpanel" data-panel="${t.id}"${t.id === active ? '' : ' hidden'}>${t.html}</div>`)
      .join('');
    return `<div class="tabs" role="tablist">${head}</div>${body}`;
  };
}

export function copyBtn(target, en = 'Copy', es = 'Copiar') {
  return `<button class="btn" type="button" data-copy="${target}"><i class="fas fa-copy"></i> <span>${tr(en, es)}</span></button>`;
}

export function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

export const toHex = (bytes, sep = '') => [...bytes].map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(sep);
