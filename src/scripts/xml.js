import { esc } from './common.js';

/** Indented XML; with html=true the output is escaped and syntax-highlighted. */
export function pretty(node, depth = 0, html = true) {
  const pad = '  '.repeat(depth);
  const e = html ? esc : (s) => s;
  const span = (cls, s) => (html ? `<span class="${cls}">${s}</span>` : s);

  if (node.nodeType === Node.COMMENT_NODE) return `${pad}${span('x-cmt', e(`<!--${node.data}-->`))}`;
  if (node.nodeType === Node.TEXT_NODE || node.nodeType === Node.CDATA_SECTION_NODE) {
    const t = node.data.trim();
    return t ? `${pad}${e(t)}` : '';
  }
  if (node.nodeType !== Node.ELEMENT_NODE) return '';

  const attrs = [...node.attributes]
    .map((a) => ` ${span('x-attr', e(a.name))}=${span('x-val', e(`"${a.value}"`))}`)
    .join('');
  const open = `${span('x-tag', e(`<${node.nodeName}`))}${attrs}`;
  const close = span('x-tag', e(`</${node.nodeName}>`));
  const children = [...node.childNodes].filter((c) => !(c.nodeType === Node.TEXT_NODE && !c.data.trim()));

  if (!children.length) return `${pad}${open}${span('x-tag', e('/>'))}`;
  if (children.length === 1 && children[0].nodeType === Node.TEXT_NODE) {
    return `${pad}${open}${span('x-tag', e('>'))}${e(children[0].data.trim())}${close}`;
  }
  const inner = children.map((c) => pretty(c, depth + 1, html)).filter(Boolean).join('\n');
  return `${pad}${open}${span('x-tag', e('>'))}\n${inner}\n${pad}${close}`;
}

export const kids = (el, ns, name) => (el ? [...el.children].filter((c) => c.namespaceURI === ns && c.localName === name) : []);
export const kid = (el, ns, name) => kids(el, ns, name)[0];
export const all = (el, ns, name) => (el ? [...el.getElementsByTagNameNS(ns, name)] : []);
export const text = (el) => (el ? el.textContent.trim() : '');
/** Last segment of a URN/URL: "urn:…:bindings:HTTP-POST" → "HTTP-POST". */
export const short = (uri) => (uri ? String(uri).split(/[:#/]/).filter(Boolean).pop() : '');
