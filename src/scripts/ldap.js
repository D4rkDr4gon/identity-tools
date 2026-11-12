import { initPage, esc, fmtDate, relative, onInput, notesHtml, tabs, copyBtn, toHex } from './common.js';
import { tr } from './i18n.js';
import { UAC_FLAGS, GROUP_TYPE_FLAGS, ENCTYPE_FLAGS, decodeBits } from './ad-flags.js';

initPage({
  _title: 'Validador y formateador de filtros LDAP — Identity Tools',
  h1: 'Filtros LDAP',
  lead: 'Pegá un filtro LDAP para validarlo según RFC 4515, verlo indentado y leer en palabras qué busca, con los flags de AD y las reglas de coincidencia explicados. También escapa valores y arma la consulta de PowerShell.',
  'in.title': 'Filtro',
  'in.label': 'Filtro LDAP',
  'in.hint': 'Puede venir en una línea o indentado; los espacios entre componentes se ignoran.',
  'tpl.label': 'Plantillas',
  'tpl.pick': 'Cargar una plantilla…',
  'esc.title': 'Escapar un valor',
  'esc.label': 'Valor a usar dentro de un filtro',
  'esc.ph': 'Ventas (Buenos Aires) * 2026',
  'esc.nonAscii': 'Escapar también caracteres no ASCII (como bytes UTF-8)',
  'esc.hint': 'Escapa * ( ) \\ y NUL según RFC 4515. Si pegás un SID (S-1-5-21-…) o un GUID, también te da su forma binaria para buscar por objectSid u objectGUID.',
  empty: 'Pegá un filtro LDAP para analizarlo.',
  'about.h': 'Para tener en cuenta',
  'about.1': '<code>memberOf</code> solo lista la membresía directa. Para incluir grupos anidados se usa la regla <code>1.2.840.113556.1.4.1941</code> (<code>LDAP_MATCHING_RULE_IN_CHAIN</code>), que es exacta pero puede ser costosa en jerarquías grandes.',
  'about.2': 'En AD, <code>computer</code> hereda de <code>user</code>: <code>(objectClass=user)</code> también devuelve equipos. Para personas se combina con <code>(objectCategory=person)</code>.',
  'about.3': 'Un comodín al principio (<code>cn=*ventas</code>) no puede usar el índice del atributo y obliga a recorrer todos los objetos del alcance.',
  'about.4': '<code>(!(atributo=valor))</code> también trae los objetos que no tienen ese atributo. Si eso no es lo que querés, agregá <code>(atributo=*)</code>.',
});

// ── Matching rules and attribute knowledge ───────────────

const RULES = {
  '1.2.840.113556.1.4.803': ['LDAP_MATCHING_RULE_BIT_AND', 'bitwise AND: every bit in the value must be set', 'AND de bits: tienen que estar todos los bits del valor'],
  '1.2.840.113556.1.4.804': ['LDAP_MATCHING_RULE_BIT_OR', 'bitwise OR: at least one bit in the value must be set', 'OR de bits: alcanza con que esté uno de los bits del valor'],
  '1.2.840.113556.1.4.1941': ['LDAP_MATCHING_RULE_IN_CHAIN', 'walks the chain of links (nested groups, manager chains…)', 'recorre la cadena de vínculos (grupos anidados, cadenas de manager…)'],
  '1.2.840.113556.1.4.2253': ['LDAP_MATCHING_RULE_DN_WITH_DATA', 'matches DN-Binary / DN-String values by their DN part', 'compara valores DN-Binary / DN-String por la parte del DN'],
};
const BIT_AND = '1.2.840.113556.1.4.803';
const BIT_OR = '1.2.840.113556.1.4.804';
const IN_CHAIN = '1.2.840.113556.1.4.1941';

const BIT_ATTRS = {
  useraccountcontrol: UAC_FLAGS,
  grouptype: GROUP_TYPE_FLAGS,
  'msds-supportedencryptiontypes': ENCTYPE_FLAGS,
};
// Attributes every object of its class has: negating them needs no warning.
const ALWAYS_SET = new Set(['objectclass', 'objectcategory', 'useraccountcontrol', 'samaccountname', 'samaccounttype', 'grouptype', 'distinguishedname', 'name', 'cn', 'objectsid', 'objectguid']);
const FILETIME_ATTRS = new Set(['lastlogontimestamp', 'lastlogon', 'pwdlastset', 'accountexpires', 'lockouttime', 'badpasswordtime']);

// ── Parser (RFC 4515) ────────────────────────────────────

class ParseError extends Error {
  constructor(message, pos) {
    super(message);
    this.pos = pos;
  }
}

const ATTR = String.raw`(?:[A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)+)(?:;[A-Za-z0-9-]+)*`;
const SIMPLE = new RegExp(String.raw`(${ATTR})(=|~=|>=|<=)`, 'y');
const EXT = new RegExp(String.raw`(${ATTR})?(:dn)?(?::([A-Za-z][A-Za-z0-9-]*|\d+(?:\.\d+)+))?:=`, 'iy');

function parse(input) {
  const lead = input.length - input.trimStart().length;
  let src = input.trim();
  const wrapped = src[0] !== '(';
  if (wrapped) src = `(${src})`;
  const offset = wrapped ? lead - 1 : lead;
  let i = 0;
  let loose = false; // whitespace between components

  const ws = () => {
    const s = i;
    while (i < src.length && /\s/.test(src[i])) i++;
    if (i > s) loose = true;
  };

  function filter() {
    ws();
    if (src[i] !== '(') throw new ParseError(i >= src.length ? tr('The filter ends too early: a ")" is missing.', 'El filtro termina antes de tiempo: falta un ")".') : tr('Expected "(".', 'Se esperaba "(".'), i);
    const start = i++;
    let node;
    const c = src[i];
    if (c === '&' || c === '|') {
      i++;
      const children = [];
      ws();
      while (src[i] === '(') {
        children.push(filter());
        ws();
      }
      if (src[i] !== ')' && i < src.length) throw new ParseError(tr('Expected "(" or ")" inside (&…) / (|…).', 'Se esperaba "(" o ")" dentro de (&…) / (|…).'), i);
      node = { type: c === '&' ? 'and' : 'or', children };
    } else if (c === '!') {
      i++;
      const child = filter();
      ws();
      if (src[i] === '(') throw new ParseError(tr('(!…) takes exactly one filter. Wrap several in (&…) or (|…) first.', '(!…) admite un solo filtro. Si son varios, envolvelos en (&…) o (|…).'), i);
      node = { type: 'not', child };
    } else {
      node = item();
    }
    if (src[i] !== ')') throw new ParseError(tr('Missing ")".', 'Falta un ")".'), i);
    i++;
    node.start = start;
    node.end = i;
    return node;
  }

  function item() {
    const s = i;
    SIMPLE.lastIndex = i;
    let m = SIMPLE.exec(src);
    let node;
    if (m) {
      i = SIMPLE.lastIndex;
      node = { attr: m[1], op: m[2] };
    } else {
      EXT.lastIndex = i;
      m = EXT.exec(src);
      if (m && (m[1] || m[3])) {
        i = EXT.lastIndex;
        node = { type: 'ext', attr: m[1] || '', dn: !!m[2], rule: m[3] || '', op: ':=' };
      } else {
        const close = src.indexOf(')', i);
        const chunk = src.slice(i, close < 0 ? undefined : close);
        const eq = chunk.indexOf('=');
        if (eq < 0) throw new ParseError(tr('Missing operator: use =, >=, <= or ~=.', 'Falta el operador: =, >=, <= o ~=.'), i);
        if (/\s/.test(chunk.slice(0, eq + 1))) throw new ParseError(tr('Spaces are not allowed in the attribute name or before the operator.', 'No se permiten espacios en el nombre del atributo ni antes del operador.'), i + chunk.search(/\s/));
        if (!chunk.slice(0, eq)) throw new ParseError(tr('Missing attribute name before "=".', 'Falta el nombre del atributo antes del "=".'), i);
        throw new ParseError(tr('Invalid attribute description: letters, digits and "-", starting with a letter, or a numeric OID.', 'Descripción de atributo inválida: letras, dígitos y "-", empezando por letra, o un OID numérico.'), i);
      }
    }

    // value: up to the next unescaped ')'
    const vs = i;
    const stars = [];
    while (i < src.length && src[i] !== ')') {
      const ch = src[i];
      if (ch === '(') throw new ParseError(tr('Unescaped "(" in a value: write \\28.', '"(" sin escapar en un valor: escribí \\28.'), i);
      if (ch === '\\') {
        if (!/^[0-9a-fA-F]{2}$/.test(src.slice(i + 1, i + 3))) throw new ParseError(tr('"\\" must be followed by two hex digits (\\2a, \\28, \\5c…).', '"\\" debe ir seguido de dos dígitos hex (\\2a, \\28, \\5c…).'), i);
        i += 3;
        continue;
      }
      if (ch === '*') stars.push(i - vs);
      i++;
    }
    if (i >= src.length) throw new ParseError(tr('Missing ")" at the end of the value.', 'Falta el ")" al final del valor.'), i);
    const raw = src.slice(vs, i);

    if (stars.length && node.op !== '=') {
      throw new ParseError(tr('"*" is only a wildcard with "="; escape it as \\2a.', '"*" solo es comodín con "="; escapalo como \\2a.'), vs + stars[0]);
    }
    if (node.op === '=' && raw === '*') return { type: 'present', attr: node.attr, text: src.slice(s, i) };
    if (node.op === '=' && stars.length) {
      const parts = [];
      let last = 0;
      for (const p of stars) {
        parts.push(raw.slice(last, p));
        last = p + 1;
      }
      parts.push(raw.slice(last));
      return {
        type: 'substr',
        attr: node.attr,
        initial: parts[0],
        any: parts.slice(1, -1),
        final: parts[parts.length - 1],
        text: src.slice(s, i),
      };
    }
    const types = { '=': 'eq', '>=': 'ge', '<=': 'le', '~=': 'approx' };
    return { type: node.type || types[node.op], ...node, value: raw, text: src.slice(s, i) };
  }

  try {
    const tree = filter();
    ws();
    if (i < src.length) {
      if (src[i] === '(') throw new ParseError(tr('Two filters side by side: combine them with (&…) or (|…).', 'Dos filtros seguidos: combinalos con (&…) o (|…).'), i);
      throw new ParseError(tr('Unexpected text after the end of the filter.', 'Texto inesperado después del final del filtro.'), i);
    }
    return { tree, wrapped, loose };
  } catch (e) {
    // report positions in the user's text, not in the trimmed/wrapped copy
    if (e instanceof ParseError) e.pos = Math.max(0, Math.min(input.length, e.pos + offset));
    throw e;
  }
}

// ── Values ───────────────────────────────────────────────

/** Escaped assertion value → bytes. */
function valueBytes(raw) {
  const out = [];
  const enc = new TextEncoder();
  for (let i = 0; i < raw.length; ) {
    if (raw[i] === '\\') {
      out.push(parseInt(raw.slice(i + 1, i + 3), 16));
      i += 3;
    } else {
      const cp = raw.codePointAt(i);
      const ch = String.fromCodePoint(cp);
      out.push(...enc.encode(ch));
      i += ch.length;
    }
  }
  return new Uint8Array(out);
}

function readable(raw) {
  const bytes = valueBytes(raw);
  try {
    const s = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!/[\u0000-\u0008\u000e-\u001f]/.test(s)) return { text: s, bytes };
  } catch {
    /* binary */
  }
  return { hex: toHex(bytes, ' '), bytes };
}

function sidFromBytes(b) {
  if (b.length < 8 || b[0] !== 1 || b.length !== 8 + b[1] * 4) return null;
  let auth = 0;
  for (let i = 2; i < 8; i++) auth = auth * 256 + b[i];
  const subs = [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  for (let i = 0; i < b[1]; i++) subs.push(dv.getUint32(8 + i * 4, true));
  return `S-1-${auth}-${subs.join('-')}`;
}

function guidFromBytes(b) {
  if (b.length !== 16) return null;
  const h = (idx) => idx.map((i) => b[i].toString(16).padStart(2, '0')).join('');
  return `${h([3, 2, 1, 0])}-${h([5, 4])}-${h([7, 6])}-${h([8, 9])}-${h([10, 11, 12, 13, 14, 15])}`;
}

function sidToBytes(sid) {
  const m = sid.trim().match(/^S-1-(\d+)((?:-\d+){1,15})$/i);
  if (!m) return null;
  const subs = m[2].slice(1).split('-').map(Number);
  if (subs.some((n) => n > 0xffffffff)) return null;
  const b = new Uint8Array(8 + subs.length * 4);
  b[0] = 1;
  b[1] = subs.length;
  let auth = Number(m[1]);
  for (let i = 7; i >= 2; i--) {
    b[i] = auth % 256;
    auth = Math.floor(auth / 256);
  }
  const dv = new DataView(b.buffer);
  subs.forEach((n, i) => dv.setUint32(8 + i * 4, n, true));
  return b;
}

function guidToBytes(guid) {
  const g = guid.trim().replace(/^\{|\}$/g, '');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(g)) return null;
  const hex = g.replace(/-/g, '');
  const raw = hex.match(/../g).map((x) => parseInt(x, 16));
  return new Uint8Array([raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], ...raw.slice(8)]);
}

const escBytes = (bytes) => [...bytes].map((x) => `\\${x.toString(16).padStart(2, '0')}`).join('');

function escapeValue(s, nonAscii) {
  let out = '';
  for (const ch of s) {
    if (ch === '\\' || ch === '*' || ch === '(' || ch === ')' || ch === '\0') out += escBytes([ch.charCodeAt(0)]);
    else if (nonAscii && ch.codePointAt(0) > 0x7e) out += escBytes(new TextEncoder().encode(ch));
    else out += ch;
  }
  return out;
}

const EPOCH_DIFF_MS = 11644473600000n;

/** Extra line under a value: dates, flags, SIDs… (plain text). */
function interpret(attr, raw, rule) {
  const a = attr.toLowerCase().split(';')[0];
  const r = readable(raw);
  const s = r.text ?? '';

  if ((BIT_ATTRS[a] || rule === BIT_AND || rule === BIT_OR) && /^-?\d+$/.test(s)) {
    const flags = BIT_ATTRS[a];
    const n = Number(s);
    if (!flags) return `0x${(n >>> 0).toString(16).toUpperCase()}`;
    const { set, unknown } = decodeBits(flags, n);
    const names = set.map((f) => f.name);
    if (unknown) names.push(`0x${unknown.toString(16).toUpperCase()} ${tr('(undefined bits)', '(bits no definidos)')}`);
    return names.join(' + ') || tr('no flags', 'sin flags');
  }
  if (FILETIME_ATTRS.has(a) && /^\d+$/.test(s)) {
    const n = BigInt(s);
    if (n === 0n) return tr('0: not set / never', '0: sin valor / nunca');
    if (n >= 9223372036854775807n) return tr('maximum value: never', 'valor máximo: nunca');
    const d = new Date(Number(n / 10000n - EPOCH_DIFF_MS));
    return Number.isNaN(d.getTime()) ? '' : `FILETIME → ${fmtDate(d)} (${relative(d)})`;
  }
  const gt = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/i);
  if (gt) {
    const d = new Date(Date.UTC(gt[1], gt[2] - 1, gt[3], gt[4], gt[5], gt[6]));
    return `Generalized Time → ${fmtDate(d)} (${relative(d)})`;
  }
  if (a === 'objectsid' && r.hex) return sidFromBytes(r.bytes) || '';
  if (a === 'objectguid' && r.hex) {
    const g = guidFromBytes(r.bytes);
    return g ? `GUID ${g}` : '';
  }
  return '';
}

// ── Output ───────────────────────────────────────────────

const isLeaf = (n) => !['and', 'or', 'not'].includes(n.type);

function compact(n) {
  if (n.type === 'and' || n.type === 'or') return `(${n.type === 'and' ? '&' : '|'}${n.children.map(compact).join('')})`;
  if (n.type === 'not') return `(!${compact(n.child)})`;
  return `(${n.text})`;
}

function leafHtml(n) {
  const m = n.text.match(/^([^=~<>:]*)(.*)$/s);
  return `(<span class="k">${esc(m[1])}</span>${esc(m[2])})`;
}

function compactHtml(n) {
  if (n.type === 'and' || n.type === 'or') return `(${n.type === 'and' ? '&amp;' : '|'}${n.children.map(compactHtml).join('')})`;
  if (n.type === 'not') return `(!${compactHtml(n.child)})`;
  return leafHtml(n);
}

/** Indented filter; html=true escapes and highlights attribute names. */
function format(n, depth = 0, html = false) {
  const pad = '  '.repeat(depth);
  const one = html ? compactHtml : compact;
  if (n.type === 'and' || n.type === 'or') {
    const op = n.type === 'and' ? (html ? '&amp;' : '&') : '|';
    if (!n.children.length) return `${pad}(${op})`;
    return `${pad}(${op}\n${n.children.map((c) => format(c, depth + 1, html)).join('\n')}\n${pad})`;
  }
  if (n.type === 'not') {
    if (isLeaf(n.child)) return `${pad}${one(n)}`;
    return `${pad}(!\n${format(n.child, depth + 1, html)}\n${pad})`;
  }
  return `${pad}${one(n)}`;
}

function val(raw) {
  if (raw === '') return `<em>${tr('(empty)', '(vacío)')}</em>`;
  const r = readable(raw);
  return r.text !== undefined ? `<code>${esc(r.text)}</code>` : `<code>${esc(r.hex)}</code> <em>${tr('(binary)', '(binario)')}</em>`;
}

function explainLeaf(n) {
  const attr = `<code>${esc(n.attr)}</code>`;
  let line;
  let sub = '';
  switch (n.type) {
    case 'present':
      line = tr(`${attr} has a value`, `${attr} tiene algún valor`);
      break;
    case 'eq':
      line = tr(`${attr} equals ${val(n.value)}`, `${attr} es igual a ${val(n.value)}`);
      sub = interpret(n.attr, n.value);
      break;
    case 'ge':
      line = tr(`${attr} is greater than or equal to ${val(n.value)}`, `${attr} es mayor o igual que ${val(n.value)}`);
      sub = interpret(n.attr, n.value);
      break;
    case 'le':
      line = tr(`${attr} is less than or equal to ${val(n.value)}`, `${attr} es menor o igual que ${val(n.value)}`);
      sub = interpret(n.attr, n.value);
      break;
    case 'approx':
      line = tr(`${attr} approximately matches ${val(n.value)}`, `${attr} coincide aproximadamente con ${val(n.value)}`);
      break;
    case 'substr': {
      const bits = [];
      if (n.initial) bits.push(tr(`starts with ${val(n.initial)}`, `empieza con ${val(n.initial)}`));
      n.any.filter(Boolean).forEach((a) => bits.push(tr(`contains ${val(a)}`, `contiene ${val(a)}`)));
      if (n.final) bits.push(tr(`ends with ${val(n.final)}`, `termina con ${val(n.final)}`));
      line = `${attr} ${bits.join(tr(', then ', ', después '))}`;
      break;
    }
    case 'ext': {
      const known = RULES[n.rule];
      const target = n.attr ? attr : tr('any attribute', 'cualquier atributo');
      if (n.rule === BIT_AND || n.rule === BIT_OR) {
        line = n.rule === BIT_AND
          ? tr(`${target} has <strong>all</strong> these bits set: ${val(n.value)}`, `${target} tiene <strong>todos</strong> estos bits: ${val(n.value)}`)
          : tr(`${target} has <strong>at least one</strong> of these bits: ${val(n.value)}`, `${target} tiene <strong>al menos uno</strong> de estos bits: ${val(n.value)}`);
        sub = interpret(n.attr, n.value, n.rule);
      } else if (n.rule === IN_CHAIN) {
        line = tr(`${target} links to ${val(n.value)} <strong>directly or through nesting</strong>`, `${target} apunta a ${val(n.value)} <strong>directamente o por anidamiento</strong>`);
      } else {
        line = tr(`${target} matches ${val(n.value)} with rule <code>${esc(n.rule || 'equality')}</code>`, `${target} coincide con ${val(n.value)} según la regla <code>${esc(n.rule || 'igualdad')}</code>`);
      }
      const bitRule = n.rule === BIT_AND || n.rule === BIT_OR;
      const meta = [known && !bitRule && `${known[0]}: ${tr(known[1], known[2])}`, known && bitRule && known[0], n.dn && tr(':dn also matches the attributes of the entry DN', ':dn también compara contra los atributos del DN de la entrada')].filter(Boolean);
      if (meta.length) sub = [sub, ...meta].filter(Boolean).join(' · ');
      break;
    }
    default:
      line = esc(n.text);
  }
  let link = '';
  const num = readable(n.value ?? '').text;
  if (n.attr.toLowerCase() === 'useraccountcontrol' && (n.type === 'eq' || n.type === 'ext') && /^\d+$/.test(num || '')) {
    link = ` <a href="/identity-tools/uac/?v=${Number(num) >>> 0}">${tr('open in the calculator', 'abrir en la calculadora')} →</a>`;
  }
  return `<div class="lx-leaf">${line}${sub || link ? `<small>${esc(sub)}${link}</small>` : ''}</div>`;
}

function explain(n) {
  if (n.type === 'and' || n.type === 'or') {
    if (!n.children.length) {
      return `<div class="lx-op">${n.type === 'and' ? tr('(&) — always true (RFC 4526)', '(&) — siempre verdadero (RFC 4526)') : tr('(|) — always false (RFC 4526)', '(|) — siempre falso (RFC 4526)')}</div>`;
    }
    const head = n.type === 'and' ? tr('All of these', 'Todas estas condiciones') : tr('Any of these', 'Alguna de estas condiciones');
    return `<div class="lx-op">${head}</div><ul>${n.children.map((c) => `<li>${explain(c)}</li>`).join('')}</ul>`;
  }
  if (n.type === 'not') {
    return `<div class="lx-op">${tr('Not', 'Que no se cumpla')}</div><ul><li>${explain(n.child)}</li></ul>`;
  }
  return explainLeaf(n);
}

// ── Review notes ─────────────────────────────────────────

function review(parsed) {
  const notes = [];
  const seen = new Set();
  const note = (key, level, en, es, html = false) => {
    if (seen.has(key)) return;
    seen.add(key);
    notes.push(html ? { level, html: tr(en, es) } : { level, text: tr(en, es) });
  };
  const leaves = [];
  const walk = (n, negated) => {
    if (n.type === 'and' || n.type === 'or') n.children.forEach((c) => walk(c, negated));
    else if (n.type === 'not') walk(n.child, !negated);
    else leaves.push({ n, negated, a: n.attr.toLowerCase().split(';')[0] });
  };
  walk(parsed.tree, false);

  const has = (pred) => leaves.some(pred);
  const eqv = (l, attr, v) => l.n.type === 'eq' && l.a === attr && (readable(l.n.value).text || '').toLowerCase() === v;

  if (parsed.wrapped) note('wrap', 'info', 'The filter had no outer parentheses; they were added. RFC 4515 requires them, although some tools add them for you.', 'El filtro no tenía paréntesis exteriores y se agregaron. RFC 4515 los exige, aunque algunas herramientas los agregan solas.');
  if (parsed.loose) note('ws', 'info', 'Whitespace between components was ignored. RFC 4515 does not allow it and some clients reject it: use the compact form.', 'Se ignoraron espacios entre componentes. RFC 4515 no los permite y algunos clientes los rechazan: usá la forma compacta.');

  for (const l of leaves) {
    const { n, a } = l;
    if (n.type === 'substr' && n.initial === '' && a !== 'anr') {
      note('lead', 'warn', `Leading wildcard on ${n.attr}: it cannot use the index and forces a scan of every object in scope.`, `Comodín al principio en ${n.attr}: no puede usar el índice y obliga a recorrer todos los objetos del alcance.`);
    }
    if (n.type === 'eq' && a === 'memberof') {
      note('memberof', 'info', 'memberOf only matches direct membership. For nested groups use memberOf:1.2.840.113556.1.4.1941:=<group DN>.', 'memberOf solo coincide con la membresía directa. Para grupos anidados usá memberOf:1.2.840.113556.1.4.1941:=<DN del grupo>.');
    }
    if (n.type === 'ext' && n.rule === IN_CHAIN) {
      note('chain', 'info', 'IN_CHAIN (1.2.840.113556.1.4.1941) is exact but can be slow on deep or wide group hierarchies; scope the search base when you can.', 'IN_CHAIN (1.2.840.113556.1.4.1941) es exacta pero puede ser lenta con jerarquías de grupos profundas o anchas; acotá la base de búsqueda cuando puedas.');
    }
    if (n.type === 'eq' && a === 'useraccountcontrol') {
      note('uaceq', 'warn', `(userAccountControl=${readable(n.value).text}) only matches that exact value: 512 misses 66048 (enabled + password never expires). Use the bitwise rule 1.2.840.113556.1.4.803 for single flags.`, `(userAccountControl=${readable(n.value).text}) solo coincide con ese valor exacto: 512 no trae 66048 (habilitada + contraseña sin vencimiento). Para flags sueltos usá la regla de bits 1.2.840.113556.1.4.803.`);
    }
    if (n.type === 'ext' && a === 'useraccountcontrol' && /^\d+$/.test(n.value) && (Number(n.value) & (0x10 | 0x800000))) {
      note('uaccomp', 'warn', 'LOCKOUT (16) and PASSWORD_EXPIRED (8388608) are not maintained in userAccountControl, so this filter will miss accounts. Use lockoutTime>=1 or msDS-User-Account-Control-Computed (not searchable) instead.', 'LOCKOUT (16) y PASSWORD_EXPIRED (8388608) no se mantienen en userAccountControl, así que el filtro se va a perder cuentas. Usá lockoutTime>=1 o msDS-User-Account-Control-Computed (no se puede filtrar por él).');
    }
    if (n.type === 'ext' && n.rule && !RULES[n.rule] && /^\d/.test(n.rule)) {
      note(`rule${n.rule}`, 'info', `Matching rule ${n.rule} is not one of the AD rules this tool knows; check that your directory supports it.`, `La regla ${n.rule} no es una de las reglas de AD que conoce esta herramienta; verificá que tu directorio la soporte.`);
    }
    if (a === 'lastlogon') {
      note('lastlogon', 'info', 'lastLogon is not replicated: each DC has its own value. For stale-account reports use lastLogonTimestamp.', 'lastLogon no se replica: cada DC tiene su propio valor. Para reportes de cuentas inactivas usá lastLogonTimestamp.');
    }
    if (l.negated && n.type !== 'present' && !ALWAYS_SET.has(a)) {
      note('neg', 'info', `A negated condition also matches objects that have no ${n.attr} at all. Add (${n.attr}=*) if that is not what you want.`, `Una condición negada también trae objetos que no tienen ${n.attr}. Si no es lo que buscás, agregá (${n.attr}=*).`);
    }
  }

  if (has((l) => eqv(l, 'objectclass', 'user')) && !has((l) => l.a === 'objectcategory') && !has((l) => eqv(l, 'samaccounttype', '805306368'))) {
    note('objuser', 'info', '(objectClass=user) also returns computer accounts, which inherit from user. For people add (objectCategory=person).', '(objectClass=user) también devuelve cuentas de equipo, que heredan de user. Para personas agregá (objectCategory=person).');
  }
  if (parsed.tree.type === 'present' && parsed.tree.attr.toLowerCase() === 'objectclass') {
    note('all', 'info', '(objectClass=*) matches every object in scope.', '(objectClass=*) coincide con todos los objetos del alcance.');
  }

  if (!notes.some((x) => x.level === 'warn' || x.level === 'bad')) {
    notes.unshift({ level: 'ok', text: tr('Valid RFC 4515 filter.', 'Filtro válido según RFC 4515.') });
  }
  return { notes, leaves };
}

// ── Queries ──────────────────────────────────────────────

function queries(leaves, filter) {
  const eq = (attr, v) => leaves.some((l) => l.n.type === 'eq' && l.a === attr && (readable(l.n.value).text || '').toLowerCase() === v);
  let cmd = 'Get-ADObject';
  if (eq('objectcategory', 'computer') || eq('objectclass', 'computer')) cmd = 'Get-ADComputer';
  else if (eq('objectcategory', 'group') || eq('objectclass', 'group')) cmd = 'Get-ADGroup';
  else if (eq('objectcategory', 'person') || eq('objectclass', 'user')) cmd = 'Get-ADUser';

  const skip = new Set(['objectclass', 'objectcategory', 'samaccountname', 'name', 'distinguishedname']);
  const props = [...new Map(leaves.filter((l) => l.n.attr && !skip.has(l.a)).map((l) => [l.a, l.n.attr.split(';')[0]])).values()];
  const ps = `${cmd} -LDAPFilter '${filter.replace(/'/g, "''")}'${props.length ? ` -Properties ${props.join(', ')}` : ''}`;
  const sh = `ldapsearch -H ldaps://dc.example.com -D 'user@example.com' -W -b 'DC=example,DC=com' \\\n  '${filter.replace(/'/g, "'\\''")}'${props.length ? ` \\\n  ${props.join(' ')}` : ''}`;
  return { ps, sh };
}

// ── Rendering ────────────────────────────────────────────

const $ = (id) => document.getElementById(id);
const inputEl = $('input');
const resultEl = $('result');
const renderTabs = tabs(resultEl);

function errorHtml(e, src) {
  const pos = e.pos;
  const before = src.slice(0, pos);
  const lineNo = before.split('\n').length;
  const lineStart = before.lastIndexOf('\n') + 1;
  const lineEnd = src.indexOf('\n', pos);
  const line = src.slice(lineStart, lineEnd < 0 ? undefined : lineEnd);
  const col = pos - lineStart;
  const where = tr(`line ${lineNo}, column ${col + 1}`, `línea ${lineNo}, columna ${col + 1}`);
  return `<div class="error">${esc(e.message)} <small>(${where})</small></div>
    <pre class="code">${esc(line)}\n<span class="k">${' '.repeat(col)}^</span></pre>`;
}

function render() {
  const src = inputEl.value;
  if (!src.trim()) {
    resultEl.innerHTML = `<p class="empty">${tr('Paste an LDAP filter to analyse it.', 'Pegá un filtro LDAP para analizarlo.')}</p>`;
    return;
  }
  let parsed;
  try {
    parsed = parse(src);
  } catch (e) {
    if (!(e instanceof ParseError)) throw e;
    resultEl.innerHTML = errorHtml(e, src);
    return;
  }
  const { notes, leaves } = review(parsed);
  const one = compact(parsed.tree);
  const q = queries(leaves, one);

  const summary = `${notesHtml(notes)}<h3 class="sub">${tr('What it matches', 'Qué busca')}</h3><div class="lx">${explain(parsed.tree)}</div>`;
  const formatted = `
    <h3 class="sub">${tr('Indented', 'Indentado')}</h3>
    <pre class="code">${format(parsed.tree, 0, true)}</pre>
    <textarea id="fmtPlain" hidden>${esc(format(parsed.tree))}</textarea>
    <div class="btn-row">${copyBtn('#fmtPlain')}</div>
    <h3 class="sub">${tr('Single line', 'En una línea')}</h3>
    <pre class="code" id="oneLine">${esc(one)}</pre>
    <div class="btn-row">${copyBtn('#oneLine')}</div>`;
  const query = `
    <h3 class="sub">PowerShell (${tr('ActiveDirectory module', 'módulo ActiveDirectory')})</h3>
    <pre class="code" id="psOut">${esc(q.ps)}</pre>
    <div class="btn-row">${copyBtn('#psOut')}</div>
    <h3 class="sub">ldapsearch (OpenLDAP)</h3>
    <pre class="code" id="shOut">${esc(q.sh)}</pre>
    <div class="btn-row">${copyBtn('#shOut')}</div>
    <p class="hint">${esc(tr('Replace the server, bind account and search base with yours. The cmdlet is picked from objectCategory / objectClass in the filter.', 'Reemplazá el servidor, la cuenta de conexión y la base de búsqueda por los tuyos. El cmdlet se elige según objectCategory / objectClass del filtro.'))}</p>`;

  resultEl.innerHTML = renderTabs([
    { id: 'explain', label: tr('Explanation', 'Explicación'), html: summary },
    { id: 'format', label: tr('Formatted', 'Formateado'), html: formatted },
    { id: 'query', label: tr('Queries', 'Consultas'), html: query },
  ]);
}

// ── Escape a value ───────────────────────────────────────

function renderEscape() {
  const raw = $('escIn').value;
  const out = $('escOut');
  if (!raw) {
    out.innerHTML = '';
    return;
  }
  const blocks = [[tr('Escaped value', 'Valor escapado'), escapeValue(raw, $('nonAscii').checked), 'escVal']];
  const sid = sidToBytes(raw);
  const guid = !sid && guidToBytes(raw);
  if (sid) {
    blocks.push([tr('objectSid as binary', 'objectSid en binario'), `(objectSid=${escBytes(sid)})`, 'escSid']);
  }
  if (guid) blocks.push([tr('objectGUID as binary', 'objectGUID en binario'), `(objectGUID=${escBytes(guid)})`, 'escGuid']);
  out.innerHTML =
    blocks.map(([h, v, id]) => `<h3 class="sub">${esc(h)}</h3><pre class="code" id="${id}">${esc(v)}</pre><div class="btn-row">${copyBtn(`#${id}`)}</div>`).join('') +
    (sid ? `<p class="hint">${esc(tr('AD also accepts the SID string directly: (objectSid=' + raw.trim() + ').', 'AD también acepta el SID como texto: (objectSid=' + raw.trim() + ').'))}</p>` : '');
}

// ── Templates ────────────────────────────────────────────

const UAC = BIT_AND;
const TEMPLATES = [
  ['Enabled users', 'Usuarios habilitados', `(&(objectCategory=person)(objectClass=user)(!(userAccountControl:${UAC}:=2)))`],
  ['Members of a group, including nested', 'Miembros de un grupo, incluidos los anidados', `(memberOf:${IN_CHAIN}:=CN=App-Users,OU=Groups,DC=example,DC=com)`],
  ['Groups a user belongs to, including nested', 'Grupos de un usuario, incluidos los anidados', `(&(objectCategory=group)(member:${IN_CHAIN}:=CN=Jane Doe,OU=Users,DC=example,DC=com))`],
  ['Enabled users whose password never expires', 'Usuarios habilitados con contraseña sin vencimiento', `(&(objectCategory=person)(objectClass=user)(userAccountControl:${UAC}:=65536)(!(userAccountControl:${UAC}:=2)))`],
  ['Users who must change password at next logon', 'Usuarios que deben cambiar la contraseña al iniciar sesión', '(&(objectCategory=person)(objectClass=user)(pwdLastSet=0))'],
  ['Users with an SPN (Kerberoastable)', 'Usuarios con SPN (kerberoasteables)', `(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:${UAC}:=2)))`],
  ['No Kerberos pre-authentication (AS-REP roastable)', 'Sin preautenticación Kerberos (AS-REP roasting)', `(&(objectCategory=person)(objectClass=user)(userAccountControl:${UAC}:=4194304))`],
  ['Unconstrained delegation, excluding DCs', 'Delegación sin restricciones, sin contar DCs', `(&(userAccountControl:${UAC}:=524288)(!(userAccountControl:${UAC}:=8192)))`],
  ['Accounts that explicitly allow DES or RC4', 'Cuentas que permiten DES o RC4 explícitamente', `(msDS-SupportedEncryptionTypes:${BIT_OR}:=7)`],
  ['Protected accounts (adminCount=1)', 'Cuentas protegidas (adminCount=1)', '(&(objectCategory=person)(objectClass=user)(adminCount=1))'],
  ['Empty security groups', 'Grupos de seguridad vacíos', `(&(objectCategory=group)(groupType:${UAC}:=2147483648)(!(member=*)))`],
  ['Computers running Windows Server 2012', 'Equipos con Windows Server 2012', '(&(objectCategory=computer)(operatingSystem=Windows Server 2012*))'],
];

function renderTemplates() {
  const sel = $('tpl');
  const keep = sel.value;
  sel.innerHTML = `<option value="">${esc(tr('Load a template…', 'Cargar una plantilla…'))}</option>` +
    TEMPLATES.map(([en, es], i) => `<option value="${i}">${esc(tr(en, es))}</option>`).join('');
  sel.value = keep;
}

$('tpl').addEventListener('change', (e) => {
  const t = TEMPLATES[e.target.value];
  if (!t) return;
  inputEl.value = t[2];
  render();
});
$('clear').addEventListener('click', () => {
  inputEl.value = '';
  $('tpl').value = '';
  render();
  inputEl.focus();
});
onInput(inputEl, render, 150);
onInput($('escIn'), renderEscape, 100);
$('nonAscii').addEventListener('change', renderEscape);
document.addEventListener('langchange', () => {
  renderTemplates();
  render();
  renderEscape();
});

renderTemplates();
inputEl.value = TEMPLATES[0][2];
render();
