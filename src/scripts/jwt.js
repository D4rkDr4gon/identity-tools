import { initPage, esc, jsonHtml, b64ToBytes, bytesToUtf8, fmtDate, fmtLocal, relative, onInput } from './common.js';
import { tr } from './i18n.js';
import { certToSpki, pemToDer } from './der.js';

initPage({
  _title: 'Decodificador y verificador de JWT — Identity Tools',
  h1: 'Decodificador y verificador de JWT',
  lead: 'Pegá un id_token o access token para ver el header, los claims y la ventana de validez, y verificá la firma con un secreto compartido, una clave pública, un certificado o el JWKS del emisor.',
  'token.label': 'Token',
  'token.hint': 'Si empieza con "Bearer " o es una línea de header Authorization, se limpia sola.',
  'verify.title': 'Verificar firma',
  'key.label': 'Secreto, clave pública, certificado o JWKS',
  'key.b64': 'El secreto HMAC está en base64 / base64url',
  'verify.btn': 'Verificar',
  'key.hint': 'Acepta: secreto HMAC (HS*), clave pública PEM (SPKI), certificado PEM, un JWK o un JWKS (se elige por kid). Soporta HS, RS, PS, ES y EdDSA.',
  empty: 'Pegá un token para decodificarlo.',
  'about.h': 'Qué revisa',
  'about.1': 'Decodifica header y payload (base64url) y convierte <code>exp</code>, <code>nbf</code>, <code>iat</code> y <code>auth_time</code> a fechas legibles.',
  'about.2': 'Marca problemas comunes: <code>alg: none</code>, falta de <code>exp</code>, algoritmos simétricos, vidas útiles largas, tokens vencidos o todavía no válidos.',
  'about.3': 'Reconoce tokens de Entra ID (emisor v1/v2, <code>tid</code>, <code>oid</code>, audiencia de Microsoft Graph) y explica las sorpresas habituales.',
  'about.4': 'Verifica la firma con la Web Crypto API. De los tokens cifrados (JWE) solo se puede mostrar el header.',
});

const SAMPLE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlbW8tMjAyNiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6Impkb2UiLCJhdWQiOiJodHRwczovL2FwcC5leGFtcGxlLmNvbSIsImlhdCI6MTc5Mzc1MDQwMCwibmJmIjoxNzkzNzUwNDAwLCJleHAiOjE3OTM3NTQwMDAsIm5hbWUiOiJKYW5lIERvZSIsImVtYWlsIjoiamFuZS5kb2VAZXhhbXBsZS5jb20iLCJncm91cHMiOlsiYXBwLXVzZXJzIiwiZmluYW5jZS1yZWFkZXJzIl0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJhbXIiOlsicHdkIiwibWZhIl19.OlgG1GeSV7Dquq7HCrqNn_kwbtYUpye_ZduTPUUrfAw';
const SAMPLE_SECRET = 'identity-tools-demo-secret';

const GRAPH_AUD = ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'];

// Registered (RFC 7519 / OIDC) and common Entra ID claims.
const CLAIMS = {
  iss: ['Issuer', 'Emisor'],
  sub: ['Subject', 'Sujeto'],
  aud: ['Audience', 'Audiencia'],
  exp: ['Expires', 'Vence'],
  nbf: ['Not before', 'No antes de'],
  iat: ['Issued at', 'Emitido'],
  jti: ['Token ID', 'ID del token'],
  auth_time: ['Authentication time', 'Momento de autenticación'],
  nonce: ['Nonce (replay protection)', 'Nonce (anti-replay)'],
  azp: ['Authorized party (client)', 'Parte autorizada (cliente)'],
  client_id: ['Client ID', 'Client ID'],
  scope: ['Scopes', 'Scopes'],
  scp: ['Scopes (Entra ID)', 'Scopes (Entra ID)'],
  roles: ['App roles', 'Roles de la aplicación'],
  groups: ['Groups', 'Grupos'],
  amr: ['Authentication methods', 'Métodos de autenticación'],
  acr: ['Authentication context', 'Contexto de autenticación'],
  sid: ['Session ID', 'ID de sesión'],
  name: ['Name', 'Nombre'],
  email: ['Email', 'Email'],
  preferred_username: ['Preferred username', 'Usuario preferido'],
  upn: ['User principal name', 'User principal name'],
  unique_name: ['Unique name (Entra v1)', 'Nombre único (Entra v1)'],
  oid: ['Object ID (Entra ID)', 'Object ID (Entra ID)'],
  tid: ['Tenant ID (Entra ID)', 'Tenant ID (Entra ID)'],
  appid: ['Application ID (Entra v1)', 'Application ID (Entra v1)'],
  idp: ['Identity provider', 'Proveedor de identidad'],
  ver: ['Token version', 'Versión del token'],
  wids: ['Directory role template IDs', 'IDs de roles de directorio'],
  hasgroups: ['Group overage (too many groups)', 'Exceso de grupos (overage)'],
  _claim_names: ['Claim sources (overage)', 'Fuentes de claims (overage)'],
};
const TIME_CLAIMS = ['exp', 'nbf', 'iat', 'auth_time'];

const $ = (id) => document.getElementById(id);
const tokenEl = $('token');
const keyEl = $('key');
const resultEl = $('result');
const verifyOut = $('verifyOut');

let parsed = null;

function clean(raw) {
  return raw
    .trim()
    .replace(/^authorization:\s*/i, '')
    .replace(/^bearer\s+/i, '')
    .replace(/^["']|["']$/g, '')
    .replace(/\s+/g, '');
}

function decodePart(part) {
  const text = bytesToUtf8(b64ToBytes(part));
  try {
    return { json: JSON.parse(text), text };
  } catch {
    return { json: null, text };
  }
}

function parse(raw) {
  const token = clean(raw);
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3 && parts.length !== 5) {
    throw new Error(
      tr(
        `A JWT has 3 parts (JWS) or 5 parts (JWE) separated by dots; this one has ${parts.length}.`,
        `Un JWT tiene 3 partes (JWS) o 5 (JWE) separadas por puntos; este tiene ${parts.length}.`,
      ),
    );
  }
  let header;
  try {
    header = decodePart(parts[0]);
  } catch {
    throw new Error(tr('The header is not valid base64url.', 'El header no es base64url válido.'));
  }
  if (!header.json) throw new Error(tr('The header is not valid JSON.', 'El header no es JSON válido.'));
  if (parts.length === 5) return { token, parts, header: header.json, jwe: true };
  let payload;
  try {
    payload = decodePart(parts[1]);
  } catch {
    throw new Error(tr('The payload is not valid base64url.', 'El payload no es base64url válido.'));
  }
  return { token, parts, header: header.json, payload: payload.json, payloadText: payload.text, jwe: false };
}

function notes(h, p) {
  const out = [];
  const add = (level, en, es) => out.push({ level, text: tr(en, es) });
  const alg = String(h.alg || '');
  const now = Date.now() / 1000;

  if (!alg || alg.toLowerCase() === 'none') {
    add('bad', 'alg is "none": the token is unsigned. A verifier must never accept it.', 'alg es "none": el token no está firmado. Ningún verificador debería aceptarlo.');
  } else if (/^HS/.test(alg)) {
    add('warn', `${alg} is symmetric: whoever can verify the token can also mint one. Fine inside one system, risky across parties.`, `${alg} es simétrico: quien puede verificar el token también puede emitir uno. Sirve dentro de un mismo sistema, es riesgoso entre partes.`);
  }
  if (h.jku || h.x5u) {
    add('warn', 'The header points to a key URL (jku/x5u). Verifiers must only fetch keys from allow-listed issuers.', 'El header apunta a una URL de claves (jku/x5u). El verificador solo debe obtener claves de emisores permitidos.');
  }
  if (h.jwk) {
    add('warn', 'The header embeds its own key (jwk). Trusting it lets anyone sign tokens.', 'El header trae su propia clave (jwk). Confiar en ella permite que cualquiera firme tokens.');
  }
  if (!p) return out;

  if (p.exp === undefined) {
    add('warn', 'No exp claim: the token never expires on its own.', 'No tiene claim exp: el token no vence nunca por sí solo.');
  } else if (p.exp < now) {
    add('bad', `Expired ${relative(new Date(p.exp * 1000))}.`, `Vencido ${relative(new Date(p.exp * 1000))}.`);
  }
  if (p.nbf !== undefined && p.nbf > now) {
    add('warn', `Not valid yet (nbf ${relative(new Date(p.nbf * 1000))}).`, `Todavía no es válido (nbf ${relative(new Date(p.nbf * 1000))}).`);
  }
  if (p.iat !== undefined && p.iat > now + 300) {
    add('warn', 'iat is in the future: check the issuer clock.', 'iat está en el futuro: revisá el reloj del emisor.');
  }
  if (p.exp !== undefined && p.iat !== undefined) {
    const life = p.exp - p.iat;
    if (life <= 0) add('bad', 'exp is before iat.', 'exp es anterior a iat.');
    else if (life > 86400) {
      const hours = Math.round(life / 3600);
      add('warn', `Lifetime of ${hours} h. Access tokens are usually minutes to a few hours.`, `Vida útil de ${hours} h. Los access tokens suelen durar de minutos a pocas horas.`);
    }
  }

  const iss = String(p.iss || '');
  if (/sts\.windows\.net/i.test(iss)) {
    add('info', 'Entra ID v1.0 token (issuer sts.windows.net).', 'Token de Entra ID v1.0 (emisor sts.windows.net).');
  } else if (/login\.microsoftonline\.com\/[^/]+\/v2\.0/i.test(iss)) {
    add('info', 'Entra ID v2.0 token (issuer login.microsoftonline.com/…/v2.0).', 'Token de Entra ID v2.0 (emisor login.microsoftonline.com/…/v2.0).');
  }
  const auds = [].concat(p.aud || []);
  if (auds.some((a) => GRAPH_AUD.includes(a)) || h.nonce) {
    add('info', 'Microsoft Graph token: it is meant for Graph only. Its signature cannot be validated by your API (the header carries a nonce), and that is expected.', 'Token para Microsoft Graph: es solo para Graph. Tu API no puede validar su firma (el header lleva un nonce), y es lo esperado.');
  }
  if (p.hasgroups || (p._claim_names && p._claim_names.groups)) {
    add('info', 'Group overage: the user has too many groups to fit in the token. Query Graph for the full list.', 'Overage de grupos: el usuario tiene demasiados grupos para el token. Consultá Graph para obtener la lista completa.');
  }
  if (h.typ && /^at\+jwt$/i.test(h.typ)) {
    add('info', 'typ at+jwt: OAuth 2.0 access token profile (RFC 9068).', 'typ at+jwt: perfil de access token OAuth 2.0 (RFC 9068).');
  }
  return out;
}

function statusBadge(p) {
  if (!p) return '';
  const now = Date.now() / 1000;
  if (p.exp !== undefined && p.exp < now) return `<span class="badge bad"><i class="fas fa-clock"></i> ${tr('Expired', 'Vencido')}</span>`;
  if (p.nbf !== undefined && p.nbf > now) return `<span class="badge warn"><i class="fas fa-hourglass-start"></i> ${tr('Not yet valid', 'Aún no válido')}</span>`;
  if (p.exp === undefined) return `<span class="badge warn"><i class="fas fa-infinity"></i> ${tr('No expiry', 'Sin vencimiento')}</span>`;
  return `<span class="badge ok"><i class="fas fa-check"></i> ${tr('Within validity window', 'Dentro de la vigencia')}</span>`;
}

function claimRows(p) {
  return Object.entries(p)
    .map(([k, v]) => {
      const info = CLAIMS[k];
      const label = info ? `<small>${esc(tr(info[0], info[1]))}</small>` : '';
      let value;
      if (TIME_CLAIMS.includes(k) && typeof v === 'number') {
        const d = new Date(v * 1000);
        value = `${esc(fmtDate(d))}<small>${esc(v)} · ${esc(fmtLocal(d))} · ${esc(relative(d))}</small>`;
      } else if (typeof v === 'object' && v !== null) {
        value = Array.isArray(v) && v.every((x) => typeof x !== 'object') ? esc(v.join(', ')) : esc(JSON.stringify(v));
      } else {
        value = esc(v);
      }
      return `<tr><th><code>${esc(k)}</code>${label}</th><td>${value}</td></tr>`;
    })
    .join('');
}

const ICON = { bad: 'fa-circle-xmark', warn: 'fa-triangle-exclamation', info: 'fa-circle-info', ok: 'fa-circle-check' };

function render() {
  verifyOut.innerHTML = '';
  try {
    parsed = parse(tokenEl.value);
  } catch (e) {
    parsed = null;
    resultEl.innerHTML = `<div class="error">${esc(e.message)}</div>`;
    return;
  }
  if (!parsed) {
    resultEl.innerHTML = `<p class="empty">${tr('Paste a token to decode it.', 'Pegá un token para decodificarlo.')}</p>`;
    return;
  }
  const { header: h, payload: p } = parsed;
  const badges = [
    `<span class="badge"><i class="fas fa-signature"></i> ${esc(h.alg || 'none')}</span>`,
    h.typ ? `<span class="badge">typ ${esc(h.typ)}</span>` : '',
    h.kid ? `<span class="badge">kid ${esc(h.kid)}</span>` : '',
    parsed.jwe ? `<span class="badge warn"><i class="fas fa-lock"></i> JWE</span>` : statusBadge(p),
  ].join('');

  const list = parsed.jwe
    ? [{ level: 'info', text: tr('Encrypted token (JWE): only the header is readable without the recipient private key.', 'Token cifrado (JWE): sin la clave privada del destinatario solo se puede leer el header.') }]
    : notes(h, p);

  let html = `<div class="badges">${badges}</div>`;
  if (list.length) {
    html += `<ul class="notes">${list.map((n) => `<li class="${n.level}"><i class="fas ${ICON[n.level]}"></i><span>${esc(n.text)}</span></li>`).join('')}</ul>`;
  }
  if (p && typeof p === 'object') {
    html += `<h3 class="sub">Claims</h3><table class="kv">${claimRows(p)}</table>`;
  }
  html += `<h3 class="sub">Header</h3><pre class="code">${jsonHtml(h)}</pre>`;
  if (!parsed.jwe) {
    html += `<h3 class="sub">Payload</h3><pre class="code">${p ? jsonHtml(p) : esc(parsed.payloadText)}</pre>`;
    html += `<h3 class="sub">${tr('Signature', 'Firma')}</h3><pre class="code">${esc(parsed.parts[2] || tr('(empty)', '(vacía)'))}</pre>`;
  }
  resultEl.innerHTML = html;
}

// ── Signature verification (Web Crypto) ──────────────────

const HASH = { 256: 'SHA-256', 384: 'SHA-384', 512: 'SHA-512' };

function algParams(alg) {
  const bits = alg.slice(2);
  const hash = HASH[bits];
  switch (alg.slice(0, 2)) {
    case 'HS': return hash && { kind: 'hmac', imp: { name: 'HMAC', hash }, ver: { name: 'HMAC' } };
    case 'RS': return hash && { kind: 'pub', imp: { name: 'RSASSA-PKCS1-v1_5', hash }, ver: { name: 'RSASSA-PKCS1-v1_5' } };
    case 'PS': return hash && { kind: 'pub', imp: { name: 'RSA-PSS', hash }, ver: { name: 'RSA-PSS', saltLength: Number(bits) / 8 } };
    case 'ES': {
      const curve = { 256: 'P-256', 384: 'P-384', 512: 'P-521' }[bits];
      return curve && { kind: 'pub', imp: { name: 'ECDSA', namedCurve: curve }, ver: { name: 'ECDSA', hash } };
    }
    default:
      if (alg === 'EdDSA' || alg === 'Ed25519') return { kind: 'pub', imp: { name: 'Ed25519' }, ver: { name: 'Ed25519' } };
      return null;
  }
}

function publicJwk(jwk) {
  const keep = ['kty', 'n', 'e', 'crv', 'x', 'y'];
  return Object.fromEntries(Object.entries(jwk).filter(([k]) => keep.includes(k)));
}

/** Returns [{ label, key }] candidates for the given algorithm. */
async function loadKeys(input, alg, params, header) {
  const text = input.trim();
  if (!text) throw new Error(tr('Enter a secret or key first.', 'Primero ingresá un secreto o una clave.'));
  const usage = ['verify'];

  if (params.kind === 'hmac') {
    const raw = $('secretB64').checked ? b64ToBytes(text) : new TextEncoder().encode(input);
    return [{ label: tr('secret', 'secreto'), key: await crypto.subtle.importKey('raw', raw, params.imp, false, usage) }];
  }

  if (text.startsWith('{')) {
    const json = JSON.parse(text);
    let jwks = Array.isArray(json.keys) ? json.keys : [json];
    if (header.kid && jwks.length > 1) {
      const match = jwks.filter((k) => k.kid === header.kid);
      if (!match.length) throw new Error(tr(`No key with kid "${header.kid}" in the JWKS.`, `No hay ninguna clave con kid "${header.kid}" en el JWKS.`));
      jwks = match;
    }
    const out = [];
    for (const jwk of jwks) {
      try {
        out.push({ label: jwk.kid ? `kid ${jwk.kid}` : 'JWK', key: await crypto.subtle.importKey('jwk', publicJwk(jwk), params.imp, false, usage) });
      } catch {
        /* key of another type: skip */
      }
    }
    if (!out.length) throw new Error(tr(`No key in the JWK/JWKS fits ${alg}.`, `Ninguna clave del JWK/JWKS sirve para ${alg}.`));
    return out;
  }

  let spki = pemToDer(text, 'PUBLIC KEY');
  let label = 'PEM';
  if (!spki) {
    let cert = pemToDer(text, 'CERTIFICATE');
    if (!cert && /^MII[A-Za-z0-9+/=\s]+$/.test(text)) cert = b64ToBytes(text); // bare x5c value
    if (cert) {
      spki = certToSpki(cert);
      label = tr('certificate', 'certificado');
    }
  }
  if (!spki) {
    if (/BEGIN RSA PUBLIC KEY/.test(text)) throw new Error(tr('PKCS#1 "RSA PUBLIC KEY" is not supported; use the "PUBLIC KEY" (SPKI) form or the certificate.', 'El formato PKCS#1 "RSA PUBLIC KEY" no está soportado; usá "PUBLIC KEY" (SPKI) o el certificado.'));
    throw new Error(tr('Unrecognised key format.', 'No se reconoce el formato de la clave.'));
  }
  return [{ label, key: await crypto.subtle.importKey('spki', spki, params.imp, false, usage) }];
}

async function verify() {
  verifyOut.innerHTML = '';
  if (!parsed || parsed.jwe) return;
  const alg = String(parsed.header.alg || '');
  const show = (cls, icon, text) =>
    (verifyOut.innerHTML = `<span class="badge ${cls}"><i class="fas ${icon}"></i> ${esc(text)}</span>`);
  const params = algParams(alg);
  if (!params) return show('bad', 'fa-circle-xmark', tr(`Algorithm "${alg || 'none'}" cannot be verified.`, `El algoritmo "${alg || 'none'}" no se puede verificar.`));
  try {
    const keys = await loadKeys(keyEl.value, alg, params, parsed.header);
    const data = new TextEncoder().encode(`${parsed.parts[0]}.${parsed.parts[1]}`);
    const sig = b64ToBytes(parsed.parts[2]);
    for (const { label, key } of keys) {
      if (await crypto.subtle.verify(params.ver, key, sig, data)) {
        return show('ok', 'fa-circle-check', tr(`Signature valid (${label})`, `Firma válida (${label})`));
      }
    }
    show('bad', 'fa-circle-xmark', tr('Invalid signature for this key', 'Firma inválida para esta clave'));
  } catch (e) {
    show('bad', 'fa-circle-xmark', e.message || String(e));
  }
}

onInput(tokenEl, render);
$('verify').addEventListener('click', verify);
$('sample').addEventListener('click', () => {
  tokenEl.value = SAMPLE;
  keyEl.value = SAMPLE_SECRET;
  $('secretB64').checked = false;
  render();
});
$('clear').addEventListener('click', () => {
  tokenEl.value = '';
  keyEl.value = '';
  render();
  tokenEl.focus();
});
document.addEventListener('langchange', render);
