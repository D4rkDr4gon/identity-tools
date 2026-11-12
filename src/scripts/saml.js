import { initPage, esc, b64ToBytes, bytesToUtf8, bytesToB64, fmtDate, fmtLocal, relative, onInput, notesHtml, tabs } from './common.js';
import { pretty, kids, kid, all, text, short } from './xml.js';
import { tr } from './i18n.js';

initPage({
  _title: 'Decodificador SAML — Identity Tools',
  h1: 'Decodificador SAML',
  lead: 'Pegá un SAMLRequest o SAMLResponse tal como viaja (binding POST o Redirect, o la URL completa) y leé lo que realmente se dicen el IdP y el SP.',
  'in.label': 'Mensaje SAML',
  'in.hint': 'Acepta base64 (binding POST), base64 + deflate (binding Redirect), valores URL-encoded, una URL completa o el body de un formulario con SAMLRequest / SAMLResponse, o XML plano.',
  'enc.post': 'Codificar XML para POST',
  'enc.redirect': 'Codificar XML para Redirect',
  empty: 'Pegá un mensaje SAML para decodificarlo.',
  'about.h': 'Notas',
  'about.1': 'El binding HTTP-Redirect comprime el mensaje con DEFLATE crudo antes del base64 y el URL-encoding; el binding HTTP-POST solo lo pasa a base64. El decodificador detecta cuál recibió.',
  'about.2': 'Las firmas se informan (dónde están y qué algoritmos usan) pero no se validan criptográficamente: eso requiere canonicalización XML y el certificado del IdP, y le corresponde al SP.',
  'about.3': 'Un <code>EncryptedAssertion</code> solo se puede leer con la clave privada del SP, que nunca debería pegarse en una página web.',
  'about.4': 'Para revisar la configuración de un IdP o un SP (endpoints, certificados y su vencimiento) usá el <a href="/identity-tools/saml-metadata/"><strong>inspector de metadata SAML</strong></a>.',
});

const NS = {
  p: 'urn:oasis:names:tc:SAML:2.0:protocol',
  a: 'urn:oasis:names:tc:SAML:2.0:assertion',
  ds: 'http://www.w3.org/2000/09/xmldsig#',
};

const $ = (id) => document.getElementById(id);
const inputEl = $('input');
const resultEl = $('result');
const encOut = $('encOut');

let lastXml = '';
const renderTabs = tabs(resultEl);

// ── Decoding pipeline ────────────────────────────────────

async function pipe(bytes, stream) {
  const out = new Blob([bytes]).stream().pipeThrough(stream);
  return new Uint8Array(await new Response(out).arrayBuffer());
}

function looksLikeXml(bytes) {
  let i = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
  while (i < bytes.length && /\s/.test(String.fromCharCode(bytes[i]))) i++;
  return bytes[i] === 0x3c; // '<'
}

async function decode(raw) {
  const steps = [];
  const meta = {};
  let s = raw.trim();
  if (!s) return null;

  if (s.startsWith('<')) return { xml: s, steps: ['XML'], meta };

  const m = s.match(/(?:^|[?&\s])(SAMLRequest|SAMLResponse)=([^&#\s]+)/);
  if (m) {
    meta.param = m[1];
    const query = s.includes('?') ? s.slice(s.indexOf('?') + 1) : s;
    const qs = new URLSearchParams(query.split('#')[0]);
    if (qs.get('RelayState')) meta.relayState = qs.get('RelayState');
    if (qs.get('SigAlg')) meta.sigAlg = qs.get('SigAlg');
    if (qs.get('Signature')) meta.querySigned = true;
    if (/^https?:\/\//i.test(s)) meta.url = s.split('?')[0];
    s = decodeURIComponent(m[2]); // '+' stays '+': it is base64, not a space
    steps.push(tr(`${m[1]} parameter`, `parámetro ${m[1]}`));
  } else if (/%[0-9a-f]{2}/i.test(s)) {
    s = decodeURIComponent(s);
    steps.push('URL-decode');
  }

  let bytes;
  try {
    bytes = b64ToBytes(s);
  } catch {
    throw new Error(tr('Not valid base64, URL-encoded base64 or XML.', 'No es base64, base64 URL-encoded ni XML válido.'));
  }
  steps.push('base64');

  if (!looksLikeXml(bytes)) {
    let inflated = null;
    for (const fmt of ['deflate-raw', 'deflate']) {
      try {
        inflated = await pipe(bytes, new DecompressionStream(fmt));
        if (looksLikeXml(inflated)) {
          steps.push(fmt === 'deflate-raw' ? 'DEFLATE' : 'zlib');
          meta.redirect = true;
          break;
        }
      } catch {
        inflated = null;
      }
    }
    if (!inflated || !looksLikeXml(inflated)) {
      throw new Error(tr('Decoded base64 but the result is not XML, plain or compressed.', 'El base64 se decodificó pero el resultado no es XML, ni plano ni comprimido.'));
    }
    bytes = inflated;
  }
  return { xml: bytesToUtf8(bytes).replace(/^﻿/, ''), steps, meta };
}

// ── Reading the XML ──────────────────────────────────────

function when(iso) {
  const d = new Date(iso);
  if (!iso || Number.isNaN(d.getTime())) return { v: iso || '' };
  return { v: fmtDate(d), sub: `${fmtLocal(d)} · ${relative(d)}`, raw: iso };
}

function uri(value) {
  return value ? { v: short(value), sub: value } : null;
}

function analyse(doc, meta) {
  const root = doc.documentElement;
  const type = root.localName;
  const rows = [];
  const notes = [];
  const add = (label, val) => {
    if (val === null || val === undefined || val === '') return;
    rows.push([label, typeof val === 'object' ? val : { v: String(val) }]);
  };
  const note = (level, en, es) => notes.push({ level, text: tr(en, es) });

  add(tr('Message', 'Mensaje'), { v: type, sub: root.namespaceURI });
  add('ID', root.getAttribute('ID'));
  add('IssueInstant', root.getAttribute('IssueInstant') && when(root.getAttribute('IssueInstant')));
  add('Destination', root.getAttribute('Destination'));
  add('InResponseTo', root.getAttribute('InResponseTo'));
  add('Issuer', text(kid(root, NS.a, 'Issuer')));
  if (meta.url) add(tr('Endpoint', 'Endpoint'), meta.url);
  if (meta.relayState) add('RelayState', meta.relayState);

  if (root.namespaceURI !== NS.p && type !== 'Assertion') {
    note('warn', 'This is not a SAML 2.0 protocol message; only the XML view is reliable.', 'No es un mensaje de protocolo SAML 2.0; solo la vista XML es confiable.');
  }

  if (type === 'AuthnRequest') {
    add('AssertionConsumerServiceURL', root.getAttribute('AssertionConsumerServiceURL'));
    add('ProtocolBinding', uri(root.getAttribute('ProtocolBinding')));
    add('ForceAuthn', root.getAttribute('ForceAuthn'));
    add('IsPassive', root.getAttribute('IsPassive'));
    const pol = kid(root, NS.p, 'NameIDPolicy');
    if (pol) add('NameIDPolicy', { v: short(pol.getAttribute('Format')) || '—', sub: [pol.getAttribute('Format'), pol.getAttribute('AllowCreate') && `AllowCreate=${pol.getAttribute('AllowCreate')}`].filter(Boolean).join(' · ') });
    const rac = kid(root, NS.p, 'RequestedAuthnContext');
    if (rac) add('RequestedAuthnContext', { v: all(rac, NS.a, 'AuthnContextClassRef').map((c) => short(text(c))).join(', '), sub: `Comparison=${rac.getAttribute('Comparison') || 'exact'}` });
  }

  if (type === 'LogoutRequest') {
    const nid = kid(root, NS.a, 'NameID');
    if (nid) add('NameID', { v: text(nid), sub: nid.getAttribute('Format') });
    add('SessionIndex', kids(root, NS.p, 'SessionIndex').map(text).join(', '));
    add('Reason', uri(root.getAttribute('Reason')));
  }

  const status = kid(root, NS.p, 'Status');
  if (status) {
    const code = kid(status, NS.p, 'StatusCode');
    const sub = kid(code, NS.p, 'StatusCode');
    const value = code && code.getAttribute('Value');
    add('Status', { v: [short(value), sub && short(sub.getAttribute('Value'))].filter(Boolean).join(' / '), sub: text(kid(status, NS.p, 'StatusMessage')) || value });
    if (value && short(value) !== 'Success') {
      note('bad', `Status is ${short(value)}${sub ? ` / ${short(sub.getAttribute('Value'))}` : ''}: the IdP did not authenticate the user.`, `El estado es ${short(value)}${sub ? ` / ${short(sub.getAttribute('Value'))}` : ''}: el IdP no autenticó al usuario.`);
    }
  }

  // Assertions
  const assertions = type === 'Assertion' ? [root] : kids(root, NS.a, 'Assertion');
  const encrypted = kids(root, NS.a, 'EncryptedAssertion');
  if (encrypted.length) {
    note('info', 'The assertion is encrypted (EncryptedAssertion): only the SP private key can open it.', 'La assertion está cifrada (EncryptedAssertion): solo la clave privada del SP puede abrirla.');
  }
  if (assertions.length > 1) {
    note('warn', `${assertions.length} assertions in one response. SPs should expect exactly one; extra ones are a classic signature-wrapping vector.`, `${assertions.length} assertions en una misma respuesta. El SP debería esperar exactamente una; las extra son un vector clásico de signature wrapping.`);
  }
  const now = Date.now();
  const attributes = [];

  assertions.forEach((as, i) => {
    const pre = assertions.length > 1 ? `#${i + 1} ` : '';
    if (as !== root) add(`${pre}Assertion Issuer`, text(kid(as, NS.a, 'Issuer')));
    const subject = kid(as, NS.a, 'Subject');
    const nid = kid(subject, NS.a, 'NameID');
    if (nid) add(`${pre}NameID`, { v: text(nid), sub: nid.getAttribute('Format') });
    const scd = all(subject, NS.a, 'SubjectConfirmationData')[0];
    if (scd) {
      add(`${pre}Recipient`, scd.getAttribute('Recipient'));
      if (scd.getAttribute('NotOnOrAfter')) add(`${pre}SubjectConfirmation NotOnOrAfter`, when(scd.getAttribute('NotOnOrAfter')));
    }
    const cond = kid(as, NS.a, 'Conditions');
    if (cond) {
      if (cond.getAttribute('NotBefore')) add(`${pre}NotBefore`, when(cond.getAttribute('NotBefore')));
      if (cond.getAttribute('NotOnOrAfter')) add(`${pre}NotOnOrAfter`, when(cond.getAttribute('NotOnOrAfter')));
      const audiences = all(cond, NS.a, 'Audience').map(text);
      add(`${pre}Audience`, audiences.join(', '));
      if (!audiences.length) note('warn', 'No AudienceRestriction: the assertion is not bound to a specific SP.', 'Sin AudienceRestriction: la assertion no está atada a un SP concreto.');
      const noa = Date.parse(cond.getAttribute('NotOnOrAfter'));
      if (noa && noa < now) note('warn', `Conditions expired ${relative(new Date(noa))} (expected if this message was captured earlier).`, `Las condiciones vencieron ${relative(new Date(noa))} (es esperable si el mensaje se capturó antes).`);
      const nb = Date.parse(cond.getAttribute('NotBefore'));
      if (nb && nb > now + 300000) note('warn', 'NotBefore is in the future: check clock skew between IdP and SP.', 'NotBefore está en el futuro: revisá la diferencia de reloj entre IdP y SP.');
    } else {
      note('warn', 'No Conditions element: no validity window or audience.', 'Sin elemento Conditions: no hay ventana de validez ni audiencia.');
    }
    const authn = kid(as, NS.a, 'AuthnStatement');
    if (authn) {
      if (authn.getAttribute('AuthnInstant')) add(`${pre}AuthnInstant`, when(authn.getAttribute('AuthnInstant')));
      add(`${pre}SessionIndex`, authn.getAttribute('SessionIndex'));
      add(`${pre}AuthnContext`, uri(text(all(authn, NS.a, 'AuthnContextClassRef')[0])));
    }
    all(as, NS.a, 'Attribute').forEach((at) =>
      attributes.push({
        name: at.getAttribute('Name'),
        friendly: at.getAttribute('FriendlyName'),
        format: at.getAttribute('NameFormat'),
        values: kids(at, NS.a, 'AttributeValue').map(text),
      }),
    );
  });

  // Signatures
  const signatures = all(doc, NS.ds, 'Signature').map((sig) => {
    const info = kid(sig, NS.ds, 'SignedInfo');
    const method = kid(info, NS.ds, 'SignatureMethod');
    const refs = kids(info, NS.ds, 'Reference');
    return {
      on: sig.parentElement ? sig.parentElement.localName : '?',
      method: method && method.getAttribute('Algorithm'),
      digests: refs.map((r) => kid(r, NS.ds, 'DigestMethod')?.getAttribute('Algorithm')).filter(Boolean),
      refs: refs.map((r) => r.getAttribute('URI')),
      cert: !!all(sig, NS.ds, 'X509Certificate').length,
    };
  });
  if (meta.sigAlg) signatures.push({ on: tr('query string', 'query string'), method: meta.sigAlg, digests: [], refs: [], cert: false });

  const weak = signatures.some((s) => /sha1$/i.test(s.method || '') || s.digests.some((d) => /sha1$/i.test(d)));
  if (weak) note('warn', 'SHA-1 in a signature or digest. Move the IdP and SP to SHA-256.', 'SHA-1 en una firma o digest. Conviene pasar el IdP y el SP a SHA-256.');

  if (!signatures.length) {
    if (type === 'Response' && !encrypted.length) note('bad', 'Neither the Response nor the Assertion is signed. An SP must reject it.', 'Ni la Response ni la Assertion están firmadas. El SP debe rechazarla.');
    else if (type === 'AuthnRequest') note('info', 'Unsigned AuthnRequest: common, and only a problem if the IdP requires signed requests.', 'AuthnRequest sin firma: es habitual y solo es un problema si el IdP exige requests firmados.');
    else if (type.startsWith('Logout')) note('warn', 'Unsigned logout message: most IdPs require logout messages to be signed.', 'Mensaje de logout sin firma: la mayoría de los IdP exigen que estén firmados.');
  } else if (type === 'Response' && assertions.length && !signatures.some((s) => s.on === 'Assertion')) {
    note('info', 'Only the Response envelope is signed, not the Assertion. Valid, but some SPs require a signed Assertion.', 'Solo está firmado el sobre de la Response, no la Assertion. Es válido, pero algunos SP exigen la Assertion firmada.');
  }

  if (!notes.some((n) => n.level === 'bad' || n.level === 'warn')) {
    note('ok', 'No obvious problems in structure, status, conditions or algorithms.', 'Sin problemas evidentes de estructura, estado, condiciones ni algoritmos.');
  }

  return { type, rows, notes, attributes, signatures };
}

// ── Rendering ────────────────────────────────────────────

function kvTable(rows) {
  return `<table class="kv">${rows
    .map(([k, { v, sub }]) => `<tr><th>${esc(k)}</th><td>${esc(v)}${sub && sub !== v ? `<small>${esc(sub)}</small>` : ''}</td></tr>`)
    .join('')}</table>`;
}

let seq = 0;

async function render() {
  encOut.innerHTML = '';
  const mine = ++seq;
  let decoded;
  try {
    decoded = await decode(inputEl.value);
    if (mine !== seq) return; // a newer input already rendered
  } catch (e) {
    if (mine !== seq) return;
    lastXml = '';
    resultEl.innerHTML = `<div class="error">${esc(e.message)}</div>`;
    return;
  }
  if (!decoded) {
    lastXml = '';
    resultEl.innerHTML = `<p class="empty">${tr('Paste a SAML message to decode it.', 'Pegá un mensaje SAML para decodificarlo.')}</p>`;
    return;
  }
  lastXml = decoded.xml;

  const doc = new DOMParser().parseFromString(decoded.xml, 'application/xml');
  const err = doc.getElementsByTagName('parsererror')[0];
  if (err) {
    resultEl.innerHTML = `<div class="error">${tr('Decoded, but the XML is not well-formed:', 'Se decodificó, pero el XML no está bien formado:')} ${esc(err.textContent.trim().split('\n')[0])}</div><h3 class="sub">${tr('Decoded text', 'Texto decodificado')}</h3><pre class="code">${esc(decoded.xml)}</pre>`;
    return;
  }

  const r = analyse(doc, decoded.meta);
  const badges = [
    `<span class="badge"><i class="fas fa-envelope-open-text"></i> ${esc(r.type)}</span>`,
    `<span class="badge">${esc(decoded.steps.join(' → '))}</span>`,
    decoded.meta.redirect ? `<span class="badge">HTTP-Redirect</span>` : decoded.steps.includes('base64') ? `<span class="badge">HTTP-POST</span>` : '',
  ].join('');

  const summary =
    notesHtml(r.notes) +
    `<h3 class="sub">${tr('Fields', 'Campos')}</h3>${kvTable(r.rows)}`;

  const attrs = r.attributes.length
    ? `<table class="kv">${r.attributes
        .map((a) => `<tr><th><code>${esc(short(a.name) === a.name ? a.name : short(a.name))}</code><small>${esc([a.friendly, a.name !== short(a.name) ? a.name : ''].filter(Boolean).join(' · '))}</small></th><td>${a.values.map(esc).join('<br />') || '—'}</td></tr>`)
        .join('')}</table>`
    : `<p class="empty">${tr('No attributes in this message.', 'Este mensaje no trae atributos.')}</p>`;

  const sigs = r.signatures.length
    ? `<table class="kv">${r.signatures
        .map((s) => `<tr><th>${tr('Signed element', 'Elemento firmado')}<small>${esc(s.on)}</small></th><td>${esc(short(s.method) || '—')}<small>${esc([s.method, ...s.digests.map((d) => `digest ${short(d)}`), ...s.refs.map((u) => `ref ${u || '""'}`), s.cert ? tr('includes X509Certificate', 'incluye X509Certificate') : ''].filter(Boolean).join(' · '))}</small></td></tr>`)
        .join('')}</table>`
    : `<p class="empty">${tr('No signatures.', 'Sin firmas.')}</p>`;

  const xml = `<div class="btn-row"><button class="btn" type="button" data-copy="#xmlPlain"><i class="fas fa-copy"></i> <span>${tr('Copy XML', 'Copiar XML')}</span></button></div>
    <textarea id="xmlPlain" hidden>${esc(pretty(doc.documentElement, 0, false))}</textarea>
    <pre class="code">${pretty(doc.documentElement)}</pre>`;

  resultEl.innerHTML =
    `<div class="badges">${badges}</div>` +
    renderTabs([
      { id: 'summary', label: tr('Summary', 'Resumen'), html: summary },
      { id: 'attributes', label: `${tr('Attributes', 'Atributos')} (${r.attributes.length})`, html: attrs },
      { id: 'signatures', label: `${tr('Signatures', 'Firmas')} (${r.signatures.length})`, html: sigs },
      { id: 'xml', label: 'XML', html: xml },
    ]);
}

// ── Encoding (XML → binding) ─────────────────────────────

async function encode(redirect) {
  const xml = lastXml || (inputEl.value.trim().startsWith('<') ? inputEl.value.trim() : '');
  if (!xml) {
    encOut.innerHTML = `<p class="hint">${tr('Paste or decode an XML message first.', 'Primero pegá o decodificá un mensaje XML.')}</p>`;
    return;
  }
  let bytes = new TextEncoder().encode(xml);
  if (redirect) bytes = await pipe(bytes, new CompressionStream('deflate-raw'));
  const b64 = bytesToB64(bytes);
  const value = redirect ? encodeURIComponent(b64) : b64;
  const label = redirect ? tr('Redirect binding (deflate + base64 + URL-encode)', 'Binding Redirect (deflate + base64 + URL-encode)') : tr('POST binding (base64)', 'Binding POST (base64)');
  encOut.innerHTML = `<h3 class="sub">${esc(label)}</h3><pre class="code" id="encValue">${esc(value)}</pre>
    <div class="btn-row"><button class="btn" type="button" data-copy="#encValue"><i class="fas fa-copy"></i> <span>${tr('Copy', 'Copiar')}</span></button></div>`;
}

// ── Sample ───────────────────────────────────────────────

const SAMPLE_XML = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp-7f3a" InResponseTo="_req-91c2" Version="2.0" IssueInstant="2026-11-04T13:00:05Z" Destination="https://app.example.com/saml/acs">
  <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_assert-4b1e" Version="2.0" IssueInstant="2026-11-04T13:00:05Z">
    <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_assert-4b1e">
          <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>c2FtcGxlLWRpZ2VzdC12YWx1ZS1ub3QtcmVhbA==</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>c2FtcGxlLXNpZ25hdHVyZS12YWx1ZS1ub3QtcmVhbA==</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">jane.doe@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="_req-91c2" Recipient="https://app.example.com/saml/acs" NotOnOrAfter="2026-11-04T13:05:05Z"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-11-04T12:59:05Z" NotOnOrAfter="2026-11-04T13:05:05Z">
      <saml:AudienceRestriction><saml:Audience>https://app.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-11-04T13:00:01Z" SessionIndex="_sess-22d0">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>jane.doe@example.com</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="givenName" FriendlyName="First name"><saml:AttributeValue>Jane</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="memberOf"><saml:AttributeValue>app-users</saml:AttributeValue><saml:AttributeValue>finance-readers</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

onInput(inputEl, render, 200);
$('encPost').addEventListener('click', () => encode(false));
$('encRedirect').addEventListener('click', () => encode(true));
$('sample').addEventListener('click', () => {
  inputEl.value = bytesToB64(new TextEncoder().encode(SAMPLE_XML));
  render();
});
$('clear').addEventListener('click', () => {
  inputEl.value = '';
  render();
  inputEl.focus();
});
document.addEventListener('langchange', render);
