import { initPage, esc, b64ToBytes, bytesToUtf8, fmtDate, fmtLocal, relative, onInput, notesHtml, tabs, copyBtn, toHex } from './common.js';
import { tr } from './i18n.js';
import { pretty, kids, kid, all, text, short } from './xml.js';
import { parseCert } from './der.js';
import { SAMPLE_IDP, SAMPLE_SP } from './saml-metadata-samples.js';

initPage({
  _title: 'Inspector de metadata SAML — Identity Tools',
  h1: 'Inspector de metadata SAML',
  lead: 'Pegá la metadata de un IdP o de un SP y revisá entityID, endpoints por binding, formatos de NameID, atributos y certificados, con su huella y su vencimiento.',
  'in.label': 'Metadata XML',
  'in.hint': 'EntityDescriptor o EntitiesDescriptor (federaciones), en XML o base64. Esta página no puede descargar la metadata desde una URL: abrila en otra pestaña y pegá el XML.',
  'sample.idp': 'IdP de ejemplo',
  'sample.sp': 'SP de ejemplo',
  'entity.label': 'Entidad',
  empty: 'Pegá metadata SAML para revisarla.',
  'about.h': 'Notas',
  'about.1': 'Las huellas SHA-1 y SHA-256 son las que piden la mayoría de las consolas (ADFS, Entra ID, One Identity, Okta) al configurar una relación de confianza, y sirven para confirmar por otro canal que el certificado es el correcto.',
  'about.2': 'En SAML, el certificado de la metadata es solo un contenedor de la clave pública: su emisor y su algoritmo de firma no importan, pero el vencimiento sí, porque muchos SP dejan de aceptar firmas con un certificado vencido.',
  'about.3': 'Para hacer un cambio de certificado sin corte, el IdP publica el nuevo junto al actual (dos <code>KeyDescriptor use="signing"</code>), los SP actualizan la metadata y recién después se firma con el nuevo.',
  'about.4': 'La firma de la metadata se informa pero no se valida. Para un mensaje SAML concreto usá el <a href="/identity-tools/saml/"><strong>decodificador SAML</strong></a>.',
});

const NS = {
  md: 'urn:oasis:names:tc:SAML:2.0:metadata',
  a: 'urn:oasis:names:tc:SAML:2.0:assertion',
  ds: 'http://www.w3.org/2000/09/xmldsig#',
  mdui: 'urn:oasis:names:tc:SAML:metadata:ui',
  xsi: 'http://www.w3.org/2001/XMLSchema-instance',
};
const SAML2 = 'urn:oasis:names:tc:SAML:2.0:protocol';
const DAY = 86400000;

const $ = (id) => document.getElementById(id);
const inputEl = $('input');
const resultEl = $('result');
const entityWrap = $('entityWrap');
const entitySel = $('entity');
const renderTabs = tabs(resultEl);

// ── Input ────────────────────────────────────────────────

function toXml(raw) {
  const s = raw.trim();
  if (!s) return null;
  if (s.startsWith('<')) return s;
  if (/^https?:\/\//i.test(s)) {
    const err = new Error(tr('This page cannot download metadata (network access is blocked). Open the URL, then paste the XML here:', 'Esta página no puede descargar la metadata (el acceso a la red está bloqueado). Abrí la URL y pegá el XML acá:'));
    err.url = s.split(/\s/)[0];
    throw err;
  }
  try {
    const xml = bytesToUtf8(b64ToBytes(s)).replace(/^﻿/, '').trim();
    if (xml.startsWith('<')) return xml;
  } catch {
    /* not base64 */
  }
  throw new Error(tr('Not XML or base64-encoded XML.', 'No es XML ni XML en base64.'));
}

// ── Certificates ─────────────────────────────────────────

async function readCert(b64) {
  const clean = b64.replace(/\s+/g, '');
  const der = b64ToBytes(clean);
  const [sha1, sha256] = await Promise.all(['SHA-1', 'SHA-256'].map((h) => crypto.subtle.digest(h, der)));
  let info;
  try {
    info = parseCert(der);
  } catch {
    info = null;
  }
  return {
    info,
    sha1: toHex(new Uint8Array(sha1)),
    sha256: toHex(new Uint8Array(sha256)),
    pem: `-----BEGIN CERTIFICATE-----\n${clean.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`,
  };
}

function certStatus(info) {
  if (!info?.notAfter) return null;
  const left = info.notAfter.getTime() - Date.now();
  if (info.notBefore && info.notBefore.getTime() > Date.now()) return 'future';
  if (left < 0) return 'expired';
  if (left < 30 * DAY) return 'soon';
  return 'ok';
}

// ── Analysis ─────────────────────────────────────────────

const ROLE_NAMES = {
  IDPSSODescriptor: 'IdP',
  SPSSODescriptor: 'SP',
  AttributeAuthorityDescriptor: 'Attribute Authority',
  AuthnAuthorityDescriptor: 'Authn Authority',
  PDPDescriptor: 'PDP',
};

const PROTOCOLS = {
  'urn:oasis:names:tc:SAML:2.0:protocol': 'SAML 2.0',
  'urn:oasis:names:tc:SAML:1.1:protocol': 'SAML 1.1',
  'urn:oasis:names:tc:SAML:1.0:protocol': 'SAML 1.0',
  'http://docs.oasis-open.org/wsfed/federation/200706': 'WS-Federation',
  'http://schemas.xmlsoap.org/ws/2005/02/trust': 'WS-Trust',
};
const protoName = (uri) => PROTOCOLS[uri] || uri;

function roleLabel(el) {
  if (el.localName === 'RoleDescriptor') {
    const t = el.getAttributeNS(NS.xsi, 'type') || el.getAttribute('xsi:type') || '';
    return `RoleDescriptor${t ? ` (${t})` : ''}`;
  }
  return ROLE_NAMES[el.localName] || el.localName;
}

function lang(els) {
  const want = document.documentElement.lang;
  const pick = els.find((e) => e.getAttribute('xml:lang') === want) || els.find((e) => e.getAttribute('xml:lang') === 'en') || els[0];
  return text(pick);
}

function sigInfo(el) {
  const sig = kid(el, NS.ds, 'Signature');
  if (!sig) return null;
  const info = kid(sig, NS.ds, 'SignedInfo');
  return {
    method: kid(info, NS.ds, 'SignatureMethod')?.getAttribute('Algorithm') || '',
    digests: all(info, NS.ds, 'DigestMethod').map((d) => d.getAttribute('Algorithm')),
  };
}

async function analyse(ent) {
  const notes = [];
  const note = (level, en, es) => notes.push({ level, text: tr(en, es) });
  const rows = [];
  const add = (k, v, sub) => v && rows.push([k, v, sub]);
  const now = Date.now();

  add('entityID', ent.getAttribute('entityID'));
  const roles = [...ent.children].filter((c) => c.namespaceURI === NS.md && /Descriptor$/.test(c.localName) && c.localName !== 'AffiliationDescriptor');
  add(tr('Roles', 'Roles'), roles.map(roleLabel).join(', ') || '—');
  const display = all(ent, NS.mdui, 'DisplayName');
  if (display.length) add(tr('Display name', 'Nombre visible'), lang(display));

  // validUntil / cacheDuration on the entity or any enclosing EntitiesDescriptor
  for (let el = ent; el && el.nodeType === 1; el = el.parentElement) {
    const vu = el.getAttribute('validUntil');
    if (vu) {
      const d = new Date(vu);
      add('validUntil', fmtDate(d), `${el === ent ? '' : `${el.localName} · `}${relative(d)}`);
      if (d.getTime() < now) note('bad', `The metadata expired (validUntil ${fmtDate(d)}). Many SPs and IdPs refuse expired metadata.`, `La metadata venció (validUntil ${fmtDate(d)}). Muchos SP e IdP rechazan metadata vencida.`);
      else if (d.getTime() - now < 7 * DAY) note('warn', `validUntil is ${relative(d)}: refresh it before it expires.`, `validUntil vence ${relative(d)}: conviene actualizarla antes.`);
    }
    if (el.getAttribute('cacheDuration')) add('cacheDuration', el.getAttribute('cacheDuration'));
  }

  // Metadata signature
  let sig = null;
  for (let el = ent; el && el.nodeType === 1 && !sig; el = el.parentElement) sig = sigInfo(el);
  if (sig) {
    add(tr('Metadata signature', 'Firma de la metadata'), short(sig.method), [sig.method, ...sig.digests.map((d) => `digest ${short(d)}`)].join(' · '));
    if ([sig.method, ...sig.digests].some((a) => /sha1$/i.test(a))) note('warn', 'The metadata is signed with SHA-1. Ask the publisher to move to SHA-256.', 'La metadata está firmada con SHA-1. Conviene pedirle al emisor que pase a SHA-256.');
  } else {
    add(tr('Metadata signature', 'Firma de la metadata'), tr('Not signed', 'Sin firma'));
    note('info', 'The metadata is not signed. That is normal when it is exchanged directly between the parties; federation aggregates should always be signed.', 'La metadata no está firmada. Es normal si se intercambia directamente entre las partes; los agregados de federaciones siempre deberían estarlo.');
  }

  const org = kid(ent, NS.md, 'Organization');
  if (org) add(tr('Organization', 'Organización'), lang(kids(org, NS.md, 'OrganizationDisplayName')) || lang(kids(org, NS.md, 'OrganizationName')), lang(kids(org, NS.md, 'OrganizationURL')));
  kids(ent, NS.md, 'ContactPerson').forEach((c) => {
    const who = [text(kid(c, NS.md, 'GivenName')), text(kid(c, NS.md, 'SurName'))].filter(Boolean).join(' ') || text(kid(c, NS.md, 'Company'));
    const mails = kids(c, NS.md, 'EmailAddress').map((m) => text(m).replace(/^mailto:/i, ''));
    add(`${tr('Contact', 'Contacto')} (${c.getAttribute('contactType') || '?'})`, who || mails[0] || '—', who ? mails.join(', ') : '');
  });

  if (!roles.length) note('bad', 'No role descriptor (IDPSSODescriptor, SPSSODescriptor…): there is nothing to configure from this metadata.', 'No hay ningún descriptor de rol (IDPSSODescriptor, SPSSODescriptor…): no hay nada para configurar con esta metadata.');

  const endpoints = [];
  const attributes = [];
  const keys = [];
  const roleRows = [];

  for (const role of roles) {
    const label = roleLabel(role);
    const proto = role.getAttribute('protocolSupportEnumeration') || '';
    const isIdp = role.localName === 'IDPSSODescriptor';
    const isSp = role.localName === 'SPSSODescriptor';
    const rr = [];
    const radd = (k, v, sub) => v && rr.push([k, v, sub]);

    radd('protocolSupportEnumeration', proto.split(/\s+/).filter(Boolean).map(protoName).join(', '), proto);
    if (role.localName === 'RoleDescriptor') note('info', `${label}: WS-Federation role, published by ADFS and Entra ID next to the SAML one. SAML SPs ignore it.`, `${label}: rol de WS-Federation que publican ADFS y Entra ID junto al de SAML. Los SP de SAML lo ignoran.`);
    else if ((isIdp || isSp) && !proto.split(/\s+/).includes(SAML2)) note('warn', `${label} does not list SAML 2.0 in protocolSupportEnumeration.`, `${label} no incluye SAML 2.0 en protocolSupportEnumeration.`);

    if (role.getAttribute('validUntil')) {
      const d = new Date(role.getAttribute('validUntil'));
      radd('validUntil', fmtDate(d), relative(d));
      if (d.getTime() < now) note('bad', `${label}: validUntil is in the past.`, `${label}: validUntil ya pasó.`);
    }

    if (isIdp) {
      const w = role.getAttribute('WantAuthnRequestsSigned');
      radd('WantAuthnRequestsSigned', w || 'false', w ? '' : tr('not set (false)', 'sin definir (false)'));
      if (w === 'true') note('info', 'The IdP wants signed AuthnRequests: the SP needs a signing certificate configured.', 'El IdP pide AuthnRequests firmados: el SP necesita un certificado de firma configurado.');
    }
    if (isSp) {
      const a = role.getAttribute('AuthnRequestsSigned');
      const w = role.getAttribute('WantAssertionsSigned');
      radd('AuthnRequestsSigned', a || 'false', a ? '' : tr('not set (false)', 'sin definir (false)'));
      radd('WantAssertionsSigned', w || 'false', w ? '' : tr('not set (false)', 'sin definir (false)'));
      if (w !== 'true') note('info', 'The SP does not declare WantAssertionsSigned="true". The IdP may sign only the Response; check that the SP validates it.', 'El SP no declara WantAssertionsSigned="true". El IdP puede firmar solo la Response; verificá que el SP la valide.');
    }
    const nameIds = kids(role, NS.md, 'NameIDFormat').map(text);
    radd('NameIDFormat', nameIds.map(short).join(', '), nameIds.join(' · '));

    // Endpoints
    for (const ep of [...role.children].filter((c) => c.namespaceURI === NS.md && c.hasAttribute('Binding') && c.hasAttribute('Location'))) {
      const binding = ep.getAttribute('Binding');
      const loc = ep.getAttribute('Location');
      endpoints.push({ role: label, service: ep.localName, binding, loc, index: ep.getAttribute('index'), isDefault: ep.getAttribute('isDefault'), resp: ep.getAttribute('ResponseLocation') });
      if (/^http:\/\//i.test(loc)) note('warn', `${ep.localName} uses plain http:// (${loc}). Assertions and session data travel unencrypted.`, `${ep.localName} usa http:// sin TLS (${loc}). Las assertions y los datos de sesión viajan sin cifrar.`);
      if (ep.localName === 'AssertionConsumerService' && /HTTP-Redirect$/.test(binding)) note('warn', 'An AssertionConsumerService uses HTTP-Redirect. The Web Browser SSO profile forbids it for responses (they do not fit in a URL).', 'Un AssertionConsumerService usa HTTP-Redirect. El perfil Web Browser SSO lo prohíbe para respuestas (no entran en una URL).');
    }
    if (isIdp && !kids(role, NS.md, 'SingleSignOnService').length) note('bad', 'The IdP has no SingleSignOnService endpoint.', 'El IdP no tiene endpoint SingleSignOnService.');
    if (isSp) {
      const acs = kids(role, NS.md, 'AssertionConsumerService');
      if (!acs.length) note('bad', 'The SP has no AssertionConsumerService: the IdP has nowhere to send responses.', 'El SP no tiene AssertionConsumerService: el IdP no tiene adónde mandar las respuestas.');
      if (acs.length > 1 && !acs.some((a) => a.getAttribute('isDefault') === 'true')) note('info', `${acs.length} AssertionConsumerService endpoints and none marked isDefault: IdPs use the lowest index, or the first one.`, `${acs.length} endpoints AssertionConsumerService y ninguno con isDefault: los IdP usan el de menor index, o el primero.`);
    }

    // Attributes offered (IdP) or requested (SP)
    kids(role, NS.a, 'Attribute').forEach((at) => attributes.push({ role: label, kind: tr('offered', 'ofrecido'), name: at.getAttribute('Name'), friendly: at.getAttribute('FriendlyName'), format: at.getAttribute('NameFormat') }));
    all(role, NS.md, 'RequestedAttribute').forEach((at) => attributes.push({ role: label, kind: at.getAttribute('isRequired') === 'true' ? tr('required', 'requerido') : tr('requested', 'pedido'), name: at.getAttribute('Name'), friendly: at.getAttribute('FriendlyName'), format: at.getAttribute('NameFormat') }));

    // Keys
    const kds = kids(role, NS.md, 'KeyDescriptor');
    const roleKeys = [];
    for (const kd of kds) {
      const use = kd.getAttribute('use') || '';
      const enc = kids(kd, NS.md, 'EncryptionMethod').map((e) => e.getAttribute('Algorithm'));
      const keyName = text(all(kd, NS.ds, 'KeyName')[0]);
      const certs = all(kd, NS.ds, 'X509Certificate').map(text).filter(Boolean);
      for (const c of certs.length ? certs : [null]) {
        let cert = null;
        let error = '';
        if (c) {
          try {
            cert = await readCert(c);
          } catch {
            error = tr('Could not decode the certificate (invalid base64).', 'No se pudo decodificar el certificado (base64 inválido).');
          }
        }
        roleKeys.push({ role: label, use, enc, keyName, cert, error });
      }
      if (enc.some((a) => /rsa-1_5$/i.test(a))) note('warn', 'EncryptionMethod rsa-1_5 is vulnerable to padding-oracle attacks. Prefer rsa-oaep.', 'EncryptionMethod rsa-1_5 es vulnerable a ataques de padding oracle. Conviene rsa-oaep.');
      if (enc.some((a) => /-cbc$/i.test(a))) note('info', 'AES-CBC data encryption is listed. AES-GCM (xmlenc11) is preferred where both sides support it.', 'Se lista cifrado de datos AES-CBC. Conviene AES-GCM (xmlenc11) donde ambas partes lo soporten.');
    }
    keys.push(...roleKeys);

    const signing = roleKeys.filter((k) => k.use !== 'encryption' && k.cert);
    if ((isIdp || role.localName === 'AttributeAuthorityDescriptor') && !signing.length) note('bad', `${label} has no signing certificate: nobody can validate its signatures.`, `${label} no tiene certificado de firma: nadie puede validar sus firmas.`);
    if (signing.length > 1) note('info', `${label} publishes ${signing.length} signing certificates: probably a rollover in progress. The other side should trust all of them until the old one is removed.`, `${label} publica ${signing.length} certificados de firma: probablemente un cambio de certificado en curso. La otra parte debería confiar en todos hasta que se quite el viejo.`);
    if (isSp && role.getAttribute('AuthnRequestsSigned') === 'true' && !signing.length) note('warn', 'AuthnRequestsSigned="true" but the SP publishes no signing certificate.', 'AuthnRequestsSigned="true" pero el SP no publica certificado de firma.');
    if (isSp && !roleKeys.some((k) => k.use !== 'signing' && k.cert)) note('info', 'The SP publishes no encryption certificate, so the IdP cannot encrypt assertions for it.', 'El SP no publica certificado de cifrado, así que el IdP no puede cifrarle las assertions.');

    for (const k of roleKeys) {
      if (!k.cert?.info) continue;
      const st = certStatus(k.cert.info);
      const who = `${label}${k.use ? ` (${k.use})` : ''}: ${k.cert.info.subject}`;
      if (st === 'expired') note('bad', `${who} expired ${relative(k.cert.info.notAfter)}.`, `${who} venció ${relative(k.cert.info.notAfter)}.`);
      else if (st === 'soon') note('warn', `${who} expires ${relative(k.cert.info.notAfter)}. Plan the rollover now.`, `${who} vence ${relative(k.cert.info.notAfter)}. Planificá el cambio ya.`);
      else if (st === 'future') note('info', `${who} is not valid yet (from ${fmtDate(k.cert.info.notBefore)}): typical of a certificate published ahead of a rollover.`, `${who} todavía no es válido (desde ${fmtDate(k.cert.info.notBefore)}): típico de un certificado publicado antes de un cambio.`);
      if (k.cert.info.key.type === 'RSA' && k.cert.info.key.size < 2048) note('warn', `${who} uses an RSA ${k.cert.info.key.size} key. Use 2048 bits or more.`, `${who} usa una clave RSA de ${k.cert.info.key.size} bits. Conviene 2048 o más.`);
    }

    roleRows.push({ label, rows: rr });
  }

  if (!notes.some((n) => n.level === 'bad' || n.level === 'warn')) {
    notes.unshift({ level: 'ok', text: tr('No problems found in endpoints, certificates or validity.', 'Sin problemas en endpoints, certificados ni vigencia.') });
  }
  return { rows, roleRows, notes, endpoints, attributes, keys };
}

// ── Rendering ────────────────────────────────────────────

function kvTable(rows) {
  return `<table class="kv">${rows
    .map(([k, v, sub]) => `<tr><th>${esc(k)}</th><td>${esc(v)}${sub && sub !== v ? `<small>${esc(sub)}</small>` : ''}</td></tr>`)
    .join('')}</table>`;
}

const STATUS_BADGE = {
  ok: ['ok', 'Valid', 'Vigente'],
  soon: ['warn', 'Expires soon', 'Vence pronto'],
  expired: ['bad', 'Expired', 'Vencido'],
  future: ['warn', 'Not valid yet', 'Todavía no vigente'],
};

function keyHtml(k, i) {
  const use = k.use || tr('signing + encryption', 'firma + cifrado');
  const head = `<h3 class="sub">${esc(k.role)} · ${esc(use)}</h3>`;
  if (k.error) return `${head}<div class="error">${esc(k.error)}</div>`;
  if (!k.cert) return `${head}<p class="hint">${esc(tr(`No X509Certificate${k.keyName ? `; KeyName ${k.keyName}` : ''}.`, `Sin X509Certificate${k.keyName ? `; KeyName ${k.keyName}` : ''}.`))}</p>`;
  const { info, sha1, sha256, pem } = k.cert;
  const rows = [];
  if (info) {
    rows.push(['Subject', info.subject], ['Issuer', info.selfIssued ? tr('Self-signed', 'Autofirmado') : info.issuer, info.selfIssued ? '' : '']);
    rows.push([tr('Valid from', 'Válido desde'), fmtDate(info.notBefore), `${fmtLocal(info.notBefore)} · ${relative(info.notBefore)}`]);
    rows.push([tr('Valid until', 'Válido hasta'), fmtDate(info.notAfter), `${fmtLocal(info.notAfter)} · ${relative(info.notAfter)}`]);
    rows.push([tr('Key', 'Clave'), info.key.label], [tr('Signature algorithm', 'Algoritmo de firma'), info.sigAlg], [tr('Serial number', 'Número de serie'), info.serial]);
  }
  rows.push([tr('SHA-1 thumbprint', 'Huella SHA-1'), sha1], [tr('SHA-256 thumbprint', 'Huella SHA-256'), sha256]);
  if (k.keyName) rows.push(['KeyName', k.keyName]);
  if (k.enc.length) rows.push(['EncryptionMethod', k.enc.map(short).join(', '), k.enc.join(' · ')]);
  const st = info && certStatus(info);
  const badge = st ? `<div class="badges"><span class="badge ${STATUS_BADGE[st][0]}">${esc(tr(STATUS_BADGE[st][1], STATUS_BADGE[st][2]))}</span></div>` : `<div class="error">${esc(tr('The certificate could not be parsed; thumbprints are still valid.', 'No se pudo interpretar el certificado; las huellas siguen siendo válidas.'))}</div>`;
  return `${head}${badge}${kvTable(rows)}
    <textarea id="pem${i}" hidden>${esc(pem)}</textarea>
    <textarea id="sha1${i}" hidden>${esc(sha1)}</textarea>
    <div class="btn-row">${copyBtn(`#pem${i}`, 'Copy PEM', 'Copiar PEM')}${copyBtn(`#sha1${i}`, 'Copy SHA-1', 'Copiar SHA-1')}</div>`;
}

let entities = [];
let doc = null;
let seq = 0;

async function renderEntity() {
  const mine = ++seq;
  const ent = entities[Number(entitySel.value)] || entities[0];
  if (!ent) return;
  const r = await analyse(ent);
  if (mine !== seq) return;

  const summary = `${notesHtml(r.notes)}<h3 class="sub">${tr('Entity', 'Entidad')}</h3>${kvTable(r.rows)}${r.roleRows
    .map((rr) => `<h3 class="sub">${esc(rr.label)}</h3>${rr.rows.length ? kvTable(rr.rows) : ''}`)
    .join('')}`;

  const eps = r.endpoints.length
    ? `<table class="kv">${r.endpoints
        .map((e) => `<tr><th>${esc(e.service)}<small>${esc([e.role, short(e.binding), e.index !== null && `index ${e.index}`, e.isDefault === 'true' && 'default'].filter(Boolean).join(' · '))}</small></th><td>${esc(e.loc)}${e.resp ? `<small>ResponseLocation ${esc(e.resp)}</small>` : ''}</td></tr>`)
        .join('')}</table>`
    : `<p class="empty">${tr('No endpoints.', 'Sin endpoints.')}</p>`;
  const attrs = r.attributes.length
    ? `<h3 class="sub">${tr('Attributes', 'Atributos')}</h3><table class="kv">${r.attributes
        .map((a) => `<tr><th><code>${esc(a.friendly || short(a.name))}</code><small>${esc(`${a.role} · ${a.kind}`)}</small></th><td>${esc(a.name)}${a.format ? `<small>${esc(short(a.format))}</small>` : ''}</td></tr>`)
        .join('')}</table>`
    : '';

  const keys = r.keys.length ? r.keys.map(keyHtml).join('') : `<p class="empty">${tr('No KeyDescriptor elements.', 'Sin elementos KeyDescriptor.')}</p>`;

  const xml = `<div class="btn-row">${copyBtn('#xmlPlain', 'Copy XML', 'Copiar XML')}</div>
    <textarea id="xmlPlain" hidden>${esc(pretty(ent, 0, false))}</textarea>
    <pre class="code">${pretty(ent)}</pre>`;

  resultEl.innerHTML = renderTabs([
    { id: 'summary', label: tr('Summary', 'Resumen'), html: summary },
    { id: 'endpoints', label: `${tr('Endpoints', 'Endpoints')} (${r.endpoints.length})`, html: eps + attrs },
    { id: 'certs', label: `${tr('Certificates', 'Certificados')} (${r.keys.filter((k) => k.cert).length})`, html: keys },
    { id: 'xml', label: 'XML', html: xml },
  ]);
}

function render() {
  entityWrap.hidden = true;
  entities = [];
  let xml;
  try {
    xml = toXml(inputEl.value);
  } catch (e) {
    seq++;
    resultEl.innerHTML = `<div class="error">${esc(e.message)}${e.url ? ` <a href="${esc(e.url)}" target="_blank" rel="noopener noreferrer">${esc(e.url)}</a>` : ''}</div>`;
    return;
  }
  if (!xml) {
    seq++;
    resultEl.innerHTML = `<p class="empty">${tr('Paste SAML metadata to inspect it.', 'Pegá metadata SAML para revisarla.')}</p>`;
    return;
  }
  doc = new DOMParser().parseFromString(xml, 'application/xml');
  const err = doc.getElementsByTagName('parsererror')[0];
  if (err) {
    seq++;
    resultEl.innerHTML = `<div class="error">${tr('The XML is not well-formed:', 'El XML no está bien formado:')} ${esc(err.textContent.trim().split('\n')[0])}</div>`;
    return;
  }
  const root = doc.documentElement;
  entities = root.namespaceURI === NS.md && root.localName === 'EntityDescriptor' ? [root] : all(root, NS.md, 'EntityDescriptor');
  if (!entities.length) {
    seq++;
    resultEl.innerHTML = `<div class="error">${esc(tr(`No SAML 2.0 EntityDescriptor found (root element: ${root.localName}).`, `No se encontró un EntityDescriptor de SAML 2.0 (elemento raíz: ${root.localName}).`))}</div>`;
    return;
  }
  entitySel.innerHTML = '';
  if (entities.length > 1) {
    entitySel.innerHTML = entities
      .map((e, i) => {
        const r = [...e.children].filter((c) => /SSODescriptor$/.test(c.localName)).map((c) => ROLE_NAMES[c.localName]).join('+');
        return `<option value="${i}">${esc(e.getAttribute('entityID') || `#${i + 1}`)}${r ? ` (${r})` : ''}</option>`;
      })
      .join('');
    entityWrap.hidden = false;
    $('entityCount').textContent = `${entities.length}`;
  }
  renderEntity();
}

onInput(inputEl, render, 250);
entitySel.addEventListener('change', renderEntity);
$('sampleIdp').addEventListener('click', () => {
  inputEl.value = SAMPLE_IDP;
  render();
});
$('sampleSp').addEventListener('click', () => {
  inputEl.value = SAMPLE_SP;
  render();
});
$('clear').addEventListener('click', () => {
  inputEl.value = '';
  render();
  inputEl.focus();
});
document.addEventListener('langchange', () => {
  if (entities.length) renderEntity();
  else render();
});
