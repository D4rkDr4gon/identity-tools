/**
 * Just enough DER to pull the SubjectPublicKeyInfo out of an X.509
 * certificate so Web Crypto can import it as 'spki'.
 */

function tlv(bytes, pos) {
  const tag = bytes[pos];
  let len = bytes[pos + 1];
  let head = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('Unsupported DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | bytes[pos + 2 + i];
    head += n;
  }
  const end = pos + head + len;
  if (end > bytes.length) throw new Error('Truncated DER');
  return { tag, start: pos, body: pos + head, end };
}

function children(bytes, node) {
  const out = [];
  for (let p = node.body; p < node.end; ) {
    const c = tlv(bytes, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

/** DER certificate → DER SubjectPublicKeyInfo. */
export function certToSpki(der) {
  const cert = tlv(der, 0);
  const [tbs] = children(der, cert);
  const fields = children(der, tbs);
  // tbsCertificate: [0] version (optional), serial, signature, issuer, validity, subject, spki
  const idx = fields[0].tag === 0xa0 ? 6 : 5;
  const spki = fields[idx];
  if (!spki || spki.tag !== 0x30) throw new Error('SubjectPublicKeyInfo not found');
  return der.slice(spki.start, spki.end);
}

/** PEM (any label) → DER bytes of the first block with that label. */
export function pemToDer(pem, label) {
  const re = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`);
  const m = pem.match(re);
  if (!m) return null;
  const bin = atob(m[1].replace(/\s+/g, ''));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
