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

// ── X.509 fields (enough for certificates embedded in SAML metadata) ──

const OID_NAMES = {
  '2.5.4.3': 'CN', '2.5.4.5': 'serialNumber', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
  '2.5.4.10': 'O', '2.5.4.11': 'OU', '1.2.840.113549.1.9.1': 'E', '0.9.2342.19200300.100.1.25': 'DC',
  '1.2.840.113549.1.1.1': 'RSA', '1.2.840.10045.2.1': 'EC', '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
  '1.2.840.113549.1.1.4': 'md5WithRSA', '1.2.840.113549.1.1.5': 'sha1WithRSA',
  '1.2.840.113549.1.1.11': 'sha256WithRSA', '1.2.840.113549.1.1.12': 'sha384WithRSA',
  '1.2.840.113549.1.1.13': 'sha512WithRSA', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.4.1': 'ecdsaWithSHA1', '1.2.840.10045.4.3.2': 'ecdsaWithSHA256',
  '1.2.840.10045.4.3.3': 'ecdsaWithSHA384', '1.2.840.10045.4.3.4': 'ecdsaWithSHA512',
  '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521',
};

function oid(der, n) {
  const b = der.subarray(n.body, n.end);
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  const s = parts.join('.');
  return OID_NAMES[s] || s;
}

function str(der, n) {
  const b = der.subarray(n.body, n.end);
  if (n.tag === 0x1e) return new TextDecoder('utf-16be').decode(b); // BMPString
  if (n.tag === 0x14) return new TextDecoder('latin1').decode(b); // T61String
  return new TextDecoder().decode(b); // UTF8, Printable, IA5…
}

function time(der, n) {
  const s = str(der, n);
  const yl = n.tag === 0x17 ? 2 : 4; // UTCTime YY, GeneralizedTime YYYY
  const m = s.match(new RegExp(`^(\\d{${yl}})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?`));
  if (!m) return null;
  let y = Number(m[1]);
  if (n.tag === 0x17) y += y < 50 ? 2000 : 1900; // UTCTime
  return new Date(Date.UTC(y, m[2] - 1, m[3], m[4], m[5], m[6] || 0));
}

/** RFC 4514 order (most specific first): "CN=…, O=…, C=…". */
function name(der, n) {
  return children(der, n)
    .flatMap((rdn) => children(der, rdn))
    .map((atv) => {
      const [t, v] = children(der, atv);
      return `${oid(der, t)}=${str(der, v)}`;
    })
    .reverse()
    .join(', ');
}

function keyInfo(der, spki) {
  const [alg, bits] = children(der, spki);
  const [algOid, params] = children(der, alg);
  const type = oid(der, algOid);
  if (type === 'RSA') {
    const seq = tlv(der, bits.body + 1); // skip the "unused bits" byte
    const mod = children(der, seq)[0];
    let i = mod.body;
    while (der[i] === 0 && i < mod.end) i++;
    const size = (mod.end - i) * 8 - Math.clz32(der[i]) + 24;
    return { type, size, label: `RSA ${size}` };
  }
  if (type === 'EC') {
    const curve = params && params.tag === 0x06 ? oid(der, params) : '';
    return { type, curve, label: `EC ${curve}`.trim() };
  }
  return { type, label: type };
}

/** DER certificate → { subject, issuer, serial, notBefore, notAfter, sigAlg, key, selfIssued } */
export function parseCert(der) {
  const cert = tlv(der, 0);
  const [tbs, sigAlg] = children(der, cert);
  const f = children(der, tbs);
  const k = f[0].tag === 0xa0 ? 1 : 0;
  const serialBytes = der.subarray(f[k].body, f[k].end);
  const [nb, na] = children(der, f[k + 3]);
  const subject = name(der, f[k + 4]);
  const issuer = name(der, f[k + 2]);
  return {
    version: k ? der[children(der, f[0])[0].body] + 1 : 1,
    serial: [...serialBytes].map((b) => b.toString(16).padStart(2, '0')).join('').replace(/^00(?=.)/, '').toUpperCase(),
    sigAlg: oid(der, children(der, sigAlg)[0]),
    issuer,
    subject,
    selfIssued: issuer === subject,
    notBefore: time(der, nb),
    notAfter: time(der, na),
    key: keyInfo(der, f[k + 5]),
  };
}
