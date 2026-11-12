# Identity Tools

Browser-based utilities for identity and access management work, published at
**https://lcampassi.com/identity-tools/**.

| Tool | Path | What it does |
|------|------|--------------|
| JWT decoder & verifier | `/jwt/` | Header, claims, validity window and warnings; signature check with an HMAC secret, PEM public key, certificate, JWK or JWKS (HS/RS/PS/ES/EdDSA via Web Crypto). Entra ID aware. |
| SAML decoder | `/saml/` | SAMLRequest / SAMLResponse from the POST or Redirect binding (base64, deflate, URL-encoded, full URL). Summary, attributes, signature algorithms, pretty XML; encodes XML back for either binding. |
| SAML metadata inspector | `/saml-metadata/` | IdP / SP metadata (or a federation aggregate): entityID, endpoints by binding, NameID formats, attributes, signing and encryption certificates with thumbprints and expiry, rollover and configuration warnings. |
| LDAP filter validator | `/ldap/` | RFC 4515 parser with error position, indented and one-line output, plain-language explanation (bitwise / IN_CHAIN rules, AD flags, FILETIME, SID/GUID), templates, value escaping, PowerShell and ldapsearch commands. |
| userAccountControl calculator | `/uac/` | Decode/build AD `userAccountControl`, flag the risky bits, generate the LDAP filter and PowerShell query. |
| AD timestamp converter | `/filetime/` | FILETIME ⇄ Generalized Time ⇄ Unix ⇄ ISO, AD intervals (`maxPwdAge`…), stale-account LDAP filters. |

## Privacy

Everything runs client-side. There is no backend and no analytics, and the
production build ships a Content-Security-Policy with `connect-src 'none'`,
so the pages cannot send what you paste anywhere.

## Development

```bash
npm install
npm run dev      # http://localhost:8081/identity-tools/
npm run build    # → dist/ (includes sitemap.xml and the CSP meta tag)
```

Vite 6, vanilla JS modules, no frameworks. Design tokens and theme toggle are
shared with [lcampassi.com](https://lcampassi.com) (same `theme` key in
localStorage, so the light/dark choice carries over). EN/ES switch via
`data-i18n` attributes; dictionaries live in each page's script.

Add a tool: create `<name>/index.html` + `src/scripts/<name>.js`, add `<name>`
to `PAGES` in `vite.config.js` and a card to `index.html`.

## Deploy

GitHub Pages project site of `D4rkDr4gon/identity-tools`, served under the
custom domain of the user site (`D4rkDr4gon.github.io` → `lcampassi.com`).
Push to `master` → `.github/workflows/deploy.yml` builds and deploys.
Settings → Pages → Source must be **GitHub Actions**.

## License

MIT
