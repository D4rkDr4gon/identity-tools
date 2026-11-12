import { defineConfig } from 'vite';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Served by GitHub Pages as a project site under the user site's custom domain.
const BASE = '/identity-tools/';
const SITE = `https://lcampassi.com${BASE}`;

// One directory per tool; '' is the hub.
const PAGES = ['', 'jwt', 'saml', 'saml-metadata', 'ldap', 'uac', 'filetime'];

// ── Plugin: HTML partial includes (<!-- @include: path -->) ──
function htmlInclude() {
  return {
    name: 'html-include',
    transformIndexHtml: {
      order: 'pre',
      handler(html) {
        return html.replace(/<!-- @include: (.+?) -->/g, (_m, file) =>
          readFileSync(resolve(__dirname, file.trim()), 'utf-8'),
        );
      },
    },
  };
}

// ── Plugin: Content-Security-Policy (build only) ──
// connect-src 'none' is the guarantee behind "nothing leaves your browser":
// the pages cannot send data anywhere even if a script tried to.
function csp() {
  return {
    name: 'csp',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler(html) {
        const hashes = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)]
          .filter(([tag]) => !tag.includes('application/ld+json'))
          .map(([, body]) => `'sha256-${createHash('sha256').update(body).digest('base64')}'`);
        const policy = [
          "default-src 'none'",
          `script-src 'self' ${hashes.join(' ')}`.trim(),
          "style-src 'self' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
          "font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com",
          "img-src 'self' data:",
          "connect-src 'none'",
          "base-uri 'none'",
          "form-action 'none'",
        ].join('; ');
        return html.replace(
          '<meta charset="UTF-8" />',
          `<meta charset="UTF-8" />\n  <meta http-equiv="Content-Security-Policy" content="${policy}" />`,
        );
      },
    },
  };
}

// ── Plugin: sitemap.xml ──
function sitemap() {
  return {
    name: 'sitemap',
    apply: 'build',
    generateBundle() {
      const today = new Date().toISOString().slice(0, 10);
      const urls = PAGES.map(
        (p) => `  <url>\n    <loc>${SITE}${p ? `${p}/` : ''}</loc>\n    <lastmod>${today}</lastmod>\n  </url>`,
      ).join('\n');
      this.emitFile({
        type: 'asset',
        fileName: 'sitemap.xml',
        source: `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`,
      });
    },
  };
}

export default defineConfig({
  base: BASE,
  plugins: [htmlInclude(), csp(), sitemap()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: Object.fromEntries(
        PAGES.map((p) => [p || 'index', resolve(__dirname, p, 'index.html')]),
      ),
    },
  },
});
