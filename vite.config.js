import fs from 'node:fs';
import path from 'node:path';
import { defineConfig, loadEnv } from 'vite';

// Strict Content-Security-Policy, generated from the build config so the app
// can only reach its own relay and tile server. Injected only into production
// builds (Vite's dev server needs inline styles for hot reload).
function csp(env) {
  const relay = new URL((env.VITE_RELAY_URL || 'wss://wekonet-relay.onrender.com/ws').replace(/^ws/, 'http'));
  const relayOrigin = `${relay.protocol === 'https:' ? 'wss' : 'ws'}://${relay.host}`;
  const tiles = new URL((env.VITE_TILE_URL || 'https://tile.openstreetmap.org/{z}/{x}/{y}.png').replace(/\{[a-z]\}/g, '0'));
  return [
    "default-src 'none'",
    "script-src 'self'",                 // no 'unsafe-inline', no 'unsafe-eval', no CDNs
    "style-src 'self'",                  // no inline <style> or style="" attributes
    `img-src 'self' data: blob: ${tiles.origin}`,
    "font-src 'self'",
    `connect-src 'self' ${relayOrigin}`,
    "media-src 'self' blob: mediastream:",
    "worker-src 'self'",
    "manifest-src 'self'",
    "object-src 'none'",
    "frame-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types wekonet default dompurify",
    'upgrade-insecure-requests',
  ].join('; ');
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_');
  const policy = csp(env);
  return {
    base: './',
    build: {
      target: 'es2022',
      outDir: 'dist',
      sourcemap: false,
      modulePreload: { polyfill: false }, // the polyfill is an inline-ish shim we don't need
      assetsInlineLimit: 0,               // never inline assets as data: scripts
    },
    worker: { format: 'es' },
    plugins: [{
      name: 'wekonet-csp',
      apply: 'build',
      transformIndexHtml(html) {
        return html.replace('<!--CSP-->', `<meta http-equiv="Content-Security-Policy" content="${policy}">`);
      },
      generateBundle() {
        // Same policy as real HTTP headers for static hosting (Netlify / Cloudflare Pages).
        this.emitFile({
          type: 'asset', fileName: '_headers',
          source: `/*\n  Content-Security-Policy: ${policy}; frame-ancestors 'none'\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n  Cross-Origin-Opener-Policy: same-origin\n  Cross-Origin-Resource-Policy: same-origin\n  Permissions-Policy: camera=(self), microphone=(self), geolocation=(self), payment=(), usb=()\n  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n`,
        });
        this.emitFile({ type: 'asset', fileName: 'csp.txt', source: policy });
      },
      // Beacon links open https://<domain>/b/#… — serve the same app there with
      // asset paths one level up, so any static host works without rewrite rules.
      closeBundle() {
        const out = path.resolve(process.cwd(), 'dist');
        const html = fs.readFileSync(path.join(out, 'index.html'), 'utf8').replace(/(href|src)="\.\//g, '$1="../');
        fs.mkdirSync(path.join(out, 'b'), { recursive: true });
        fs.writeFileSync(path.join(out, 'b', 'index.html'), html);
      },
    }],
  };
});
