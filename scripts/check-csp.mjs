// CI guard: fail the build if anything weakens the content-security rules.
import fs from 'node:fs';
import path from 'node:path';

const fail = (m) => { console.error(`✗ ${m}`); process.exitCode = 1; };
const html = fs.readFileSync('dist/index.html', 'utf8');

const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html);
if (!meta) fail('CSP meta tag missing');
else {
  const csp = meta[1];
  for (const bad of ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", 'data: blob: *', ' *;']) if (csp.includes(bad)) fail(`CSP contains ${bad}`);
  for (const need of ["script-src 'self'", "require-trusted-types-for 'script'", "object-src 'none'", "base-uri 'none'"]) if (!csp.includes(need)) fail(`CSP missing ${need}`);
}
for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
  if (m[2].trim()) fail('inline <script> body found in index.html');
  if (!/\bsrc=/.test(m[1])) fail('<script> without src found');
}
if (/\son[a-z]+\s*=/i.test(html)) fail('inline event handler attribute found in index.html');
if (/\sstyle\s*=/i.test(html)) fail('inline style attribute found in index.html');

// Our own source must not use string-to-code sinks or inline handlers.
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
for (const f of walk('src').filter((x) => x.endsWith('.js'))) {
  const src = fs.readFileSync(f, 'utf8');
  if (/\beval\s*\(|new Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`]/.test(src)) fail(`${f}: dynamic code execution`);
  if (/\.innerHTML\s*=/.test(src) && !f.endsWith(path.join('ui', 'sanitize.js'))) fail(`${f}: innerHTML outside the sanitizer`);
  if (/\.outerHTML\s*=|insertAdjacentHTML|document\.write/.test(src)) fail(`${f}: raw HTML sink`);
  if (/setAttribute\(\s*['"]on/.test(src)) fail(`${f}: inline handler via setAttribute`);
}
if (!process.exitCode) console.log('✓ CSP and DOM-sink checks passed');
