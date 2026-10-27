// Launches the PACKAGED desktop app (the real .exe / Linux binary) and checks
// it starts, creates an identity, renders the home screen and opens Settings
// without script errors. Usage: node scripts/smoke-electron.mjs <path to executable>
import { _electron as electron } from 'playwright';

const exe = process.argv[2];
const args = process.platform === 'linux' ? ['--no-sandbox'] : [];
const app = await electron.launch({ executablePath: exe, args, timeout: 60e3 });
const errors = [];
try {
  const win = await app.firstWindow({ timeout: 60e3 });
  win.on('pageerror', (e) => errors.push(`page error: ${e.message}`));
  win.on('console', (m) => { if (m.type() === 'error' && !/WebSocket|relay|tile\.openstreetmap/i.test(m.text())) errors.push(`console: ${m.text()}`); });
  await win.waitForSelector('#my-id', { timeout: 30e3 });
  await win.waitForFunction(() => /^WKN-/.test(document.querySelector('#my-id')?.textContent || ''), null, { timeout: 30e3 });
  const title = await win.title();
  if (!/WeKoNet/.test(title)) throw new Error(`unexpected window title "${title}"`);
  if (!(await win.isVisible('text=Create beacon'))) throw new Error('home screen did not render');
  if (!(await win.isVisible('text=WeKoNet — the Disposable Chat Software'))) throw new Error('slogan missing');
  await win.click('nav [data-nav="settings"]');
  await win.waitForSelector('text=App lock', { timeout: 10e3 });
  const csp = await win.evaluate(() => document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content || '');
  if (!csp.includes("script-src 'self'")) throw new Error('CSP missing in packaged app');
  if (errors.length) throw new Error(errors.join('\n'));
  console.log(`OK: ${exe} started, identity ${await win.textContent('#my-id')}, title "${title}"`);
} finally {
  await app.close().catch(() => {});
}
