// Real-browser hard tests: several people, a hostile relay, injection attempts,
// network failure. Runs Chromium with fake camera/mic/GPS.
//
//   Build first, with the relay at ws://127.0.0.1:8787/ws, then:
//     VITE_RELAY_URL=ws://127.0.0.1:8787/ws VITE_APP_BASE=http://127.0.0.1:5173/b/ VITE_ICE_SERVERS=[] npm run build
//     node tests/e2e/attack.e2e.mjs            (WEKONET_SITE=dist by default)
import { createRequire } from 'node:module';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { startRelay } from '../../server/relay.js';
import { Signaling } from '../../src/net/signaling.js';
import { openBeacon, parseShort, shortId, openShort, splitAction } from '../../src/crypto/beacon.js';
import { generateIdentity } from '../../src/crypto/identity.js';
import { respond } from '../../src/crypto/handshake.js';
import { setKemProvider } from '../../src/crypto/kex.js';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

const SITE = path.resolve(process.env.WEKONET_SITE || 'dist');
const SHOTS = process.env.WEKONET_SHOTS || null;
const ORIGIN = 'http://127.0.0.1:5173';
const RELAY_PORT = 8787;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Node-side attacker needs ML-KEM; real lib when installed, else the same test stand-in the site uses.
try { setKemProvider((await import('@noble/post-quantum/ml-kem.js')).ml_kem768); } catch {
  const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
  setKemProvider({
    keygen() { const sk = rnd(32); const pk = new Uint8Array(1184); pk.set(sk); return { publicKey: pk, secretKey: sk }; },
    encapsulate(pk) { const ss = rnd(32); const ct = new Uint8Array(1088); for (let i = 0; i < 32; i++) ct[i] = ss[i] ^ pk[i]; return { cipherText: ct, sharedSecret: ss }; },
    decapsulate(ct, sk) { const ss = new Uint8Array(32); for (let i = 0; i < 32; i++) ss[i] = ct[i] ^ sk[i]; return ss; },
  });
}

// ---------------- static site (serves /b/... like Caddy does) ----------------
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json' };
// Attack probe: runs as a real page script (Playwright's evaluate() bypasses CSP,
// so attacks must come from a script the page itself loads).
const PROBE = `(() => {
  const r = {};
  const t = (k, f) => { try { f(); r[k] = 'ALLOWED'; } catch (e) { r[k] = 'blocked'; } };
  { const d = document.createElement('div');
    try { d.innerHTML = '<img src=x onerror=window.__pwned=20><a href="javascript:alert(1)">x</a>'; } catch (e) { /* blocked outright */ }
    const live = [...d.querySelectorAll('*')].some((el) => [...el.attributes].some((at) => /^on/i.test(at.name) || /^\\s*javascript:/i.test(at.value)));
    r['innerHTML string'] = live ? 'ALLOWED' : 'blocked'; document.body.append(d); }
  t('eval', () => eval('window.__pwned=21'));
  t('new Function', () => new Function('window.__pwned=22')());
  t('setTimeout string', () => { setTimeout('window.__pwned=23'); if (window.__pwned) throw 0; });
  t('script.textContent', () => { const s = document.createElement('script'); s.textContent = 'window.__pwned=24'; document.head.append(s); });
  t('foreign script src', () => { const s = document.createElement('script'); s.src = 'https://evil.example/x.js'; document.head.append(s); });
  t('inline handler attribute', () => { const i = document.createElement('img'); i.setAttribute('onerror', 'window.__pwned=26'); i.src = 'data:,x'; document.body.append(i); });
  window.__probe = r;
})();`;
const web = http.createServer((req, res) => {
  if (req.url === '/__probe.js') { res.writeHead(200, { 'content-type': 'text/javascript' }); return res.end(PROBE); }
  let p = decodeURIComponent(new URL(req.url, ORIGIN).pathname).replace(/^\/b(\/|$)/, '/');
  if (p.endsWith('/')) p += 'index.html';
  const f = path.join(SITE, path.normalize(p));
  if (!f.startsWith(SITE) || !fs.existsSync(f)) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'content-type': TYPES[path.extname(f)] || 'application/octet-stream', 'cache-control': 'no-store' });
  fs.createReadStream(f).pipe(res);
});
await new Promise((r) => web.listen(5173, '127.0.0.1', r));

let relay = null;
async function relayUp(opts = {}) {
  if (relay) await new Promise((r) => relay.close(r));
  relay = await startRelay({ port: RELAY_PORT, host: '127.0.0.1', origins: [ORIGIN], ...opts });
}

const ONLY = process.env.ONLY ? new RegExp(process.env.ONLY, 'i') : null;
const browser = await chromium.launch({
  args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', '--autoplay-policy=no-user-gesture-required'],
});

const results = [];
const live = new Set();
const problems = [];
let current = '';
async function scenario(name, fn) {
  if (ONLY && !ONLY.test(name)) return;
  current = name.slice(0, 32);
  const t0 = Date.now();
  try { await fn(); results.push(['PASS', name, Date.now() - t0]); console.log(`✓ ${name}`); }
  catch (e) {
    results.push(['FAIL', name, Date.now() - t0, e.message]);
    console.log(`✗ ${name}\n    ${e.message.split('\n').slice(0, 3).join('\n    ')}`);
    if (SHOTS) for (const p of live) await p.screenshot({ path: path.join(SHOTS, `FAIL-${results.length}-${p.tag}.png`) }).catch(() => {});
    for (const p of live) await p.ctx.close().catch(() => {});
  }
  live.clear();
}

async function person(tag, lat = 13.1, lon = -59.6) {
  const ctx = await browser.newContext({ viewport: { width: 412, height: 860 }, deviceScaleFactor: 2, permissions: ['camera', 'microphone', 'geolocation'], geolocation: { latitude: lat, longitude: lon } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => problems.push(`[${tag}] pageerror: ${e.message}`));
  if (process.env.VERBOSE) page.on('console', (m) => console.log(`    [${tag}] ${m.type()}: ${m.text().slice(0, 200)}`));
  page.on('console', (m) => { if (m.type() === 'error' && !/Failed to load resource|WebSocket connection/.test(m.text())) problems.push(`[${current} · ${tag}] console: ${m.text().slice(0, 160)} @ ${(m.location()?.url || '').split('/').pop()}:${m.location()?.lineNumber ?? ''}`); });
  page.on('dialog', (d) => { problems.push(`[${tag}] JS dialog opened: ${d.message()}`); d.dismiss(); });
  await page.goto(ORIGIN + '/');
  await page.waitForFunction(() => /^WKN-/.test(document.querySelector('#my-id')?.textContent || ''));
  page.tag = tag; page.ctx = ctx; live.add(page);
  return page;
}
const shot = async (p, name) => { if (SHOTS) await p.screenshot({ path: path.join(SHOTS, `${name}.png`) }); };
const toasts = (p) => p.innerText('#toasts');
async function waitToast(p, re, ms = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (re.test(await toasts(p))) return; await sleep(150); }
  throw new Error(`[${p.tag}] expected toast ${re}, saw: ${JSON.stringify(await toasts(p))}`);
}

// Turn whatever link the app shared (full #v1/#v2 beacon or #s. short link) into
// an opened beacon — exactly what someone holding the link could do.
const RELAY_URL = `ws://127.0.0.1:${RELAY_PORT}/ws`;
async function resolveLink(link) {
  try { return await resolveLinkInner(link); } catch (e) { throw new Error(`${e.message} — link was: ${JSON.stringify(String(link).slice(0, 140))}`); }
}
async function resolveLinkInner(link) {
  const k = parseShort(link);
  if (!k) return openBeacon(link, Date.now(), { defaultRelay: RELAY_URL });
  const id = await shortId(k);
  const data = await new Promise((ok, fail) => {
    const ws = new WebSocket(RELAY_URL);
    ws.onopen = () => ws.send(JSON.stringify({ op: 'fetch', id }));
    ws.onmessage = (e) => { const m = JSON.parse(e.data); ws.close(); m.op === 'stash' ? ok(m.data) : fail(new Error(`short link: ${m.code}`)); };
    ws.onerror = () => fail(new Error('relay unreachable'));
  });
  const b = await openBeacon(await openShort(k, data), Date.now(), { defaultRelay: RELAY_URL });
  b.short = { id, data };
  return b;
}

async function hostBeacon(p, { mode = 'video', people = 2, linger = 'end' } = {}) {
  await p.click('[data-nav=connect]');
  await p.click(`label[for=mode-${mode}]`);
  await p.click(`label[for=max-${people}]`);
  await p.click(`label[for=linger-${linger}]`);
  await p.click('text=Create beacon');
  await p.waitForSelector('.beacon-link');
  const shown = (await p.innerText('.beacon-link')).trim();
  const { link, action } = splitAction(shown);
  assert.equal(action, 'answer', 'the shared link should be the one-tap Answer link');
  await p.click('.modal >> text=Done');
  return link; // plain link → ringing screen (Answer / Decline / Block)
}
async function openLink(p, link, { click = true } = {}) {
  await p.goto(link);
  if (click) { await p.waitForSelector('.modal button.btn-answer'); await p.click('.modal button.btn-answer'); }
}
const remoteVideos = (p) => p.evaluate(() => [...document.querySelectorAll('.tile:not(.me) video')].map((v) => ({ w: v.videoWidth, t: v.currentTime })));
async function waitVideos(p, n, ms = 25000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    const v = await remoteVideos(p);
    if (v.length >= n && v.every((x) => x.w > 0 && x.t > 0)) return v;
    await sleep(300);
  }
  throw new Error(`[${p.tag}] expected ${n} live remote videos, got ${JSON.stringify(await remoteVideos(p))}`);
}
async function endAll(...pages) { for (const p of pages) await p.ctx.close().catch(() => {}); }
async function sendChat(p, text) {
  await p.click('[data-nav=chat]');
  await p.fill('.composer input', text);
  await p.press('.composer input', 'Enter');
}

// ============================================================ scenarios
await relayUp();

await scenario('one tap: the Answer link and QR code open straight into the call; browser guests get a download button', async () => {
  const A = await person('A'), B = await person('B');
  await A.click('[data-nav=connect]');
  await A.click('label[for=mode-video]');
  await A.click('text=Create beacon');
  await A.waitForSelector('.beacon-link');
  const qr = await A.$eval('canvas.qr', (c) => ({ w: c.width, h: c.height }));
  assert.ok(qr.w >= 200 && qr.w === qr.h, `QR code should be drawn, got ${JSON.stringify(qr)}`);
  const answer = (await A.innerText('.beacon-link')).trim();
  assert.match(answer, /#s\.[A-Za-z0-9_-]{22}\.answer$/);
  await A.click('.modal >> text=Done');
  await B.goto(answer); // no ringing screen, no extra tap
  for (const p of [A, B]) await waitVideos(p, 1);
  const dl = await B.$eval('.getapp a', (a) => ({ href: a.href, target: a.target, rel: a.rel }));
  assert.equal(dl.target, '_blank', 'download must open in a new tab so the call keeps running');
  assert.match(dl.rel, /noopener/);
  assert.match(dl.href, /^https:\/\/github\.com\//);
  assert.equal(await B.$('.modal'), null, 'answer link must not show the ringing screen');
  await shot(B, 'e2e-oneTap-B');
  await endAll(A, B);
});

await scenario('decline link: caller is told at once and the invite dies; nobody gets camera or mic', async () => {
  const A = await person('A'), B = await person('B'), C = await person('C');
  const link = await hostBeacon(A, { mode: 'voice' });
  await B.ctx.addInitScript(() => { window.__gum = 0; const g = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices); navigator.mediaDevices.getUserMedia = (c) => { window.__gum++; return g(c); }; });
  await B.goto(link + '.decline');
  await B.waitForSelector('.modal >> text=Call declined');
  await A.waitForSelector('.modal >> text=declined the call', { timeout: 15000 });
  assert.match(await B.innerText('.modal'), /has been told/);
  assert.equal(await B.evaluate(() => window.__gum ?? 0), 0, 'declining must not open the microphone');
  // The declined invite is dead: answering it later fails cleanly.
  await openLink(C, link + '.answer', { click: false });
  await waitToast(C, /ended or is invalid|expired/);
  await endAll(A, B, C);
});

await scenario('block link: caller blocked, later calls from them are auto-declined, unblock works', async () => {
  const A = await person('A'), B = await person('B');
  const link1 = await hostBeacon(A, { mode: 'chat' });
  await B.goto(link1 + '.block');
  await B.waitForSelector('.modal >> text=Caller blocked');
  await A.waitForSelector('.modal >> text=declined the call', { timeout: 15000 });
  await B.click('.modal >> text=OK');
  await A.click('.modal >> text=OK');
  await B.click('[data-nav=settings]');
  const aid = (await A.innerText('#my-id')).trim();
  await B.waitForSelector(`text=${aid}`);
  // A calls again with a fresh invite; B taps plain Answer link → auto-declined, no ringing
  await sleep(500);
  const link2 = await hostBeacon(A, { mode: 'chat' });
  await B.goto(link2 + '.answer');
  await waitToast(B, /blocked this caller/);
  await A.waitForSelector('.modal >> text=declined the call', { timeout: 15000 });
  assert.equal(await B.$('.sas-words'), null, 'a blocked caller must never connect');
  // Unblock, then a new call rings through again.
  await A.click('.modal >> text=OK');
  await B.click('[data-nav=settings]');
  await B.click('.list >> text=Unblock');
  await waitToast(B, /unblocked/);
  const link3 = await hostBeacon(A, { mode: 'chat' });
  await openLink(B, link3);
  await A.waitForSelector('.sas-words', { timeout: 20000 });
  await endAll(A, B);
});

await scenario('3-person call: everyone sees and hears the other two; 4th person is turned away', async () => {
  const A = await person('A'), B = await person('B'), C = await person('C'), D = await person('D');
  const link = await hostBeacon(A, { people: 3 });
  await openLink(B, link);
  await openLink(C, link);
  for (const p of [A, B, C]) await waitVideos(p, 2);
  const words = await Promise.all([A, B, C].map((p) => p.$$eval('.sas-words', (els) => els.length)));
  assert.deepEqual(words, [2, 2, 2], 'each person must verify both others');
  await shot(A, 'e2e-3way-A');
  await sendChat(A, 'hello both');
  for (const p of [B, C]) { await p.click('[data-nav=chat]'); await p.waitForSelector('.msg.in .bubble >> text=hello both'); }
  await openLink(D, link);
  await waitToast(D, /already has 3 people/);
  // D must not be stuck in a dead call
  await D.waitForSelector('text=Create beacon', { timeout: 5000 });
  // C hangs up — A and B keep talking
  await C.click('[data-nav=call]'); await C.click('.ctl.end');
  await sleep(1500);
  await A.click('[data-nav=call]');
  assert.equal((await remoteVideos(A)).length, 1, 'A should now see only B');
  await sendChat(B, 'still here');
  await A.click('[data-nav=chat]'); await A.waitForSelector('.msg.in .bubble >> text=still here');
  await endAll(A, B, C, D);
});

await scenario('injection: hostile chat messages never execute; Trusted Types + CSP block raw HTML, eval and foreign scripts', async () => {
  const A = await person('A'), B = await person('B');
  const link = await hostBeacon(A, { mode: 'chat' });
  await openLink(B, link);
  await A.waitForSelector('.sas-words', { timeout: 20000 });
  const payloads = [
    '<img src=x onerror="window.__pwned=1">',
    '<svg/onload=window.__pwned=2>',
    '<script>window.__pwned=3</script>',
    '<a href="javascript:window.__pwned=4">click</a>',
    '<iframe srcdoc="<script>parent.__pwned=5</script>">',
    '<b onmouseover=window.__pwned=6>bold</b>',
    '"><img src=x onerror=window.__pwned=7>',
    '<math><mtext><table><mglyph><style><img src=x onerror=window.__pwned=8>',
    '<form><button formaction=javascript:window.__pwned=9>x',
    '<details open ontoggle=window.__pwned=10>',
    '<p style="background:url(javascript:window.__pwned=11)">s</p>',
    '<b>allowed bold</b> <i>italic</i>',
  ];
  await A.click('[data-nav=chat]');
  for (const t of payloads) { await A.fill('.composer input', t); await A.press('.composer input', 'Enter'); await sleep(80); }
  await B.click('[data-nav=chat]');
  await B.waitForFunction((n) => document.querySelectorAll('.msg.in').length >= n, payloads.length, { timeout: 15000 });
  await B.hover('.msg.in .bubble >> nth=5').catch(() => {});
  await sleep(500);
  for (const p of [A, B]) assert.equal(await p.evaluate(() => window.__pwned ?? null), null, `[${p.tag}] a payload executed`);
  const attrs = await B.$$eval('.bubble *', (els) => els.flatMap((e) => [...e.attributes].map((a) => `${e.tagName}[${a.name}]`)));
  assert.deepEqual(attrs, [], 'sanitised chat must contain no attributes at all');
  const tags = await B.$$eval('.bubble *', (els) => [...new Set(els.map((e) => e.tagName))]);
  for (const t of tags) assert.ok(['B', 'STRONG', 'I', 'EM', 'U', 'S', 'CODE', 'BR', 'P'].includes(t), `disallowed tag ${t}`);

  // Direct attacks from a page-loaded script (as if a bundled library were compromised)
  const loadState = await B.evaluate(() => new Promise((ok) => {
    try { const s = document.createElement('script'); s.src = '/__probe.js'; s.onload = () => ok('loaded'); s.onerror = () => ok('error'); document.head.append(s); }
    catch (e) { ok('threw: ' + e.message); }
    setTimeout(() => ok('timeout'), 3000);
  }));
  if (process.env.VERBOSE) console.log('    probe load:', loadState);
  await sleep(800);
  const blocked = await B.evaluate(() => window.__probe);
  assert.ok(blocked, 'probe did not run');
  const leaks = Object.entries(blocked).filter(([, v]) => v !== 'blocked').map(([k]) => k);
  assert.deepEqual(leaks, [], `not blocked: ${leaks.join(', ')}`);
  assert.equal(await B.evaluate(() => window.__pwned ?? null), null, 'an injected payload executed');
  // Hostile beacon fragments in the address bar
  for (const frag of ['#v1.<script>alert(1)</script>', '#v1.' + 'A'.repeat(43) + '.' + 'B'.repeat(60), '#javascript:alert(1)']) {
    await B.goto(ORIGIN + '/' + frag);
    await sleep(400);
  }
  assert.equal(await B.evaluate(() => window.__pwned ?? null), null);
  await endAll(A, B);
});

await scenario('malicious relay #1: tampers with forwarded signaling → nobody connects, users are warned, no crash', async () => {
  await relayUp({ testTamper: (d) => { const b = Buffer.from(d, 'base64url'); b[b.length >> 1] ^= 0x40; return b.toString('base64url'); } });
  const A = await person('A'), B = await person('B');
  const link = await hostBeacon(A);
  await openLink(B, link);
  await Promise.race([waitToast(A, /altered/), waitToast(B, /altered/)]);
  await sleep(3000);
  assert.equal(await A.$$eval('.sas-words', (e) => e.length), 0, 'A connected through a tampering relay');
  assert.equal(await B.$$eval('.sas-words', (e) => e.length), 0, 'B connected through a tampering relay');
  await shot(B, 'e2e-tamper-B');
  await endAll(A, B);
  await relayUp();
});

await scenario('malicious relay #2: attacker holding the leaked link impersonates the inviter → guest refuses', async () => {
  const A = await person('A');
  const link = await hostBeacon(A);
  const leaked = await resolveLink(link); // Mallory reads the leaked link
  // The relay is diverted (simulated by a fresh relay). Mallory owns the room there.
  await relayUp();
  const mallory = await generateIdentity();
  const sig = new Signaling(leaked.payload.sig, leaked.keys);
  let gotHello = false;
  sig.addEventListener('signal', async (e) => {
    if (e.detail.msg.t !== 'hello') return;
    gotHello = true;
    const r = await respond({ identity: mallory, room: leaked.payload.room, hello: e.detail.msg });
    await sig.send(e.detail.from, r.reply);
  });
  const trace = [];
  for (const ev of ['joined', 'peer-joined', 'relay-error', 'tampered', 'warning', 'closed']) sig.addEventListener(ev, (e) => trace.push(`${ev}:${JSON.stringify(e.detail)?.slice(0, 80)}`));
  await sig.connect();
  sig.create({ max: 2, linger: 'end', exp: leaked.payload.exp });
  // A hostile relay can also serve the short link's sealed copy (it cannot read it).
  if (leaked.short) sig.raw({ op: 'stash', id: leaked.short.id, data: leaked.short.data, exp: leaked.payload.exp });
  await sleep(300);
  const B = await person('B');
  await openLink(B, link);
  await waitToast(B, /does not match the beacon|man-in-the-middle/i, 20000).catch(async (e) => {
    console.log('    debug: mallory trace =', trace.join(' | '));
    console.log('    debug: mallory got hello =', gotHello, '| B toasts =', JSON.stringify(await toasts(B)), '| B view =', JSON.stringify((await B.innerText('#view')).slice(0, 120)));
    throw e;
  });
  assert.ok(gotHello);
  assert.equal(await B.$$eval('.sas-words', (e) => e.length), 0, 'guest accepted the impostor');
  await B.waitForSelector('text=Create beacon', { timeout: 5000 }); // left the hostile room
  await shot(B, 'e2e-impostor-B');
  sig.close();
  await endAll(A, B);
});

await scenario('relay outage mid-call: video and chat keep flowing peer-to-peer', async () => {
  await relayUp();
  const A = await person('A'), B = await person('B');
  const link = await hostBeacon(A);
  await openLink(B, link);
  await waitVideos(A, 1); await waitVideos(B, 1);
  const frames = () => B.evaluate(() => document.querySelector('.tile:not(.me) video')?.getVideoPlaybackQuality().totalVideoFrames || 0);
  await new Promise((r) => relay.close(r)); relay = null; // relay goes down
  await sleep(1000);
  const before = await frames();
  await sleep(5000);
  const after = await frames();
  assert.ok(after - before > 50, `video froze when relay died (${before} → ${after} frames in 5 s)`);
  await sendChat(A, 'relay is down but we are fine');
  await B.click('[data-nav=chat]'); await B.waitForSelector('.msg.in .bubble >> text=relay is down');
  await relayUp();
  await endAll(A, B);
});

await scenario('saved connection: SOS reaches a contact with NO call open, shows on their map with a siren', async () => {
  await relayUp();
  const A = await person('A', 13.0975, -59.6167), B = await person('B', 13.1132, -59.5988);
  const link = await hostBeacon(A, { mode: 'chat' });
  await openLink(B, link);
  await A.waitForSelector('text=Save connection', { timeout: 20000 }); await B.waitForSelector('text=Save connection');
  await A.click('text=Save connection'); await B.click('text=Save connection');
  await waitToast(A, /saved/); await waitToast(B, /saved/);
  await A.click('.ctl.end');
  await B.waitForSelector('text=Keep WeKoNet'); await sleep(1500);
  if (process.env.VERBOSE) console.log('    dialogs open on B:', await B.$$eval('dialog.modal', (d) => d.map((x) => x.querySelector('h2').textContent)));
  await B.click('button:has-text("Keep WeKoNet")');
  await sleep(1500);
  // No call now. B sends SOS.
  await B.click('#sos-fab'); await B.fill('.sos-card input', 'Car accident on Highway 1'); await B.click('text=SEND SOS');
  await A.waitForSelector('.sos-banner', { timeout: 20000 });
  const banner = await A.innerText('.sos-banner');
  assert.match(banner, /Car accident on Highway 1/);
  await shot(A, 'e2e-offline-sos-A');
  await B.click('text=Cancel SOS');
  await endAll(A, B);
});

await scenario('guest "Remove everything" really erases identity and storage', async () => {
  const A = await person('A'), B = await person('B');
  const link = await hostBeacon(A, { mode: 'chat' });
  await openLink(B, link);
  await B.waitForSelector('.sas-words', { timeout: 20000 });
  const idBefore = await B.innerText('#my-id');
  await A.click('.ctl.end');
  await B.waitForSelector('text=Remove everything'); await B.click('button:has-text("Remove everything")');
  await B.waitForSelector('text=WeKoNet removed');
  const dbs = await B.evaluate(async () => (await indexedDB.databases()).map((d) => d.name));
  assert.deepEqual(dbs, [], 'IndexedDB still has data');
  await B.goto(ORIGIN + '/');
  await B.waitForFunction(() => /^WKN-/.test(document.querySelector('#my-id')?.textContent || ''));
  assert.notEqual(await B.innerText('#my-id'), idBefore, 'old identity survived the wipe');
  await endAll(A, B);
});

await scenario('expired beacon: link cannot be reused after the call ends', async () => {
  const A = await person('A'), B = await person('B'), C = await person('C');
  const link = await hostBeacon(A, { mode: 'chat' });
  await openLink(B, link);
  await A.waitForSelector('.sas-words', { timeout: 20000 });
  await A.click('.ctl.end');
  await sleep(800);
  await openLink(C, link);
  await waitToast(C, /ended or is invalid|expired/);
  await endAll(A, B, C);
});

// ============================================================ report
await browser.close();
if (relay) relay.close();
web.close();
console.log('\n──────── results ────────');
for (const [s, n, ms, err] of results) console.log(`${s}  ${n}  (${(ms / 1000).toFixed(1)} s)${err ? `\n      ${err.split('\n')[0]}` : ''}`);
if (problems.length) {
  const counts = new Map(); for (const p of problems) counts.set(p, (counts.get(p) || 0) + 1);
  console.log('\nPage errors / dialogs (deduplicated):');
  for (const [p, n] of counts) console.log(`  ${n > 1 ? `${n}× ` : ''}${p}`);
}
const failed = results.filter((r) => r[0] === 'FAIL').length + problems.filter((p) => /pageerror|dialog/.test(p)).length;
process.exit(failed ? 1 : 0);
