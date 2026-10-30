// Bim Pulse — the island's public scoreboard.
// People report potholes and traffic (with a photo and a map pin) and rate the
// best places and services. Every report carries a 1–5 score (5 = best) and at
// most 100 characters of text; the server collates them into category scores
// and leaderboards.
//
// Zero npm dependencies. Data lives in one append-only JSON-lines file plus a
// folder of JPEG photos on the persistent disk (DATA_DIR, /data on Render).
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const CATEGORIES = [
  { id: 'potholes', name: 'Potholes Spotted', kind: 'map', photo: true, needLoc: true, low: 'Dangerous', high: 'Minor', keepMs: 90 * 86400e3, subject: false },
  { id: 'traffic', name: 'Traffic Congestion', kind: 'map', photo: true, needLoc: true, low: 'Standstill', high: 'Moving freely', keepMs: 3 * 3600e3, subject: false },
  { id: 'dining', name: 'Best Dining', kind: 'best', subject: 'Restaurant' },
  { id: 'soulfood', name: 'Best Soul Food', kind: 'best', subject: 'Place' },
  { id: 'chill', name: 'Best Chill Spot', kind: 'best', subject: 'Spot' },
  { id: 'carins', name: 'Best Car Insurance Co.', kind: 'best', subject: 'Insurance company' },
  { id: 'homeins', name: 'Best Home Insurance Co.', kind: 'best', subject: 'Insurance company' },
  { id: 'supermarket', name: 'Best Supermarket', kind: 'best', subject: 'Supermarket' },
  { id: 'govdept', name: 'Best Government Dept.', kind: 'best', subject: 'Department' },
  { id: 'clinic', name: 'Best Health Clinic', kind: 'best', subject: 'Clinic' },
  { id: 'carco', name: 'Best Car Company', kind: 'best', subject: 'Car company' },
].map((c) => ({ low: 'Worst', high: 'Best', photo: false, needLoc: false, keepMs: Infinity, ...c }));
const CAT = Object.fromEntries(CATEGORIES.map((c) => [c.id, c]));

export const LIMITS = Object.freeze({
  text: 100, subject: 60, photoBytes: 600 * 1024, bodyBytes: 900 * 1024,
  perIpHour: 30, photosPerIpHour: 12, fixedToHide: 3,
});
// Barbados and a generous margin (keeps junk coordinates off the map).
const BOUNDS = { minLat: 12.9, maxLat: 13.4, minLon: -59.75, maxLon: -59.35 };

const clean = (s, max) => String(s ?? '').normalize('NFC').replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
export const subjectKey = (s) => clean(s, LIMITS.subject).toLowerCase().replace(/[^a-z0-9 ]/g, '').replace(/\b(the|ltd|limited|inc|co|company)\b/g, '').replace(/\s+/g, ' ').trim();

export function createStore(dataDir) {
  fs.mkdirSync(path.join(dataDir, 'photos'), { recursive: true });
  const file = path.join(dataDir, 'reports.jsonl');
  const reports = new Map(); // id → report
  const apply = (ev) => {
    if (ev.t === 'add') reports.set(ev.r.id, { ...ev.r, fixed: 0, hidden: false });
    else if (ev.t === 'fixed') { const r = reports.get(ev.id); if (r) r.fixed++; }
    else if (ev.t === 'hide') { const r = reports.get(ev.id); if (r) r.hidden = true; }
  };
  if (fs.existsSync(file)) {
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) { if (line) { try { apply(JSON.parse(line)); } catch { /* skip torn line */ } } }
  }
  const log = (ev) => { apply(ev); fs.appendFileSync(file, JSON.stringify(ev) + '\n'); };

  const live = (r, now) => !r.hidden && now - r.at <= CAT[r.cat].keepMs && r.fixed < LIMITS.fixedToHide;

  function summary(now = Date.now()) {
    return CATEGORIES.map((c) => {
      const rs = [...reports.values()].filter((r) => r.cat === c.id && live(r, now));
      const avg = rs.length ? rs.reduce((a, r) => a + r.rating, 0) / rs.length : null;
      const top = c.kind === 'best' ? leaders(c.id, now)[0] || null : null;
      return { id: c.id, name: c.name, kind: c.kind, count: rs.length, score: avg && Math.round(avg * 10) / 10, top: top && { name: top.name, score: top.score } };
    });
  }

  // "Best" lists: reports grouped by place/company. Ranked by a weighted average
  // (each place starts with 3 imaginary 3-star votes) so one 5-star review can't top the list.
  function leaders(cat, now = Date.now()) {
    const groups = new Map();
    for (const r of reports.values()) {
      if (r.cat !== cat || !live(r, now) || !r.key) continue;
      const g = groups.get(r.key) || { key: r.key, names: new Map(), sum: 0, n: 0, last: 0 };
      g.names.set(r.subject, (g.names.get(r.subject) || 0) + 1);
      g.sum += r.rating; g.n++; g.last = Math.max(g.last, r.at);
      groups.set(r.key, g);
    }
    return [...groups.values()].map((g) => ({
      key: g.key,
      name: [...g.names.entries()].sort((a, b) => b[1] - a[1])[0][0],
      score: Math.round((g.sum / g.n) * 10) / 10,
      rank: (g.sum + 9) / (g.n + 3),
      count: g.n, last: g.last,
    })).sort((a, b) => b.rank - a.rank || b.count - a.count).slice(0, 50);
  }

  function list(cat, { limit = 60, now = Date.now() } = {}) {
    return [...reports.values()].filter((r) => r.cat === cat && live(r, now))
      .sort((a, b) => b.at - a.at).slice(0, limit)
      .map(({ id, cat: c, text, subject, rating, lat, lon, photo, at, fixed }) => ({ id, cat: c, text, subject, rating, lat, lon, photo: !!photo, at, fixed }));
  }

  function add(input, photoBytes) {
    const c = CAT[input.cat];
    if (!c) throw new Error('Unknown section');
    const text = clean(input.text, LIMITS.text + 1);
    if (!text) throw new Error('Write a short note (up to 100 characters)');
    if (text.length > LIMITS.text) throw new Error('Keep it to 100 characters');
    const rating = Number(input.rating);
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) throw new Error('Choose a score from 1 to 5');
    let subject = null, key = null;
    if (c.subject) {
      subject = clean(input.subject, LIMITS.subject);
      key = subjectKey(subject);
      if (!key) throw new Error(`Name the ${c.subject.toLowerCase()}`);
    }
    let lat = null, lon = null;
    if (input.lat != null || input.lon != null) {
      lat = Number(input.lat); lon = Number(input.lon);
      if (!(lat >= BOUNDS.minLat && lat <= BOUNDS.maxLat && lon >= BOUNDS.minLon && lon <= BOUNDS.maxLon)) throw new Error('That location is not in Barbados');
      lat = Math.round(lat * 1e5) / 1e5; lon = Math.round(lon * 1e5) / 1e5;
    }
    if (c.needLoc && lat == null) throw new Error('Pin the location on the map (or allow location)');
    if (photoBytes && !c.photo) throw new Error('Photos are only for potholes and traffic');
    const id = crypto.randomBytes(9).toString('base64url');
    let photo = false;
    if (photoBytes) {
      if (photoBytes.length > LIMITS.photoBytes || photoBytes[0] !== 0xff || photoBytes[1] !== 0xd8 || photoBytes[2] !== 0xff) throw new Error('Photo must be a JPEG under 600 KB');
      fs.writeFileSync(path.join(dataDir, 'photos', `${id}.jpg`), photoBytes);
      photo = true;
    }
    const r = { id, cat: c.id, text, subject, key, rating, lat, lon, photo, at: Date.now() };
    log({ t: 'add', r });
    return r;
  }

  return {
    summary, leaders, list, add,
    fixed: (id) => { if (!reports.has(id)) throw new Error('Not found'); log({ t: 'fixed', id }); },
    hide: (id) => { if (!reports.has(id)) throw new Error('Not found'); log({ t: 'hide', id }); },
    photoPath: (id) => (/^[A-Za-z0-9_-]{12}$/.test(id) && reports.get(id)?.photo && !reports.get(id).hidden ? path.join(dataDir, 'photos', `${id}.jpg`) : null),
    size: () => reports.size,
  };
}

// ---------------- HTTP ----------------
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json', '.json': 'application/json' };
const TILES = 'https://tile.openstreetmap.org';
const CSP = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", `img-src 'self' data: blob: ${TILES}`,
  "connect-src 'self'", "font-src 'self'", "manifest-src 'self'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "object-src 'none'",
].join('; '); // no inline script or style anywhere; all user text is rendered with textContent
const SEC = {
  'content-security-policy': CSP, 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(self), geolocation=(self), microphone=()', 'cross-origin-opener-policy': 'same-origin',
  'strict-transport-security': 'max-age=63072000',
};

function staticFiles() {
  const out = {};
  const pub = path.join(HERE, 'public');
  for (const f of fs.readdirSync(pub)) out[`/${f}`] = { type: TYPES[path.extname(f)] || 'application/octet-stream', body: fs.readFileSync(path.join(pub, f)) };
  out['/'] = out['/index.html'];
  // Leaflet (map) when installed (Docker image); the app works as a list without it.
  for (const [url, file] of [['/vendor/leaflet.js', 'leaflet/dist/leaflet.js'], ['/vendor/leaflet.css', 'leaflet/dist/leaflet.css']]) {
    for (const base of [path.join(HERE, 'node_modules'), path.join(HERE, '..', '..', 'node_modules')]) {
      try { out[url] = { type: TYPES[path.extname(url)], body: fs.readFileSync(path.join(base, file)) }; break; } catch { /* not installed */ }
    }
  }
  for (const [name, file] of [['marker-icon.png', 'marker-icon.png'], ['marker-icon-2x.png', 'marker-icon-2x.png'], ['marker-shadow.png', 'marker-shadow.png']]) {
    for (const base of [path.join(HERE, 'node_modules'), path.join(HERE, '..', '..', 'node_modules')]) {
      try { out[`/vendor/images/${name}`] = { type: 'image/png', body: fs.readFileSync(path.join(base, 'leaflet/dist/images', file)) }; break; } catch { /* optional */ }
    }
  }
  return out;
}

export function startServer({ port = +process.env.PORT || 8790, host = process.env.HOST || '127.0.0.1', dataDir = process.env.DATA_DIR || path.join(HERE, 'data'), trustProxy = process.env.TRUST_PROXY === '1', adminToken = process.env.ADMIN_TOKEN || '' } = {}) {
  const store = createStore(dataDir);
  const files = staticFiles();
  const hits = new Map(); // ip → { n, photos, since }
  const fixedBy = new Set(); // ip|id — one "fixed" vote per address per report

  const send = (res, code, body, headers = {}) => {
    const json = typeof body !== 'string' && !Buffer.isBuffer(body);
    res.writeHead(code, { ...SEC, 'cache-control': 'no-store', ...(json ? { 'content-type': 'application/json' } : {}), ...headers });
    res.end(json ? JSON.stringify(body) : body);
  };
  const ipOf = (req) => (trustProxy && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '';
  const quota = (ip, photo) => {
    const now = Date.now();
    const q = hits.get(ip) || { n: 0, photos: 0, since: now };
    if (now - q.since > 3600e3) { q.n = 0; q.photos = 0; q.since = now; }
    if (q.n >= LIMITS.perIpHour || (photo && q.photos >= LIMITS.photosPerIpHour)) return false;
    q.n++; if (photo) q.photos++; hits.set(ip, q); return true;
  };
  const readJson = (req) => new Promise((ok, fail) => {
    let size = 0; const chunks = [];
    req.on('data', (d) => { size += d.length; if (size > LIMITS.bodyBytes) { fail(new Error('Too large')); req.destroy(); } else chunks.push(d); });
    req.on('end', () => { try { ok(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { fail(new Error('Bad request')); } });
    req.on('error', fail);
  });
  const sameOrigin = (req) => {
    const o = req.headers.origin;
    if (!o) return true;
    try { return new URL(o).host === req.headers.host; } catch { return false; }
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', 'http://x');
    const p = url.pathname;
    try {
      if (req.method === 'GET' && p === '/healthz') return send(res, 200, 'ok', { 'content-type': 'text/plain' });
      if (req.method === 'GET' && p === '/api/summary') return send(res, 200, { categories: store.summary(), limits: { text: LIMITS.text } });
      if (req.method === 'GET' && p === '/api/categories') return send(res, 200, CATEGORIES.map(({ keepMs, ...c }) => ({ ...c, keepHours: Number.isFinite(keepMs) ? keepMs / 3600e3 : null })));
      if (req.method === 'GET' && p === '/api/reports') {
        const cat = url.searchParams.get('cat');
        if (!CAT[cat]) return send(res, 404, { error: 'Unknown section' });
        return send(res, 200, { reports: store.list(cat), leaders: CAT[cat].kind === 'best' ? store.leaders(cat) : [] });
      }
      const ph = /^\/photos\/([A-Za-z0-9_-]{12})\.jpg$/.exec(p);
      if (req.method === 'GET' && ph) {
        const f = store.photoPath(ph[1]);
        if (!f) return send(res, 404, '');
        return send(res, 200, fs.readFileSync(f), { 'content-type': 'image/jpeg', 'cache-control': 'public, max-age=86400' });
      }
      if (req.method === 'POST' && p.startsWith('/api/')) {
        if (!sameOrigin(req)) return send(res, 403, { error: 'Forbidden' });
        const body = await readJson(req);
        const ip = ipOf(req);
        if (p === '/api/submit') {
          const photo = typeof body.photo === 'string' && body.photo ? Buffer.from(body.photo, 'base64') : null;
          if (!quota(ip, !!photo)) return send(res, 429, { error: 'Too many reports from your connection — try again in an hour' });
          const r = store.add(body, photo);
          return send(res, 201, { ok: true, id: r.id });
        }
        if (p === '/api/fixed') {
          const k = `${ip}|${body.id}`;
          if (fixedBy.has(k)) return send(res, 200, { ok: true, already: true });
          if (!quota(ip, false)) return send(res, 429, { error: 'Too many reports from your connection' });
          store.fixed(String(body.id)); fixedBy.add(k);
          return send(res, 200, { ok: true });
        }
        if (p === '/api/hide') {
          const t = String(req.headers['x-admin-token'] || '');
          if (!adminToken || t.length !== adminToken.length || !crypto.timingSafeEqual(Buffer.from(t), Buffer.from(adminToken))) return send(res, 403, { error: 'Forbidden' });
          store.hide(String(body.id));
          return send(res, 200, { ok: true });
        }
        return send(res, 404, { error: 'Not found' });
      }
      const f = req.method === 'GET' || req.method === 'HEAD' ? files[p] : null;
      if (f) return send(res, 200, req.method === 'HEAD' ? '' : f.body, { 'content-type': f.type, ...(p.startsWith('/vendor/') ? { 'cache-control': 'public, max-age=604800' } : {}) });
      return send(res, 404, 'Not found', { 'content-type': 'text/plain' });
    } catch (e) {
      return send(res, 400, { error: e.message || 'Bad request' });
    }
  });
  server.store = store;
  return new Promise((ok) => server.listen(port, host, () => ok(server)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startServer({ host: process.env.HOST || '0.0.0.0' }).then((s) => console.log(`Bim Pulse listening on ${s.address().port}`));
}
