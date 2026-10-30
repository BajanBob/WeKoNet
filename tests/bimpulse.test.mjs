// Bim Pulse server: limits, scoring, photos, abuse handling, persistence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startServer, createStore, subjectKey, CATEGORIES } from '../apps/bimpulse/server.js';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bimpulse-'));
const JPEG = Buffer.from([0xff, 0xd8, 0xff, 0xe0, ...Buffer.alloc(2000, 7), 0xff, 0xd9]);

async function boot(opts = {}) {
  const server = await startServer({ port: 0, host: '127.0.0.1', dataDir: tmp(), adminToken: 'secret-admin-token', ...opts });
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (p, body, headers = {}) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) })
    .then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));
  const get = (p) => fetch(base + p).then(async (r) => ({ status: r.status, headers: r.headers, body: r.headers.get('content-type')?.includes('json') ? await r.json() : await r.text() }));
  return { server, base, post, get };
}

test('bim pulse: all eleven sections, potholes and traffic take photos and need a pin', () => {
  assert.deepEqual(CATEGORIES.map((c) => c.id), ['potholes', 'traffic', 'dining', 'soulfood', 'chill', 'carins', 'homeins', 'supermarket', 'govdept', 'clinic', 'carco']);
  for (const c of CATEGORIES) assert.equal(c.photo, c.kind === 'map');
});

test('bim pulse: 100-character limit, 1–5 score, place name and Barbados location enforced', () => {
  const s = createStore(tmp());
  assert.throws(() => s.add({ cat: 'dining', text: 'x'.repeat(101), rating: 4, subject: 'A' }), /100 characters/);
  assert.ok(s.add({ cat: 'dining', text: 'x'.repeat(100), rating: 4, subject: 'Cuz Fish Shack' }));
  for (const rating of [0, 6, 2.5, '5x', null]) assert.throws(() => s.add({ cat: 'dining', text: 'ok', rating, subject: 'A' }), /1 to 5/);
  assert.throws(() => s.add({ cat: 'dining', text: 'ok', rating: 3 }), /Name the restaurant/);
  assert.throws(() => s.add({ cat: 'potholes', text: 'deep one', rating: 1 }), /Pin the location/);
  assert.throws(() => s.add({ cat: 'potholes', text: 'deep one', rating: 1, lat: 51.5, lon: -0.1 }), /not in Barbados/);
  assert.throws(() => s.add({ cat: 'nope', text: 'x', rating: 3 }), /Unknown section/);
  assert.throws(() => s.add({ cat: 'dining', text: 'x', rating: 3, subject: 'A' }, JPEG), /only for potholes/);
  assert.throws(() => s.add({ cat: 'potholes', text: 'x', rating: 1, lat: 13.1, lon: -59.6 }, Buffer.from('<svg onload=alert(1)>')), /JPEG/);
  const r = s.add({ cat: 'potholes', text: '  Big\n‮hole  ', rating: 1, lat: 13.123456789, lon: -59.6 }, JPEG);
  assert.equal(r.text, 'Big hole', 'control and bidi characters are stripped');
  assert.equal(r.lat, 13.12346);
});

test('bim pulse: leaderboard groups spellings of one place and one 5-star review cannot top it', () => {
  const s = createStore(tmp());
  assert.equal(subjectKey('The Cuz Fish Shack Ltd.'), subjectKey('cuz fish shack'));
  for (const [subject, rating] of [['Cuz Fish Shack', 5], ['cuz fish shack', 4], ['The Cuz Fish Shack', 5], ['CUZ FISH SHACK', 4], ['New Place', 5]]) {
    s.add({ cat: 'dining', text: 'good', rating, subject });
  }
  const top = s.leaders('dining');
  assert.equal(top[0].count, 4);
  assert.equal(top[0].score, 4.5);
  assert.equal(top[1].name, 'New Place');
  const sum = s.summary().find((c) => c.id === 'dining');
  assert.equal(sum.count, 5); assert.equal(sum.score, 4.6); assert.equal(sum.top.score, 4.5);
});

test('bim pulse: traffic reports drop off after 3 hours, potholes after 3 "fixed" votes', () => {
  const s = createStore(tmp());
  s.add({ cat: 'traffic', text: 'jam', rating: 1, lat: 13.1, lon: -59.6 });
  assert.equal(s.list('traffic', { now: Date.now() + 2 * 3600e3 }).length, 1);
  assert.equal(s.list('traffic', { now: Date.now() + 4 * 3600e3 }).length, 0);
  const p = s.add({ cat: 'potholes', text: 'hole', rating: 2, lat: 13.1, lon: -59.6 });
  s.fixed(p.id); s.fixed(p.id);
  assert.equal(s.list('potholes').length, 1);
  s.fixed(p.id);
  assert.equal(s.list('potholes').length, 0);
});

test('bim pulse: data survives a restart', () => {
  const dir = tmp();
  const a = createStore(dir);
  const r = a.add({ cat: 'potholes', text: 'hole', rating: 2, lat: 13.1, lon: -59.6 }, JPEG);
  a.add({ cat: 'clinic', text: 'quick', rating: 5, subject: 'Polyclinic' });
  const b = createStore(dir);
  assert.equal(b.size(), 2);
  assert.ok(fs.existsSync(b.photoPath(r.id)));
});

test('bim pulse HTTP: submit, read back, photo served, strict headers', async () => {
  const { server, post, get } = await boot();
  try {
    const ok = await post('/api/submit', { cat: 'potholes', text: 'Deep hole by the bus stop', rating: 1, lat: 13.09, lon: -59.61, photo: JPEG.toString('base64') });
    assert.equal(ok.status, 201);
    const list = await get('/api/reports?cat=potholes');
    assert.equal(list.body.reports[0].text, 'Deep hole by the bus stop');
    assert.equal(list.body.reports[0].photo, true);
    assert.equal(list.body.reports[0].key, undefined, 'internal fields stay private');
    const img = await fetch(`${server.address().port ? `http://127.0.0.1:${server.address().port}` : ''}/photos/${ok.body.id}.jpg`);
    assert.equal(img.headers.get('content-type'), 'image/jpeg');
    assert.equal(Buffer.from(await img.arrayBuffer()).length, JPEG.length);
    const page = await get('/');
    assert.match(page.body, /Bim Pulse/);
    const csp = page.headers.get('content-security-policy');
    assert.match(csp, /script-src 'self'/); assert.doesNotMatch(csp, /unsafe/);
    assert.match(page.headers.get('permissions-policy'), /camera=\(self\)/);
    for (const bad of ['/photos/../reports.jsonl', '/photos/%2e%2e%2freports.jsonl.jpg', '/reports.jsonl', '/server.js', '/photos/AAAAAAAAAAAA.jpg']) {
      assert.equal((await get(bad)).status, 404, bad);
    }
  } finally { server.close(); }
});

test('bim pulse HTTP: other sites cannot post, floods are limited, oversized bodies refused, admin can hide', async () => {
  const { server, post, get } = await boot();
  try {
    assert.equal((await post('/api/submit', { cat: 'chill', text: 'x', rating: 3, subject: 'Y' }, { origin: 'https://evil.example' })).status, 403);
    let last;
    for (let i = 0; i < 31; i++) last = await post('/api/submit', { cat: 'chill', text: `spot ${i}`, rating: 4, subject: 'Pebbles Beach' });
    assert.equal(last.status, 429);
    const big = await fetch(`http://127.0.0.1:${server.address().port}/api/submit`, { method: 'POST', body: 'x'.repeat(1024 * 1024) }).catch(() => ({ status: 413 }));
    assert.ok([400, 413].includes(big.status));
    const id = (await get('/api/reports?cat=chill')).body.reports[0].id;
    assert.equal((await post('/api/hide', { id }, { 'x-admin-token': 'wrong-admin-token!' })).status, 403);
    assert.equal((await post('/api/hide', { id }, { 'x-admin-token': 'secret-admin-token' })).status, 200);
    assert.ok(!(await get('/api/reports?cat=chill')).body.reports.some((r) => r.id === id));
  } finally { server.close(); }
});
