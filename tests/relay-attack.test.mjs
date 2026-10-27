// HARD tests against the relay: protocol abuse, floods, brute force,
// resource exhaustion and load. The relay must stay up, stay correct and
// keep memory bounded no matter what a hostile client sends.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import crypto from 'node:crypto';
import { startRelay } from '../server/relay.js';
const stats = () => server.stats();

let server, port, url;
before(async () => {
  server = await startRelay({ port: 0, host: '127.0.0.1', maxConnPerIp: 1000 });
  port = server.address().port; url = `ws://127.0.0.1:${port}/ws`;
});
after(() => server.close());

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rid = (n = 16) => crypto.randomBytes(n).toString('base64url');

// ---------- raw socket helpers (to send things a normal client never would) ----------
function rawUpgrade(headers = {}) {
  return new Promise((ok, fail) => {
    const s = net.connect(port, '127.0.0.1');
    let buf = Buffer.alloc(0), upgraded = false;
    s.on('error', () => {});
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (!upgraded && buf.includes('\r\n\r\n')) {
        upgraded = true;
        const head = buf.toString('latin1', 0, buf.indexOf('\r\n\r\n'));
        buf = buf.subarray(buf.indexOf('\r\n\r\n') + 4);
        ok({ s, status: +head.split(' ')[1], read: () => buf });
      }
    });
    s.on('close', () => { if (!upgraded) fail(new Error('closed before upgrade')); });
    const h = { Host: 'x', Upgrade: 'websocket', Connection: 'Upgrade', 'Sec-WebSocket-Key': crypto.randomBytes(16).toString('base64'), 'Sec-WebSocket-Version': '13', ...headers };
    const path = h.path || '/ws'; delete h.path;
    s.write(`GET ${path} HTTP/1.1\r\n${Object.entries(h).filter(([, v]) => v != null).map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n`);
  });
}
function frame(payload, { opcode = 1, mask = true, fin = true, lenOverride } = {}) {
  const p = Buffer.from(payload);
  const len = lenOverride ?? p.length;
  let head;
  if (len < 126) head = Buffer.from([(fin ? 0x80 : 0) | opcode, (mask ? 0x80 : 0) | len]);
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = (fin ? 0x80 : 0) | opcode; head[1] = (mask ? 0x80 : 0) | 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = (fin ? 0x80 : 0) | opcode; head[1] = (mask ? 0x80 : 0) | 127; head.writeBigUInt64BE(BigInt(len), 2); }
  if (!mask) return Buffer.concat([head, p]);
  const k = crypto.randomBytes(4); const m = Buffer.from(p);
  for (let i = 0; i < m.length; i++) m[i] ^= k[i & 3];
  return Buffer.concat([head, k, m]);
}
const closed = (s, ms = 2000) => new Promise((ok) => { if (s.destroyed) return ok(true); s.once('close', () => ok(true)); setTimeout(() => ok(false), ms); });

async function healthy() {
  const ws = await client();
  ws.send({ op: 'ping' });
  const r = await ws.next();
  ws.close();
  return r.op === 'pong';
}

function client() {
  return new Promise((ok, fail) => {
    const ws = new WebSocket(url);
    const q = [], waiters = [];
    let isClosed = false;
    ws.onmessage = (e) => { const m = JSON.parse(e.data); const w = waiters.shift(); w ? w(m) : q.push(m); };
    ws.onclose = () => { isClosed = true; for (const w of waiters.splice(0)) w({ op: '__closed' }); };
    ws.onopen = () => ok({
      send: (o) => ws.send(typeof o === 'string' ? o : JSON.stringify(o)),
      next: (ms = 3000) => new Promise((r) => { if (q.length) return r(q.shift()); if (isClosed) return r({ op: '__closed' }); waiters.push(r); setTimeout(() => r({ op: '__timeout' }), ms); }),
      drain: () => q.splice(0),
      close: () => ws.close(),
      get closed() { return isClosed; },
    });
    ws.onerror = () => fail(new Error('ws error'));
  });
}

// =================================================================== protocol abuse
test('handshake abuse: bad path, foreign origin, missing key → refused', async () => {
  assert.equal((await rawUpgrade({ path: '/admin' })).status, 400);
  assert.equal((await rawUpgrade({ Origin: 'https://evil.example' })).status, 403);
  assert.equal((await rawUpgrade({ 'Sec-WebSocket-Key': null })).status, 400);
  assert.ok(await healthy());
});

test('frame abuse: unmasked, fragmented, binary, oversized, lying length, bad UTF-8/JSON → disconnected, relay survives', async () => {
  const cases = {
    unmasked: frame('{"op":"ping"}', { mask: false }),
    fragmented: frame('{"op":"pi', { fin: false }),
    binary: frame(Buffer.from([1, 2, 3]), { opcode: 2 }),
    oversized: frame(Buffer.alloc(70000, 65)),
    lyingLength64: Buffer.concat([Buffer.from([0x81, 0xff]), Buffer.from('7fffffffffffffff', 'hex'), crypto.randomBytes(4)]),
    badJson: frame('{"op": ping'),
    notObject: frame('"just a string"'),
    nullMsg: frame('null'),
    reservedOpcode: frame('x', { opcode: 0x3 }),
  };
  for (const [name, bytes] of Object.entries(cases)) {
    const { s } = await rawUpgrade();
    s.write(bytes);
    assert.ok(await closed(s), `${name}: connection should be closed`);
  }
  assert.ok(await healthy(), 'relay must survive all malformed frames');
});

test('garbage: 200 connections spraying random bytes do not crash the relay', async () => {
  const socks = [];
  for (let i = 0; i < 200; i++) {
    const { s } = await rawUpgrade();
    s.write(crypto.randomBytes(1 + Math.floor(Math.random() * 3000)));
    socks.push(s);
  }
  await sleep(300);
  for (const s of socks) s.destroy();
  assert.ok(await healthy());
});

test('slowloris: a client that never finishes a frame cannot hold more than its buffer', async () => {
  const { s } = await rawUpgrade();
  const f = frame(Buffer.alloc(60000, 66));
  s.write(f.subarray(0, 30000)); // half a frame, then silence
  await sleep(200);
  assert.ok(await healthy());
  s.destroy();
});

test('wrong-type fields: every op with hostile field types gets an error, never a crash', async () => {
  const ws = await client();
  const junk = [null, 1, -1, 1e308, true, {}, [], 'a'.repeat(70), '../../etc/passwd', '<script>', '\u0000'];
  const ops = ['create', 'join', 'signal', 'sub', 'ack', 'post', 'leave', 'end', 'nope', '__proto__', 'constructor'];
  let sent = 0;
  for (const op of ops) for (const v of junk) {
    ws.send({ op, room: v, proof: v, to: v, data: v, box: v, boxes: v, max: v, linger: v, exp: v });
    sent++;
    if (sent % 15 === 0) await sleep(800); // stay under the rate limit
  }
  ws.send({ __proto__: { op: 'ping' } });
  await sleep(300);
  assert.ok(await healthy());
  ws.close();
});

// =================================================================== access control
test('brute force: 300 random join proofs never get in; legit guest still joins', async () => {
  const room = rid(16), proof = rid(32);
  const host = await client();
  host.send({ op: 'create', room, proof, max: 2, linger: 'end', exp: Date.now() + 600e3 });
  assert.equal((await host.next()).op, 'joined');
  let admitted = 0;
  const attackers = await Promise.all(Array.from({ length: 15 }, client));
  for (let round = 0; round < 20; round++) {
    for (const a of attackers) a.send({ op: 'join', room, proof: rid(32) });
    await sleep(60);
  }
  await sleep(300);
  for (const a of attackers) for (const m of a.drain()) if (m.op === 'joined') admitted++;
  assert.equal(admitted, 0, 'an attacker was admitted with a guessed proof');
  const guest = await client(); guest.send({ op: 'join', room, proof });
  assert.equal((await guest.next()).op, 'joined');
  for (const c of [host, guest, ...attackers]) c.close();
});

test('isolation: cannot signal before joining, into another room, or to a peer in another room', async () => {
  const mk = async () => {
    const room = rid(16), proof = rid(32);
    const a = await client(); a.send({ op: 'create', room, proof, max: 2, linger: 'end', exp: Date.now() + 600e3 });
    const ja = await a.next();
    const b = await client(); b.send({ op: 'join', room, proof });
    const jb = await b.next(); await a.next();
    return { a, b, ja, jb };
  };
  const r1 = await mk(), r2 = await mk();
  const outsider = await client();
  outsider.send({ op: 'signal', to: r1.ja.peer, data: 'x' });
  assert.equal((await outsider.next()).code, 'bad-request');
  r2.a.send({ op: 'signal', to: r1.ja.peer, data: 'cross-room' }); // peer id from another room
  assert.equal((await r1.a.next(600)).op, '__timeout', 'cross-room signal was delivered');
  r1.b.send({ op: 'signal', to: r1.ja.peer, data: 'y'.repeat(70000) });
  assert.notEqual((await r1.a.next(600)).data?.length, 70000);
  for (const c of [r1.a, r1.b, r2.a, r2.b, outsider]) c.close();
});

test('room hijack: a second "create" for an existing room tag is refused', async () => {
  const room = rid(16), proof = rid(32);
  const a = await client(); a.send({ op: 'create', room, proof, max: 2, linger: 'end', exp: Date.now() + 600e3 }); await a.next();
  const m = await client(); m.send({ op: 'create', room, proof: rid(32), max: 3, linger: 'live', exp: Date.now() + 600e3 });
  assert.equal((await m.next()).code, 'room-exists');
  a.close(); m.close();
});

// =================================================================== exhaustion
test('flood: a client sending 500 messages at once is cut off by the rate limiter', async () => {
  const ws = await client();
  for (let i = 0; i < 500; i++) ws.send({ op: 'ping' });
  await sleep(500);
  assert.ok(ws.closed, 'flooding client should have been disconnected');
  assert.ok(await healthy());
});

test('room spam: one IP cannot create unlimited idle rooms', async () => {
  const before = stats().rooms;
  const ws = await client();
  let created = 0;
  for (let i = 0; i < 60; i++) {
    ws.send({ op: 'create', room: rid(16), proof: rid(32), max: 2, linger: 'end', exp: Date.now() + 3600e3 });
    const m = await ws.next(1000);
    if (m.op === 'joined') created++;
    ws.send({ op: 'leave' });
    if (i % 10 === 9) await sleep(600);
  }
  ws.close();
  assert.ok(created <= 20, `one IP created ${created} pending rooms`);
  assert.ok(stats().rooms - before <= 20);
});

test('mailbox spam: per-box cap and per-IP cap on new mailboxes', async () => {
  const ws = await client();
  const box = rid(32);
  for (let i = 0; i < 80; i++) { ws.send({ op: 'post', box, data: `m${i}` }); if (i % 15 === 14) await sleep(800); }
  await sleep(300); ws.drain();
  const r = await client(); r.send({ op: 'sub', boxes: [box] });
  await sleep(300);
  assert.ok(r.drain().length <= 50, 'mailbox holds more than 50 envelopes');
  const before = stats().mailboxes;
  for (let i = 0; i < 400; i++) { ws.send({ op: 'post', box: rid(32), data: 'x' }); if (i % 15 === 14) await sleep(800); }
  await sleep(300);
  assert.ok(stats().mailboxes - before <= 200, `one IP created ${stats().mailboxes - before} mailboxes`);
  ws.close(); r.close();
});

test('per-IP connection cap applies to the real client IP behind a trusted proxy', async () => {
  const srv = await startRelay({ port: 0, host: '127.0.0.1', maxConnPerIp: 5, trustProxy: true });
  const p = srv.address().port;
  const open = (ip) => new Promise((ok) => {
    const s = net.connect(p, '127.0.0.1');
    s.on('error', () => ok(0));
    s.once('data', (d) => ok(+d.toString().split(' ')[1]));
    s.write(`GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Forwarded-For: ${ip}\r\nSec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}\r\nSec-WebSocket-Version: 13\r\n\r\n`);
  });
  const a = []; for (let i = 0; i < 6; i++) a.push(await open('203.0.113.7'));
  assert.deepEqual(a, [101, 101, 101, 101, 101, 429], 'same real IP should hit the cap');
  assert.equal(await open('198.51.100.9'), 101, 'a different user behind the same proxy must not be blocked');
  srv.close();
});

// =================================================================== load
test('load: 150 concurrent rooms × 2 peers × 40 signals — every message delivered to the right peer only', async () => {
  // all test clients share 127.0.0.1, so use a relay with the per-IP beacon cap lifted
  const srv = await startRelay({ port: 0, host: '127.0.0.1', maxConnPerIp: 1000, pendingRoomsPerIp: 1000 });
  const saved = url; url = `ws://127.0.0.1:${srv.address().port}/ws`;
  const ROOMS = 150, MSGS = 40;
  const t0 = performance.now();
  const pairs = await Promise.all(Array.from({ length: ROOMS }, async (_, i) => {
    const room = rid(16), proof = rid(32);
    const a = await client(); a.send({ op: 'create', room, proof, max: 2, linger: 'end', exp: Date.now() + 600e3 });
    const ja = await a.next(5000);
    const b = await client(); b.send({ op: 'join', room, proof });
    await b.next(5000); await a.next(5000);
    return { a, b, ja, i };
  }));
  await Promise.all(pairs.map(async ({ b, ja, i }) => {
    for (let n = 0; n < MSGS; n++) { b.send({ op: 'signal', to: ja.peer, data: `${i}:${n}` }); if (n % 15 === 14) await sleep(800); }
  }));
  let ok = 0, wrong = 0;
  await Promise.all(pairs.map(async ({ a, i }) => {
    for (let n = 0; n < MSGS; n++) {
      const m = await a.next(8000);
      if (m.data === `${i}:${n}`) ok++; else wrong++;
    }
  }));
  const secs = (performance.now() - t0) / 1000;
  console.log(`# load: ${ok} msgs delivered in order across ${ROOMS} rooms in ${secs.toFixed(1)} s, ${wrong} wrong/missing`);
  assert.equal(wrong, 0);
  assert.equal(ok, ROOMS * MSGS);
  for (const { a, b } of pairs) { a.close(); b.close(); }
  await sleep(300);
  assert.ok(await healthy());
  srv.close(); url = saved;
});

test('memory: after all clients leave, rooms are cleaned up', async () => {
  let s = stats();
  for (let i = 0; i < 50 && s.connections > 0; i++) { await sleep(100); s = stats(); }
  assert.equal(s.connections, 0, `connections leaked: ${s.connections}`);
});
