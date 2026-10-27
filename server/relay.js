#!/usr/bin/env node
// WeKoNet blind relay — zero dependencies (Node ≥ 20).
//
// The relay ONLY:
//   • admits peers that present a room's join proof (derived from the beacon key)
//   • forwards opaque AES-256-GCM ciphertext between ≤ 3 peers of a room
//   • holds sealed SOS / mailbox envelopes for offline contacts (max 24 h)
// It never sees beacon keys, identities, SDP, chat, locations or media.
// No content or IP addresses are logged. Run behind TLS (Caddy/nginx → wss://).
import http from 'node:http';
import crypto from 'node:crypto';

const PORT = +process.env.PORT || 8787;
const HOST = process.env.HOST || '127.0.0.1';
const ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://wekonet.app,capacitor://localhost,https://localhost,app://wekonet,http://localhost:5173')
  .split(',').map((s) => s.trim()).filter(Boolean);
const MAX_FRAME = 64 * 1024;
const MAX_CONN_PER_IP = 20;
const MAILBOX_TTL = 24 * 3600e3;
const MAILBOX_MAX = 50;
const MAX_PEERS = 3;

const rooms = new Map();     // roomTag → { hash, max, linger, exp, deadline, peers: Map<peerId, conn>, started }
const mailboxes = new Map(); // boxId → [{ t, data }]
const subs = new Map();      // boxId → Set<conn>
const ipCount = new Map();

const okId = (s, min = 16, max = 64) => typeof s === 'string' && s.length >= min && s.length <= max && /^[A-Za-z0-9_-]+$/.test(s);
const sha384 = (s) => crypto.createHash('sha384').update(Buffer.from(s, 'base64url')).digest('base64url');
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

// ---------------- minimal RFC 6455 ----------------
function sendFrame(sock, opcode, payload) {
  if (sock.destroyed) return;
  const len = payload.length;
  let head;
  if (len < 126) head = Buffer.from([0x80 | opcode, len]);
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | opcode; head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | opcode; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  sock.write(Buffer.concat([head, payload]));
}

class Conn {
  constructor(sock, ip) {
    this.sock = sock; this.ip = ip; this.buf = Buffer.alloc(0);
    this.room = null; this.peer = null; this.boxes = new Set();
    this.tokens = 40; this.last = Date.now(); this.alive = true;
    sock.on('data', (d) => this.onData(d));
    sock.on('close', () => this.cleanup());
    sock.on('error', () => this.sock.destroy());
  }

  send(obj) { sendFrame(this.sock, 0x1, Buffer.from(JSON.stringify(obj))); }
  close(code = 1000) { const b = Buffer.alloc(2); b.writeUInt16BE(code); sendFrame(this.sock, 0x8, b); this.sock.end(); }

  onData(d) {
    this.buf = Buffer.concat([this.buf, d]);
    if (this.buf.length > MAX_FRAME + 14) return this.close(1009);
    for (;;) {
      if (this.buf.length < 2) return;
      const fin = this.buf[0] & 0x80, op = this.buf[0] & 0x0f, masked = this.buf[1] & 0x80;
      let len = this.buf[1] & 0x7f, off = 2;
      if (!masked || !fin) return this.close(1002); // clients must mask; no fragmentation
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (this.buf.length < 10) return; const L = this.buf.readBigUInt64BE(2); if (L > BigInt(MAX_FRAME)) return this.close(1009); len = Number(L); off = 10; }
      if (len > MAX_FRAME) return this.close(1009);
      if (this.buf.length < off + 4 + len) return;
      const mask = this.buf.subarray(off, off + 4);
      const payload = Buffer.from(this.buf.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < len; i++) payload[i] ^= mask[i & 3];
      this.buf = this.buf.subarray(off + 4 + len);
      if (op === 0x8) return this.close();
      if (op === 0x9) { sendFrame(this.sock, 0xA, payload); continue; }
      if (op === 0xA) { this.alive = true; continue; }
      if (op !== 0x1) return this.close(1003);
      if (!this.rateOk()) return this.close(1008);
      let msg;
      try { msg = JSON.parse(payload.toString('utf8')); } catch { return this.close(1007); }
      try { handle(this, msg); } catch {
        if (process.env.DEBUG) console.error('rejected op', msg?.op, 'room=', this.room, 'exists=', rooms.has(this.room), 'peer=', this.peer, Object.keys(msg || {}).map((k) => `${k}:${String(msg[k]).length}`).join(' '));
        this.send({ op: 'error', code: 'bad-request' });
      }
    }
  }

  rateOk() { // token bucket: 20 msg/s, burst 40
    const now = Date.now();
    this.tokens = Math.min(40, this.tokens + ((now - this.last) / 1000) * 20); this.last = now;
    if (this.tokens < 1) return false;
    this.tokens -= 1; return true;
  }

  cleanup() {
    leaveRoom(this);
    for (const b of this.boxes) subs.get(b)?.delete(this);
    const n = (ipCount.get(this.ip) || 1) - 1;
    if (n <= 0) ipCount.delete(this.ip); else ipCount.set(this.ip, n);
  }
}

// ---------------- protocol ----------------
const LINGER = { end: 0, '1h': 3600e3, '2h': 7200e3, day: 86400e3, live: Infinity };

function joinRoom(c, room, r) {
  if (r.peers.size >= r.max) return c.send({ op: 'error', code: 'room-full' });
  const peer = crypto.randomBytes(8).toString('base64url');
  const others = [...r.peers.keys()];
  r.peers.set(peer, c); c.room = room; c.peer = peer;
  if (r.peers.size >= 2 && !r.started) {
    r.started = Date.now();
    // 'end' = no clock: the room lives while anyone is in it, dies when the last leaves.
    r.deadline = r.linger === 'end' ? Infinity : r.started + LINGER[r.linger];
  }
  c.send({ op: 'joined', peer, peers: others, deadline: Number.isFinite(r.deadline) ? r.deadline : null });
  for (const o of others) r.peers.get(o).send({ op: 'peer-joined', peer });
}

function leaveRoom(c) {
  const r = c.room && rooms.get(c.room);
  if (!r) return;
  r.peers.delete(c.peer);
  for (const o of r.peers.values()) o.send({ op: 'peer-left', peer: c.peer });
  // Beacon dies when the call ends, unless the inviter chose to linger.
  if (r.peers.size === 0 && r.started && (r.linger === 'end' || Date.now() > r.deadline)) rooms.delete(c.room);
  c.room = c.peer = null;
}

function handle(c, m) {
  switch (m.op) {
    case 'create': {
      if (!okId(m.room, 16, 32) || !okId(m.proof, 40, 48) || !(m.linger in LINGER)) throw 0;
      if (c.room || rooms.has(m.room)) return c.send({ op: 'error', code: 'room-exists' });
      const exp = Math.min(+m.exp || 0, Date.now() + 24 * 3600e3);
      rooms.set(m.room, {
        hash: sha384(m.proof), max: Math.min(Math.max(+m.max || 2, 2), MAX_PEERS),
        linger: m.linger, exp, deadline: Infinity, started: 0, peers: new Map(),
      });
      return joinRoom(c, m.room, rooms.get(m.room));
    }
    case 'join': {
      if (!okId(m.room, 16, 32) || !okId(m.proof, 40, 48)) throw 0;
      const r = rooms.get(m.room);
      if (!r || !safeEq(r.hash, sha384(m.proof))) return c.send({ op: 'error', code: 'no-such-beacon' });
      if (!r.started && Date.now() > r.exp) { rooms.delete(m.room); return c.send({ op: 'error', code: 'beacon-expired' }); }
      if (r.started && Date.now() > r.deadline && r.linger !== 'end') return c.send({ op: 'error', code: 'beacon-expired' });
      if (c.room) leaveRoom(c);
      return joinRoom(c, m.room, r);
    }
    case 'signal': {
      const r = c.room && rooms.get(c.room);
      if (!r || !okId(m.to, 8, 16) || typeof m.data !== 'string' || m.data.length > MAX_FRAME) throw 0;
      return r.peers.get(m.to)?.send({ op: 'signal', from: c.peer, data: m.data });
    }
    case 'leave': return leaveRoom(c);
    case 'end': { // explicit "end call for everyone" — kills the beacon
      const key = c.room, r = key && rooms.get(key);
      if (!r) return;
      rooms.delete(key);
      for (const o of r.peers.values()) { o.send({ op: 'ended' }); o.room = o.peer = null; }
      return;
    }
    case 'sub': {
      if (!Array.isArray(m.boxes) || m.boxes.length > 64) throw 0;
      for (const b of m.boxes) {
        if (!okId(b, 22, 43)) continue;
        c.boxes.add(b);
        if (!subs.has(b)) subs.set(b, new Set());
        subs.get(b).add(c);
        for (const env of mailboxes.get(b) || []) c.send({ op: 'mail', box: b, data: env.data, t: env.t });
      }
      return;
    }
    case 'ack': { // recipient confirms delivery → delete immediately
      if (!okId(m.box, 22, 43) || !c.boxes.has(m.box)) throw 0;
      mailboxes.delete(m.box);
      return;
    }
    case 'post': {
      if (!okId(m.box, 22, 43) || typeof m.data !== 'string' || m.data.length > 16384) throw 0;
      const env = { t: Date.now(), data: m.data };
      const live = subs.get(m.box);
      if (live?.size) for (const s of live) s.send({ op: 'mail', box: m.box, data: env.data, t: env.t });
      const q = mailboxes.get(m.box) || [];
      q.push(env); while (q.length > MAILBOX_MAX) q.shift();
      mailboxes.set(m.box, q);
      return c.send({ op: 'posted', box: m.box });
    }
    case 'ping': return c.send({ op: 'pong' });
    default: throw 0;
  }
}

// ---------------- housekeeping ----------------
function sweep() {
  const now = Date.now();
  for (const [k, r] of rooms) {
    const dead = (!r.started && now > r.exp && r.peers.size === 0) ||
                 (r.started && r.peers.size === 0 && (r.linger === 'end' || now > r.deadline));
    if (dead) rooms.delete(k);
  }
  for (const [b, q] of mailboxes) {
    const keep = q.filter((e) => now - e.t < MAILBOX_TTL);
    if (keep.length) mailboxes.set(b, keep); else mailboxes.delete(b);
  }
}

/** Nightly 01:00 purge: drop every idle room and every stored envelope. */
export function nightlyPurge() {
  for (const [k, r] of rooms) if (r.peers.size === 0 && r.linger !== 'live') rooms.delete(k);
  mailboxes.clear();
}

function msUntil1am() {
  const d = new Date(); const n = new Date(d); n.setHours(1, 0, 0, 0);
  if (n <= d) n.setDate(n.getDate() + 1);
  return n - d;
}
function scheduleNightly() { setTimeout(() => { nightlyPurge(); scheduleNightly(); }, msUntil1am()).unref(); }

// ---------------- server ----------------
export function startRelay({ port = PORT, host = HOST } = {}) {
  const sockets = new Set();
  const server = http.createServer((req, res) => {
    res.writeHead(req.url === '/healthz' ? 200 : 404, {
      'content-type': 'text/plain', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
    });
    res.end(req.url === '/healthz' ? 'ok' : '');
  });

  server.on('upgrade', (req, sock) => {
    // Behind a hosting proxy (Render, Fly, …) every client arrives from the
    // proxy's address; TRUST_PROXY=1 uses the client address it forwards.
    const fwd = process.env.TRUST_PROXY === '1' ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() : '';
    const ip = fwd || req.socket.remoteAddress || '';
    const origin = req.headers.origin || '';
    const key = req.headers['sec-websocket-key'];
    const reject = (code) => { sock.end(`HTTP/1.1 ${code} No\r\nConnection: close\r\n\r\n`); };
    if (req.url !== '/ws' || !key || req.headers.upgrade?.toLowerCase() !== 'websocket') return reject(400);
    if (origin && !ORIGINS.includes(origin)) return reject(403);
    if ((ipCount.get(ip) || 0) >= MAX_CONN_PER_IP) return reject(429);
    ipCount.set(ip, (ipCount.get(ip) || 0) + 1);
    const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    sock.setNoDelay(true);
    sockets.add(sock); sock.on('close', () => sockets.delete(sock));
    const c = new Conn(sock, ip);
    const hb = setInterval(() => {
      if (!c.alive) { clearInterval(hb); return sock.destroy(); }
      c.alive = false; sendFrame(sock, 0x9, Buffer.alloc(0));
    }, 30e3);
    sock.on('close', () => clearInterval(hb));
  });

  const closeHttp = server.close.bind(server);
  server.close = (cb) => { for (const s of sockets) s.destroy(); return closeHttp(cb); };

  setInterval(sweep, 60e3).unref();
  scheduleNightly();
  return new Promise((ok) => server.listen(port, host, () => ok(server)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startRelay().then((s) => console.log(`WeKoNet relay listening on ${HOST}:${s.address().port}`));
}
