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
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = +process.env.PORT || 8787;
const HOST = process.env.HOST || '127.0.0.1';
const ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://wekonet.app,capacitor://localhost,https://localhost,app://wekonet,http://localhost:5173')
  .split(',').map((s) => s.trim()).filter(Boolean);
const MAX_FRAME = 64 * 1024;
const MAX_PENDING_ROOMS_PER_IP = 20;   // beacons created but not yet answered
const MAX_NEW_BOXES_PER_IP_HOUR = 200; // offline mailboxes one IP may create per hour
const MAX_SUBS_PER_CONN = 256;
const MAX_ROOMS = 100000, MAX_BOXES = 200000; // global hard ceilings
const MAILBOX_TTL = 24 * 3600e3;
const MAILBOX_MAX = 50;
const MAX_PEERS = 3;

// ---------------- TURN (Cloudflare) ----------------
// When CF_TURN_KEY_ID + CF_TURN_API_TOKEN are set, the relay hands short-lived
// Cloudflare TURN credentials to people who join a room, so calls connect on
// any network and "Hide my IP" works. No TURN password is ever built into the app.
const CF_TURN_KEY_ID = process.env.CF_TURN_KEY_ID || '';
const CF_TURN_API_TOKEN = process.env.CF_TURN_API_TOKEN || '';
const TURN_TTL_S = 24 * 3600;      // credentials stay valid at least ~23 h after they are handed out
let turnIce = null;
async function refreshTurn() {
  if (!CF_TURN_KEY_ID || !CF_TURN_API_TOKEN) return;
  try {
    const r = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(CF_TURN_KEY_ID)}/credentials/generate-ice-servers`, {
      method: 'POST',
      headers: { authorization: `Bearer ${CF_TURN_API_TOKEN}`, 'content-type': 'application/json' },
      body: JSON.stringify({ ttl: TURN_TTL_S }),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    const list = (Array.isArray(j.iceServers) ? j.iceServers : [j.iceServers]).filter((x) => x && x.urls);
    turnIce = list.map((x) => ({
      urls: [].concat(x.urls).filter((u) => !/:53(\?|$)/.test(u)), // port 53 is blocked by browsers
      ...(x.username ? { username: x.username, credential: x.credential } : {}),
    })).filter((x) => x.urls.length);
  } catch (e) {
    console.error(`TURN credentials refresh failed (${e.message})`);
  }
}
export const turnConfigured = () => !!turnIce;
let turnTimer = null;

const STASH_MAX = 50000, STASH_PER_IP_HOUR = 30, STASH_MAX_TTL = 125 * 60e3;

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

// ---------------- relay core (one independent state per server) ----------------
function createCore() {
  const rooms = new Map();     // roomTag → { hash, max, linger, exp, deadline, peers: Map<peerId, conn>, started }
  const mailboxes = new Map(); // boxId → [{ t, data }]
  const subs = new Map();      // boxId → Set<conn>
  const ipCount = new Map();
  const ipPending = new Map(); // ip → unanswered rooms created
  const ipBoxes = new Map();   // ip → { n, since }
  const stash = new Map();     // short-link id → { data, exp }  (sealed beacons; the relay cannot open them)
  const stashByIp = new Map(); // ip → { n, since }
  const hasOwn = (o, k) => typeof k === 'string' && Object.prototype.hasOwnProperty.call(o, k);

  function stats() {
    let connections = 0; for (const n of ipCount.values()) connections += n;
    return { rooms: rooms.size, mailboxes: mailboxes.size, stash: stash.size, connections };
  }

  function dropRoom(key) {
    const r = rooms.get(key);
    if (!r) return;
    if (!r.started) bump(ipPending, r.ownerIp, -1);
    rooms.delete(key);
  }
  function bump(map, k, d) { const n = (map.get(k) || 0) + d; if (n <= 0) map.delete(k); else map.set(k, n); }

  class Conn {
    constructor(sock, ip, limits) {
      this.sock = sock; this.ip = ip; this.limits = limits; this.buf = Buffer.alloc(0);
      this.room = null; this.peer = null; this.boxes = new Set();
      this.tokens = 40; this.last = Date.now(); this.alive = true;
      sock.on('data', (d) => this.onData(d));
      sock.on('close', () => this.cleanup());
      sock.on('error', () => this.sock.destroy());
    // HTTP-upgraded sockets are half-open capable: if the client just drops
    // (TCP FIN without a WebSocket close), free the slot immediately.
    sock.on('end', () => this.sock.destroy());
    }

    send(obj) { sendFrame(this.sock, 0x1, Buffer.from(JSON.stringify(obj))); }
    close(code = 1000) { if (this.dead) return; this.dead = true; const b = Buffer.alloc(2); b.writeUInt16BE(code); sendFrame(this.sock, 0x8, b); this.sock.end();
      // never wait forever for a peer that won't finish closing
      setTimeout(() => this.sock.destroy(), 2000).unref(); }

    onData(d) {
      if (this.dead) return;
      this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d;
      for (;;) {
        if (this.buf.length > MAX_FRAME + 14) return this.close(1009);
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
        if (op !== 0x1 || this.buf[0] & 0x70) return this.close(1003);
        if (!this.rateOk()) return this.close(1008);
        let msg;
        try { msg = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload)); } catch { return this.close(1007); }
        if (!msg || typeof msg !== 'object' || Array.isArray(msg) || typeof msg.op !== 'string') return this.close(1007);
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
      for (const b of this.boxes) { const set = subs.get(b); set?.delete(this); if (set && !set.size) subs.delete(b); }
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
      bump(ipPending, r.ownerIp, -1);
      // 'end' = no clock: the room lives while anyone is in it, dies when the last leaves.
      r.deadline = r.linger === 'end' ? Infinity : r.started + LINGER[r.linger];
    }
    c.send({ op: 'joined', peer, peers: others, deadline: Number.isFinite(r.deadline) ? r.deadline : null, ...(turnIce ? { ice: turnIce } : {}) });
    for (const o of others) r.peers.get(o).send({ op: 'peer-joined', peer });
  }

  function leaveRoom(c) {
    const r = c.room && rooms.get(c.room);
    if (!r) return;
    r.peers.delete(c.peer);
    for (const o of r.peers.values()) o.send({ op: 'peer-left', peer: c.peer });
    // Beacon dies when the call ends, unless the inviter chose to linger.
    if (r.peers.size === 0 && r.started && (r.linger === 'end' || Date.now() > r.deadline)) dropRoom(c.room);
    c.room = c.peer = null;
  }

  function handle(c, m) {
    switch (m.op) {
      case 'create': {
        if (!okId(m.room, 16, 32) || !okId(m.proof, 40, 48) || !hasOwn(LINGER, m.linger)) throw 0;
        if (c.room || rooms.has(m.room)) return c.send({ op: 'error', code: 'room-exists' });
        if ((ipPending.get(c.ip) || 0) >= c.limits.pendingRoomsPerIp || rooms.size >= MAX_ROOMS) return c.send({ op: 'error', code: 'too-many-beacons' });
        const exp = Math.min(Number.isFinite(+m.exp) ? +m.exp : 0, Date.now() + 24 * 3600e3);
        bump(ipPending, c.ip, 1);
        rooms.set(m.room, {
          ownerIp: c.ip,
          hash: sha384(m.proof), max: m.max === 3 ? 3 : 2,
          linger: m.linger, exp, deadline: Infinity, started: 0, peers: new Map(),
        });
        return joinRoom(c, m.room, rooms.get(m.room));
      }
      case 'join': {
        if (!okId(m.room, 16, 32) || !okId(m.proof, 40, 48)) throw 0;
        const r = rooms.get(m.room);
        if (!r || !safeEq(r.hash, sha384(m.proof))) return c.send({ op: 'error', code: 'no-such-beacon' });
        if (!r.started && Date.now() > r.exp) { dropRoom(m.room); return c.send({ op: 'error', code: 'beacon-expired' }); }
        if (r.started && Date.now() > r.deadline && r.linger !== 'end') return c.send({ op: 'error', code: 'beacon-expired' });
        if (c.room) leaveRoom(c);
        return joinRoom(c, m.room, r);
      }
      case 'signal': {
        const r = c.room && rooms.get(c.room);
        if (!r || !okId(m.to, 8, 16) || typeof m.data !== 'string' || m.data.length > MAX_FRAME) throw 0;
        const data = c.limits.testTamper ? c.limits.testTamper(m.data) : m.data;
        return r.peers.get(m.to)?.send({ op: 'signal', from: c.peer, data });
      }
      case 'leave': return leaveRoom(c);
      case 'end': { // explicit "end call for everyone" — kills the beacon
        const key = c.room, r = key && rooms.get(key);
        if (!r) return;
        dropRoom(key);
        for (const o of r.peers.values()) { o.send({ op: 'ended' }); o.room = o.peer = null; }
        return;
      }
      case 'sub': {
        if (!Array.isArray(m.boxes) || m.boxes.length > 64) throw 0;
        for (const b of m.boxes) {
          if (!okId(b, 22, 43) || (c.boxes.size >= MAX_SUBS_PER_CONN && !c.boxes.has(b))) continue;
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
        if (!mailboxes.has(m.box)) {
          const now = Date.now(), q = ipBoxes.get(c.ip);
          const w = q && now - q.since < 3600e3 ? q : { n: 0, since: now };
          if (w.n >= c.limits.newBoxesPerHour || mailboxes.size >= MAX_BOXES) return c.send({ op: 'error', code: 'mailbox-quota' });
          w.n++; ipBoxes.set(c.ip, w);
        }
        const env = { t: Date.now(), data: m.data };
        const live = subs.get(m.box);
        if (live?.size) for (const s of live) s.send({ op: 'mail', box: m.box, data: env.data, t: env.t });
        const q = mailboxes.get(m.box) || [];
        q.push(env); while (q.length > MAILBOX_MAX) q.shift();
        mailboxes.set(m.box, q);
        return c.send({ op: 'posted', box: m.box });
      }
      case 'stash': { // park a sealed beacon for a short link until it expires
        if (!okId(m.id, 16, 16) || typeof m.data !== 'string' || m.data.length > 3000 || !/^[A-Za-z0-9_-]+$/.test(m.data)) throw 0;
        const now = Date.now();
        const exp = Math.min(Number(m.exp) || 0, now + STASH_MAX_TTL);
        if (!(exp > now)) throw 0;
        const q = stashByIp.get(c.ip) || { n: 0, since: now };
        if (now - q.since > 3600e3) { q.n = 0; q.since = now; }
        if (q.n >= STASH_PER_IP_HOUR || stash.size >= STASH_MAX) return c.send({ op: 'error', code: 'busy', id: m.id });
        if (stash.has(m.id)) throw 0;
        q.n++; stashByIp.set(c.ip, q);
        stash.set(m.id, { data: m.data, exp });
        return c.send({ op: 'stashed', id: m.id });
      }
      case 'fetch': {
        if (!okId(m.id, 16, 16)) throw 0;
        const e = stash.get(m.id);
        if (!e || e.exp < Date.now()) return c.send({ op: 'error', code: 'no-such-link', id: m.id });
        return c.send({ op: 'stash', id: m.id, data: e.data });
      }
      case 'ping': return c.send({ op: 'pong' });
      default: throw 0;
    }
  }

  // ---------------- housekeeping ----------------
  function sweep() {
    const now = Date.now();
    for (const [k, e] of stash) if (e.exp < now) stash.delete(k);
    for (const [ip, q] of stashByIp) if (now - q.since > 3600e3) stashByIp.delete(ip);
    for (const [k, r] of rooms) {
      const dead = (!r.started && now > r.exp && r.peers.size === 0) ||
                   (r.started && r.peers.size === 0 && (r.linger === 'end' || now > r.deadline));
      if (dead) dropRoom(k);
    }
    for (const [ip, w] of ipBoxes) if (now - w.since > 3600e3) ipBoxes.delete(ip);
    for (const [b, q] of mailboxes) {
      const keep = q.filter((e) => now - e.t < MAILBOX_TTL);
      if (keep.length) mailboxes.set(b, keep); else mailboxes.delete(b);
    }
  }

  /** Nightly 01:00 purge: drop every idle room and every stored envelope. */
  function nightlyPurge() {
    for (const [k, r] of rooms) if (r.peers.size === 0 && r.linger !== 'live') dropRoom(k);
    mailboxes.clear();
    ipBoxes.clear();
  }


  return { Conn, stats, nightlyPurge, sweep, ipCount };
}

function msUntil1am() {
  const d = new Date(); const n = new Date(d); n.setHours(1, 0, 0, 0);
  if (n <= d) n.setDate(n.getDate() + 1);
  return n - d;
}
function scheduleNightly(core) { setTimeout(() => { core.nightlyPurge(); scheduleNightly(core); }, msUntil1am()).unref(); }

// ---------------- beacon landing page (https://<relay>/b/#v1...) ----------------
// The fragment (#v1...) never reaches the server; open.js hands it to the app.
function landingPages() {
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'landing');
  const read = (f) => { try { return fs.readFileSync(path.join(dir, f)); } catch { return null; } };
  const out = {};
  const esc = (v) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  const html = read('index.html');
  if (html) {
    const dl = process.env.DOWNLOAD_URL || '';
    const body = Buffer.from(html.toString('utf8').replace('<html lang="en">', `<html lang="en" data-download="${esc(/^https:\/\//.test(dl) ? dl : '')}">`));
    out['/b/'] = { type: 'text/html; charset=utf-8', body };
  }
  const home = read('home.html');
  if (home) out['/'] = { type: 'text/html; charset=utf-8', body: home };
  for (const [f, type] of [['open.js', 'text/javascript'], ['style.css', 'text/css']]) {
    const b = read(f); if (b) out[`/b/${f}`] = { type, body: b };
  }
  // Android App Links: set ANDROID_CERT_SHA256 (from `apksigner verify --print-certs`) to let
  // beacon links open the app directly without the landing page.
  const fp = (process.env.ANDROID_CERT_SHA256 || '').trim();
  if (fp) {
    out['/.well-known/assetlinks.json'] = { type: 'application/json', body: Buffer.from(JSON.stringify([{
      relation: ['delegate_permission/common.handle_all_urls'],
      target: { namespace: 'android_app', package_name: 'app.wekonet.connect', sha256_cert_fingerprints: fp.split(',').map((x) => x.trim()) },
    }])) };
  }
  return out;
}

// ---------------- server ----------------
export function startRelay({
  port = PORT, host = HOST,
  maxConnPerIp = +process.env.MAX_CONN_PER_IP || 20,
  trustProxy = process.env.TRUST_PROXY === '1', // set when behind Caddy/nginx
  // Behind a proxy that hides client IPs (e.g. Render), raise these via env so the
  // per-"IP" limits don't cap the whole service; per-connection flood limits and
  // the global ceilings still apply.
  pendingRoomsPerIp = +process.env.PENDING_ROOMS_PER_IP || MAX_PENDING_ROOMS_PER_IP,
  newBoxesPerHour = +process.env.NEW_BOXES_PER_HOUR || MAX_NEW_BOXES_PER_IP_HOUR,
  origins = ORIGINS,
  testTamper = null, // TEST ONLY: simulates a malicious relay that alters what it forwards
} = {}) {
  const limits = Object.freeze({ pendingRoomsPerIp, newBoxesPerHour, testTamper });
  const MAX_CONN_PER_IP = maxConnPerIp, TRUST_PROXY = trustProxy;
  const sockets = new Set();
  const core = createCore();
  const { Conn, ipCount } = core;
  const pages = landingPages();
  const server = http.createServer((req, res) => {
    const url = (req.url || '/').split('?')[0];
    const base = {
      'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
      'strict-transport-security': 'max-age=63072000; includeSubDomains',
      'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    };
    if (url === '/healthz') { res.writeHead(200, { ...base, 'content-type': 'text/plain' }); return res.end('ok'); }
    const page = pages[url === '/b' ? '/b/' : url];
    if (page && (req.method === 'GET' || req.method === 'HEAD')) {
      res.writeHead(200, { ...base, 'content-type': page.type });
      return res.end(req.method === 'HEAD' ? undefined : page.body);
    }
    res.writeHead(404, { ...base, 'content-type': 'text/plain' }); res.end('');
  });

  server.on('upgrade', (req, sock) => {
    // Behind a hosting proxy (Render, Fly, …) every client arrives from the
    // proxy's address; TRUST_PROXY=1 uses the client address it forwards (first
    // X-Forwarded-For entry — what Render sets). Only enable it behind such a proxy.
    const xff = TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    const ip = xff || req.socket.remoteAddress || '';
    const origin = req.headers.origin || '';
    const key = req.headers['sec-websocket-key'];
    const reject = (code) => { sock.end(`HTTP/1.1 ${code} No\r\nConnection: close\r\n\r\n`); };
    if (req.url !== '/ws' || !key || req.headers.upgrade?.toLowerCase() !== 'websocket') return reject(400);
    if (origin && !origins.includes(origin)) return reject(403);
    if ((ipCount.get(ip) || 0) >= MAX_CONN_PER_IP) return reject(429);
    ipCount.set(ip, (ipCount.get(ip) || 0) + 1);
    const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    sock.setNoDelay(true);
    sockets.add(sock); sock.on('close', () => sockets.delete(sock));
    const c = new Conn(sock, ip, limits);
    const hb = setInterval(() => {
      if (!c.alive) { clearInterval(hb); return sock.destroy(); }
      c.alive = false; sendFrame(sock, 0x9, Buffer.alloc(0));
    }, 30e3);
    sock.on('close', () => clearInterval(hb));
  });

  const closeHttp = server.close.bind(server);
  server.close = (cb) => { for (const s of sockets) s.destroy(); return closeHttp(cb); };

  server.stats = core.stats;
  server.nightlyPurge = core.nightlyPurge;
  const sweeper = setInterval(core.sweep, 60e3); sweeper.unref();
  server.on('close', () => clearInterval(sweeper));
  scheduleNightly(core);
  if (!turnTimer) { refreshTurn(); turnTimer = setInterval(refreshTurn, 3600e3); turnTimer.unref(); }
  return new Promise((ok) => server.listen(port, host, () => ok(server)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startRelay().then((s) => console.log(`WeKoNet relay listening on ${HOST}:${s.address().port}`));
}
