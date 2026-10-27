// Token beacons: the ONLY way a WeKoNet call starts.
//
// A beacon is a link such as
//     https://wekonet-relay.onrender.com/b/#v2.<256-bit key>.<AES-256-GCM ciphertext>
// or, shorter, https://wekonet-relay.onrender.com/b/#s.<128-bit key> (sealed copy kept on the relay)
// sent over WhatsApp (or any messenger). Everything after "#" is a URL
// fragment, which browsers and apps never transmit to any server — so the
// relay never sees the key, the room, or who sent the invite.
//
// The sealed payload carries the inviter's identity key + signature, so the
// person who taps the link can detect a relay trying to impersonate the inviter.
import { te, td, lp, b64u, unb64u, randomBytes, sha384, concat } from './util.js';
import { hkdf384, aesKey, seal, open } from './aead.js';
import { sign, verify, wekonetId } from './identity.js';

// How long the connection may stay open / be re-joined with the same beacon.
// 'end' = the beacon dies as soon as the call ends (default).
export const LINGER = { end: 0, '1h': 3600e3, '2h': 7200e3, day: 86400e3, live: Infinity };
export const MODES = ['voice', 'video', 'chat', 'sos'];
const AAD = te.encode('WeKoNet beacon v1');
const AAD2 = te.encode('WeKoNet beacon v2');
const SALT = new Uint8Array(48);

export async function roomKeys(beaconKey) {
  const tag = await hkdf384(beaconKey, SALT, 'room tag', 16);
  const proof = await hkdf384(beaconKey, SALT, 'join proof', 32);
  const sig = await hkdf384(beaconKey, SALT, 'signaling', 32);
  return {
    roomTag: b64u(tag),
    joinProof: b64u(proof),
    joinHash: b64u(await sha384(proof)), // relay stores only the hash
    sigKey: await aesKey(sig),
  };
}

// ---------- compact v2 encoding ----------
// v2 packs the same signed fields in binary (~340-character links instead of
// ~810): the inviter's P-384 key is point-compressed, the WeKoNet ID is derived
// from the key instead of being sent, and the relay URL is left out when it is
// the app's own default relay.
const LINGERS = Object.keys(LINGER);
const P = 2n ** 384n - 2n ** 128n - 2n ** 96n + 2n ** 32n - 1n;
const B = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn;
const big = (u8) => u8.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
const bytes48 = (n) => { const o = new Uint8Array(48); for (let i = 47; i >= 0; i--) { o[i] = Number(n & 255n); n >>= 8n; } return o; };
function modpow(b, e, m) { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }

export function compressP384(pub) {
  if (pub.length !== 97 || pub[0] !== 4) throw new Error('bad P-384 public key');
  const out = new Uint8Array(49);
  out[0] = 2 | (pub[96] & 1); out.set(pub.subarray(1, 49), 1);
  return out;
}

export function decompressP384(c) {
  if (c.length !== 49 || (c[0] !== 2 && c[0] !== 3)) throw new Error('bad compressed key');
  const x = big(c.subarray(1));
  if (x >= P) throw new Error('bad compressed key');
  const rhs = (((x * x) % P) * x - 3n * x + B) % P;
  const r = ((rhs % P) + P) % P;
  let y = modpow(r, (P + 1n) / 4n, P);
  if ((y * y) % P !== r) throw new Error('not a point on P-384');
  if ((y & 1n) !== BigInt(c[0] & 1)) y = P - y;
  const out = new Uint8Array(97); out[0] = 4; out.set(c.subarray(1), 1); out.set(bytes48(y), 49);
  return out;
}

function packBody(p, defaultRelay) {
  const relay = p.sig === defaultRelay ? null : te.encode(p.sig);
  const label = p.label ? te.encode(p.label).slice(0, 40) : null;
  if (relay && relay.length > 255) throw new Error('relay URL too long');
  const head = new Uint8Array(13);
  const dv = new DataView(head.buffer);
  head[0] = 2; head[1] = MODES.indexOf(p.mode); head[2] = LINGERS.indexOf(p.linger); head[3] = p.max;
  head[4] = (relay ? 1 : 0) | (label ? 2 : 0);
  dv.setUint32(5, Math.floor(p.iat / 1000)); dv.setUint32(9, Math.ceil(p.exp / 1000));
  return concat(head, unb64u(p.room), compressP384(unb64u(p.from)),
    relay ? concat(Uint8Array.of(relay.length), relay) : new Uint8Array(0),
    label ? concat(Uint8Array.of(label.length), label) : new Uint8Array(0));
}

function unpackBody(b, defaultRelay) {
  if (b.length < 13 + 16 + 49 || b[0] !== 2) throw new Error('bad beacon fields');
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const flags = b[4];
  let o = 13;
  const room = b64u(b.subarray(o, o + 16)); o += 16;
  const from = decompressP384(b.subarray(o, o + 49)); o += 49;
  const take = () => { const n = b[o]; const v = td.decode(b.subarray(o + 1, o + 1 + n)); o += 1 + n; return v; };
  const sig = flags & 1 ? take() : defaultRelay;
  const label = flags & 2 ? take() : '';
  if (o !== b.length) throw new Error('bad beacon fields');
  return {
    v: 2, room, sig, from: b64u(from), mode: MODES[b[1]], linger: LINGERS[b[2]], max: b[3],
    iat: dv.getUint32(5) * 1000, exp: dv.getUint32(9) * 1000, label,
  };
}

export async function createBeacon({
  identity, signalUrl, appBase = 'https://wekonet-relay.onrender.com/b/', mode = 'video',
  linger = 'end', ttlMinutes = 30, maxPeers = 2, label = '', defaultRelay = '',
}) {
  if (!MODES.includes(mode)) throw new Error('bad mode');
  if (!Object.hasOwn(LINGER, linger)) throw new Error('bad linger');
  if (maxPeers < 2 || maxPeers > 3) throw new Error('WeKoNet calls are limited to 3 people');
  const beaconKey = randomBytes(32); // AES-256
  const now = Date.now();
  const payload = {
    v: 2, room: b64u(randomBytes(16)), sig: signalUrl, from: b64u(identity.pub),
    fromId: identity.id, mode, linger, max: maxPeers, iat: now,
    exp: now + ttlMinutes * 60e3, label: String(label).slice(0, 40),
  };
  const body = packBody(payload, defaultRelay);
  const s = await sign(identity.privateKey, lp('beacon v2', body));
  const ct = await seal(await aesKey(beaconKey), concat(body, s), AAD2);
  const fragment = `v2.${b64u(beaconKey)}.${b64u(ct)}`;
  return {
    link: `${appBase}#${fragment}`,
    deepLink: `wekonet://b#${fragment}`,
    fragment, payload, beaconKey, keys: await roomKeys(beaconKey),
  };
}

/** Parse + decrypt + verify a beacon link (v2 compact, or v1). Throws on any tampering or expiry. */
export async function openBeacon(linkOrFragment, now = Date.now(), { defaultRelay = '' } = {}) {
  const frag = String(linkOrFragment).split('#').pop().trim();
  const m = /^(v1|v2)\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{40,4000})$/.exec(frag);
  if (!m) throw new Error('Not a WeKoNet beacon');
  const beaconKey = unb64u(m[2]);
  const pt = await open(await aesKey(beaconKey), unb64u(m[3]), m[1] === 'v2' ? AAD2 : AAD).catch(() => {
    throw new Error('Beacon is corrupted or was tampered with');
  });
  let payload, from;
  if (m[1] === 'v2') {
    if (pt.length < 96) throw new Error('bad beacon fields');
    const body = pt.subarray(0, pt.length - 96), s = pt.subarray(pt.length - 96);
    payload = unpackBody(body, defaultRelay);
    from = unb64u(payload.from);
    if (!(await verify(from, s, lp('beacon v2', body)))) throw new Error('Beacon signature invalid');
    payload.fromId = await wekonetId(from);
  } else {
    const { body, s } = JSON.parse(td.decode(pt));
    payload = JSON.parse(body);
    from = unb64u(payload.from);
    if (!(await verify(from, unb64u(s), lp('beacon', body)))) throw new Error('Beacon signature invalid');
    if ((await wekonetId(from)) !== payload.fromId) throw new Error('Beacon identity mismatch');
  }
  if (now > payload.exp) throw new Error('This beacon has expired');
  if (!MODES.includes(payload.mode) || !Object.hasOwn(LINGER, payload.linger) || !(payload.max >= 2 && payload.max <= 3)) throw new Error('bad beacon fields');
  if (!/^wss:\/\//.test(payload.sig || '') && !/^ws:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(payload.sig || '')) {
    throw new Error('Beacon relay must use wss:// (TLS)');
  }
  return { payload, beaconKey, inviterPub: from, keys: await roomKeys(beaconKey) };
}

// ---------- short links ----------
// A short link (#s.<22 chars>) holds a fresh 128-bit key. The full beacon is
// sealed with it and parked on the relay under an ID derived from that key, so
// the relay stores only ciphertext it cannot open and cannot link to the call.
const AADS = te.encode('WeKoNet short link v1');
async function shortKeys(k) {
  return {
    id: b64u(await hkdf384(k, SALT, 'short link id', 12)),
    key: await aesKey(await hkdf384(k, SALT, 'short link key', 32)),
  };
}

/** Seal a full beacon fragment for the relay; returns { code, id, data }. */
export async function sealShort(fragment) {
  const k = randomBytes(16);
  const { id, key } = await shortKeys(k);
  return { code: `s.${b64u(k)}`, id, data: b64u(await seal(key, te.encode(fragment), AADS)) };
}

export function parseShort(linkOrFragment) {
  const m = /^s\.([A-Za-z0-9_-]{22})$/.exec(String(linkOrFragment).split('#').pop().trim());
  return m ? unb64u(m[1]) : null;
}

export async function shortId(k) { return (await shortKeys(k)).id; }

/** Open the ciphertext fetched from the relay → the full beacon fragment. */
export async function openShort(k, data) {
  const { key } = await shortKeys(k);
  const pt = await open(key, unb64u(data), AADS).catch(() => { throw new Error('Short link is corrupted or was tampered with'); });
  return td.decode(pt);
}
