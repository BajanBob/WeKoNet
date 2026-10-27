// Token beacons: the ONLY way a WeKoNet call starts.
//
// A beacon is a link such as
//     https://wekonet.app/b/#v1.<256-bit key>.<AES-256-GCM ciphertext>
// sent over WhatsApp (or any messenger). Everything after "#" is a URL
// fragment, which browsers and apps never transmit to any server — so the
// relay never sees the key, the room, or who sent the invite.
//
// The sealed payload carries the inviter's identity key + signature, so the
// person who taps the link can detect a relay trying to impersonate the inviter.
import { te, td, lp, b64u, unb64u, randomBytes, sha384 } from './util.js';
import { hkdf384, aesKey, seal, open } from './aead.js';
import { sign, verify, wekonetId } from './identity.js';

// How long the connection may stay open / be re-joined with the same beacon.
// 'end' = the beacon dies as soon as the call ends (default).
export const LINGER = { end: 0, '1h': 3600e3, '2h': 7200e3, day: 86400e3, live: Infinity };
export const MODES = ['voice', 'video', 'chat', 'sos'];
const AAD = te.encode('WeKoNet beacon v1');
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

export async function createBeacon({
  identity, signalUrl, appBase = 'https://wekonet.app/b/', mode = 'video',
  linger = 'end', ttlMinutes = 30, maxPeers = 2, label = '',
}) {
  if (!MODES.includes(mode)) throw new Error('bad mode');
  if (!(linger in LINGER)) throw new Error('bad linger');
  if (maxPeers < 2 || maxPeers > 3) throw new Error('WeKoNet calls are limited to 3 people');
  const beaconKey = randomBytes(32); // AES-256
  const now = Date.now();
  const payload = {
    v: 1, room: b64u(randomBytes(16)), sig: signalUrl, from: b64u(identity.pub),
    fromId: identity.id, mode, linger, max: maxPeers, iat: now,
    exp: now + ttlMinutes * 60e3, label: String(label).slice(0, 40),
  };
  const body = JSON.stringify(payload);
  const s = b64u(await sign(identity.privateKey, lp('beacon', body)));
  const ct = await seal(await aesKey(beaconKey), te.encode(JSON.stringify({ body, s })), AAD);
  const fragment = `v1.${b64u(beaconKey)}.${b64u(ct)}`;
  return {
    link: `${appBase}#${fragment}`,
    deepLink: `wekonet://b#${fragment}`,
    payload, beaconKey, keys: await roomKeys(beaconKey),
  };
}

/** Parse + decrypt + verify a beacon link. Throws on any tampering or expiry. */
export async function openBeacon(linkOrFragment, now = Date.now()) {
  const frag = String(linkOrFragment).split('#').pop().trim();
  const m = /^v1\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{40,4000})$/.exec(frag);
  if (!m) throw new Error('Not a WeKoNet beacon');
  const beaconKey = unb64u(m[1]);
  const pt = await open(await aesKey(beaconKey), unb64u(m[2]), AAD).catch(() => {
    throw new Error('Beacon is corrupted or was tampered with');
  });
  const { body, s } = JSON.parse(td.decode(pt));
  const payload = JSON.parse(body);
  const from = unb64u(payload.from);
  if (!(await verify(from, unb64u(s), lp('beacon', body)))) throw new Error('Beacon signature invalid');
  if ((await wekonetId(from)) !== payload.fromId) throw new Error('Beacon identity mismatch');
  if (now > payload.exp) throw new Error('This beacon has expired');
  if (!MODES.includes(payload.mode) || !(payload.linger in LINGER)) throw new Error('bad beacon fields');
  if (!/^wss:\/\//.test(payload.sig) && !/^ws:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(payload.sig)) {
    throw new Error('Beacon relay must use wss:// (TLS)');
  }
  return { payload, beaconKey, inviterPub: from, keys: await roomKeys(beaconKey) };
}
