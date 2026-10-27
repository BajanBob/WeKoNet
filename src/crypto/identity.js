// Long-term device identity. No email, no phone number: a person IS their
// ECDSA P-384 public key. The human-readable WeKoNet ID is a hash of it.
import { subtle, sha384, concat, ctEqual } from './util.js';

const ALG = { name: 'ECDSA', namedCurve: 'P-384' };
const SIG = { name: 'ECDSA', hash: 'SHA-384' };
const B32 = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I confusion

export async function generateIdentity() {
  // Private key is created NON-extractable: it can sign but can never be read
  // out by script (including injected script), only stored as a CryptoKey.
  const kp = await subtle.generateKey(ALG, false, ['sign', 'verify']);
  const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, pub, id: await wekonetId(pub) };
}

export async function importPub(raw) {
  if (raw.length !== 97 || raw[0] !== 0x04) throw new Error('bad P-384 public key');
  return subtle.importKey('raw', raw, ALG, true, ['verify']);
}

export async function sign(privateKey, data) {
  return new Uint8Array(await subtle.sign(SIG, privateKey, data));
}

export async function verify(pubRaw, sig, data) {
  const k = await importPub(pubRaw);
  return subtle.verify(SIG, k, sig, data);
}

function base32(bytes, nChars) {
  let bits = 0, val = 0, out = '';
  for (const b of bytes) {
    val = (val << 8) | b; bits += 8;
    while (bits >= 5 && out.length < nChars) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out;
}

/** WKN-XXXX-XXXX-XXXX-XXXX (80 bits of SHA-384(pubkey)). */
export async function wekonetId(pub) {
  const h = await sha384(concat(new TextEncoder().encode('WeKoNet/v1 id'), pub));
  return 'WKN-' + base32(h, 16).match(/.{4}/g).join('-');
}

/**
 * Safety number for two identities (order-independent). Users compare it once
 * in person or over the voice call; after that the contact is pinned and any
 * key change is flagged loudly as a possible man-in-the-middle.
 */
export async function safetyNumber(pubA, pubB) {
  const [x, y] = ctLess(pubA, pubB) ? [pubA, pubB] : [pubB, pubA];
  const h = await sha384(concat(new TextEncoder().encode('WeKoNet/v1 safety'), x, y));
  const groups = [];
  for (let i = 0; i < 12; i++) {
    const n = ((h[i * 2] << 8) | h[i * 2 + 1]) % 100000;
    groups.push(String(n).padStart(5, '0'));
  }
  return groups.join(' ');
}

function ctLess(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] < b[i];
  return a.length < b.length;
}

export function samePub(a, b) { return ctEqual(a, b); }
