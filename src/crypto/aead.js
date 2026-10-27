// AES-256-GCM + HKDF-SHA-384 primitives (WebCrypto only).
import { subtle, te, randomBytes, concat } from './util.js';

const PROTO = 'WeKoNet/v1';

/** HKDF-SHA-384 → raw bytes. `info` is always namespaced with the protocol id. */
export async function hkdf384(ikm, salt, info, length = 32) {
  const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-384', salt, info: te.encode(`${PROTO} ${info}`) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** Import 32 raw bytes as a NON-extractable AES-256-GCM key. */
export function aesKey(raw, usages = ['encrypt', 'decrypt']) {
  if (raw.length !== 32) throw new Error('AES-256 key must be 32 bytes');
  return subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, usages);
}

export async function hmacKey(raw) {
  return subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-384' }, false, ['sign', 'verify']);
}

/** Seal with a fresh random 96-bit IV. Output = iv || ciphertext+tag. */
export async function seal(key, plaintext, aad = new Uint8Array(0)) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plaintext),
  );
  return concat(iv, ct);
}

export async function open(key, sealed, aad = new Uint8Array(0)) {
  if (sealed.length < 12 + 16) throw new Error('ciphertext too short');
  const iv = sealed.subarray(0, 12);
  const ct = sealed.subarray(12);
  return new Uint8Array(
    await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, ct),
  );
}

export async function sealJSON(key, obj, aad) {
  return seal(key, te.encode(JSON.stringify(obj)), aad);
}

export async function openJSON(key, sealed, aad) {
  return JSON.parse(new TextDecoder().decode(await open(key, sealed, aad)));
}
