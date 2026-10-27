// WeKoNet — byte/encoding helpers shared by every crypto module.
// No DOM access here so the crypto layer can be unit-tested in Node.

export const subtle = globalThis.crypto.subtle;
export const te = new TextEncoder();
export const td = new TextDecoder();

export function randomBytes(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export function concat(...parts) {
  const len = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** Length-prefixed concatenation: unambiguous transcript encoding. */
export function lp(...parts) {
  const chunks = [];
  for (const p of parts) {
    const b = typeof p === 'string' ? te.encode(p) : p;
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, b.length);
    chunks.push(len, b);
  }
  return concat(...chunks);
}

export function b64u(bytes) {
  let s = '';
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64u(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('bad base64url');
  const s = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Constant-time comparison for MACs / fingerprints. */
export function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function wipe(...arrs) {
  for (const a of arrs) if (a && a.fill) a.fill(0);
}

export async function sha384(bytes) {
  return new Uint8Array(await subtle.digest('SHA-384', bytes));
}
