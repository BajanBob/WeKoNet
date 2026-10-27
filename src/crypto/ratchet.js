// Symmetric hash ratchet for chat / location / SOS messages.
// Every message gets a fresh AES-256-GCM key; old chain keys are wiped,
// so a device seized later cannot decrypt earlier traffic (forward secrecy).
//
// Hardening: the receiving chain only advances AFTER a message authenticates.
// A forged or corrupted message (e.g. claiming counter n+200) is rejected
// without touching the chain, so it cannot burn keys or block later messages.
import { lp, b64u, unb64u, wipe } from './util.js';
import { hkdf384, aesKey, seal, open } from './aead.js';

const EMPTY = new Uint8Array(48);
const MAX_SKIP = 256;       // max gap between consecutive received messages
const MAX_STORED = 1024;    // max skipped keys kept for late messages

async function kdf(ck, label) {
  return {
    mk: await hkdf384(ck, EMPTY, `${label} msg`),
    next: await hkdf384(ck, EMPTY, `${label} chain`),
  };
}

export class Chain {
  constructor(chainKey, label) { this.ck = chainKey.slice(); this.n = 0; this.label = label; this.skipped = new Map(); }

  async step() {
    const { mk, next } = await kdf(this.ck, this.label);
    wipe(this.ck);
    this.ck = next;
    return { n: this.n++, mk };
  }

  destroy() { wipe(this.ck); for (const k of this.skipped.values()) wipe(k); this.skipped.clear(); }
}

export async function encryptMsg(chain, kind, obj) {
  const { n, mk } = await chain.step();
  const key = await aesKey(mk); wipe(mk);
  const body = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await seal(key, body, lp(chain.label, kind, String(n)));
  return { k: kind, n, c: b64u(ct) };
}

async function tryOpen(chain, mk, kind, n, c) {
  const key = await aesKey(mk);
  const pt = await open(key, unb64u(c), lp(chain.label, kind, String(n)));
  return JSON.parse(new TextDecoder().decode(pt));
}

export async function decryptMsg(chain, env) {
  if (!env || typeof env !== 'object') throw new Error('bad envelope');
  const { k: kind, n, c } = env;
  if (typeof kind !== 'string' || kind.length > 16) throw new Error('bad kind');
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('bad counter');
  if (typeof c !== 'string' || c.length > 200000) throw new Error('bad ciphertext');

  // Late (out-of-order) message: use its stored key, delete only on success.
  if (n < chain.n) {
    const mk = chain.skipped.get(n);
    if (!mk) throw new Error('replayed or expired message');
    const obj = await tryOpen(chain, mk, kind, n, c);
    chain.skipped.delete(n); wipe(mk);
    return obj;
  }
  if (n - chain.n > MAX_SKIP) throw new Error('too many skipped messages');

  // Future message: derive on a scratch copy; commit only if it authenticates.
  let ck = chain.ck.slice();
  const pending = [];
  for (let i = chain.n; i < n; i++) {
    const { mk, next } = await kdf(ck, chain.label);
    pending.push([i, mk]); wipe(ck); ck = next;
  }
  const { mk, next } = await kdf(ck, chain.label);
  let obj;
  try {
    obj = await tryOpen(chain, mk, kind, n, c);
  } catch (e) {
    wipe(ck, next, mk); for (const [, k] of pending) wipe(k);
    throw e;
  }
  // commit
  wipe(chain.ck, ck, mk);
  chain.ck = next; chain.n = n + 1;
  for (const [i, k] of pending) chain.skipped.set(i, k);
  while (chain.skipped.size > MAX_STORED) {
    const oldest = chain.skipped.keys().next().value;
    wipe(chain.skipped.get(oldest)); chain.skipped.delete(oldest);
  }
  return obj;
}
