// Symmetric hash ratchet for chat / location / SOS messages.
// Every message gets a fresh AES-256-GCM key; old chain keys are wiped,
// so a device seized later cannot decrypt earlier traffic (forward secrecy).
import { lp, b64u, unb64u, wipe } from './util.js';
import { hkdf384, aesKey, seal, open } from './aead.js';

const EMPTY = new Uint8Array(48);
const MAX_SKIP = 256;

export class Chain {
  constructor(chainKey, label) { this.ck = chainKey.slice(); this.n = 0; this.label = label; this.skipped = new Map(); }

  async step() {
    const mk = await hkdf384(this.ck, EMPTY, `${this.label} msg`);
    const next = await hkdf384(this.ck, EMPTY, `${this.label} chain`);
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

export async function decryptMsg(chain, env) {
  const { k: kind, n, c } = env;
  if (!Number.isInteger(n) || n < 0) throw new Error('bad counter');
  let mk;
  if (n < chain.n) {
    mk = chain.skipped.get(n);
    if (!mk) throw new Error('replayed or expired message');
    chain.skipped.delete(n);
  } else {
    if (n - chain.n > MAX_SKIP) throw new Error('too many skipped messages');
    while (chain.n < n) { const s = await chain.step(); chain.skipped.set(s.n, s.mk); }
    mk = (await chain.step()).mk;
  }
  const key = await aesKey(mk); wipe(mk);
  const pt = await open(key, unb64u(c), lp(chain.label, kind, String(n)));
  return JSON.parse(new TextDecoder().decode(pt));
}
