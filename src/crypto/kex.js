// Key-exchange primitives for the hybrid handshake:
//   • X25519            (classical, fast)
//   • ECDH P-384        (classical, NIST / CNSA-aligned)
//   • ML-KEM-768        (post-quantum, FIPS 203)
// The session secret is safe as long as ANY ONE of the three holds.
import { subtle } from './util.js';

// ---------- X25519 ----------
let nobleX = null;
async function noble25519() {
  if (!nobleX) nobleX = (await import('@noble/curves/ed25519.js')).x25519;
  return nobleX;
}

export async function x25519Keypair() {
  try {
    const kp = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
    return { pub, derive: (peer) => x25519DeriveWebCrypto(kp.privateKey, peer) };
  } catch {
    // Older WebViews without WebCrypto X25519 → audited constant-time JS impl.
    const x = await noble25519();
    const sk = x.utils.randomSecretKey ? x.utils.randomSecretKey() : x.utils.randomPrivateKey();
    const pub = x.getPublicKey(sk);
    return { pub, derive: async (peer) => { const s = x.getSharedSecret(sk, peer); sk.fill(0); return s; } };
  }
}

async function x25519DeriveWebCrypto(priv, peerRaw) {
  if (peerRaw.length !== 32) throw new Error('bad X25519 key');
  const peer = await subtle.importKey('raw', peerRaw, { name: 'X25519' }, false, []);
  const ss = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: peer }, priv, 256));
  if (ss.every((b) => b === 0)) throw new Error('X25519 low-order point rejected');
  return ss;
}

// ---------- ECDH P-384 ----------
export async function p384Keypair() {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveBits']);
  const pub = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  return {
    pub,
    derive: async (peerRaw) => {
      if (peerRaw.length !== 97 || peerRaw[0] !== 0x04) throw new Error('bad P-384 key');
      // importKey validates the point is on the curve (rejects invalid-curve attacks).
      const peer = await subtle.importKey('raw', peerRaw, { name: 'ECDH', namedCurve: 'P-384' }, false, []);
      return new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: peer }, kp.privateKey, 384));
    },
  };
}

// ---------- ML-KEM-768 ----------
let kemProvider = null;

/** Tests may inject a provider; production lazily loads @noble/post-quantum. */
export function setKemProvider(p) { kemProvider = p; }

async function kem() {
  if (!kemProvider) {
    const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
    kemProvider = ml_kem768;
  }
  return kemProvider;
}

export const MLKEM768_PK_LEN = 1184;
export const MLKEM768_CT_LEN = 1088;

export async function mlkemKeypair() {
  const k = await kem();
  const { publicKey, secretKey } = k.keygen();
  return {
    pub: publicKey,
    decapsulate: async (ct) => {
      if (ct.length !== MLKEM768_CT_LEN) throw new Error('bad ML-KEM-768 ciphertext');
      const ss = k.decapsulate(ct, secretKey);
      secretKey.fill(0);
      return ss;
    },
  };
}

export async function mlkemEncapsulate(pub) {
  if (pub.length !== MLKEM768_PK_LEN) throw new Error('bad ML-KEM-768 public key');
  const k = await kem();
  const { cipherText, sharedSecret } = k.encapsulate(pub);
  return { ct: cipherText, ss: sharedSecret };
}
