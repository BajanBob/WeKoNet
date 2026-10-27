// WeKoNet hybrid authenticated handshake (pairwise; a 3-person call runs 3 of these).
//
//   I → R  HELLO   idPub_I, X25519_I, P384_I, MLKEM768pk_I, nonce_I, sig_I(hello)
//   R → I  REPLY   idPub_R, X25519_R, P384_R, MLKEMct,      nonce_R, sig_R(T), mac_R(T)
//   I → R  FINISH  sig_I(T), mac_I(T)
//
//   IKM  = X25519(ss) ‖ ECDH-P384(ss) ‖ ML-KEM-768(ss)
//   salt = SHA-384(T)            (T = full length-prefixed transcript)
//   keys = HKDF-SHA-384(IKM, salt, label) — one independent key per purpose & direction
//
// MITM defences:
//   1. Both sides SIGN the full transcript with their long-term P-384 identity
//      (binds identities to the ephemeral keys → no key substitution / UKS).
//   2. Key-confirmation MACs prove both derived the same secret.
//   3. The responder already knows the initiator's identity from the beacon
//      (delivered out-of-band via WhatsApp), so a malicious relay cannot pose as I.
//   4. A short authentication string (SAS) is shown on both screens and read aloud.
//   5. Known contacts are pinned; a changed identity key aborts the call.
import { subtle, te, lp, b64u, unb64u, randomBytes, concat, sha384, ctEqual, wipe } from './util.js';
import { hkdf384, hmacKey } from './aead.js';
import { sign, verify, samePub } from './identity.js';
import {
  x25519Keypair, p384Keypair, mlkemKeypair, mlkemEncapsulate,
} from './kex.js';

const V = 1;

const SAS_WORDS = [
  'anchor', 'banjo', 'cactus', 'dolphin', 'eagle', 'falcon', 'guitar', 'harbor',
  'igloo', 'jaguar', 'kettle', 'lantern', 'mango', 'nectar', 'orchid', 'pepper',
  'quartz', 'rocket', 'saddle', 'tiger', 'umbrella', 'violet', 'walnut', 'yacht',
  'zebra', 'amber', 'bamboo', 'canyon', 'desert', 'ember', 'forest', 'glacier',
  'hammock', 'island', 'jungle', 'koala', 'lemon', 'meadow', 'nutmeg', 'ocean',
  'parrot', 'quiver', 'river', 'sunset', 'thunder', 'tulip', 'valley', 'willow',
  'yogurt', 'zephyr', 'apricot', 'breeze', 'coral', 'dragon', 'emerald', 'fig',
  'garnet', 'hazel', 'indigo', 'jasmine', 'kiwi', 'lotus', 'marble', 'nova',
];

function sasFromBytes(b) {
  const words = [];
  let acc = 0, bits = 0;
  for (const byte of b) {
    acc = (acc << 8) | byte; bits += 8;
    while (bits >= 6 && words.length < 6) { words.push(SAS_WORDS[(acc >>> (bits - 6)) & 63]); bits -= 6; }
  }
  return words.join(' ');
}

const helloFields = (h) => ['hello', h.room, unb64u(h.id), unb64u(h.x), unb64u(h.p), unb64u(h.k), unb64u(h.n)];
const replyFields = (r) => ['reply', unb64u(r.id), unb64u(r.x), unb64u(r.p), unb64u(r.c), unb64u(r.n)];

async function transcriptHash(hello, reply) {
  return sha384(lp(`WeKoNet/v${V} handshake`, ...helloFields(hello), ...replyFields(reply)));
}

async function deriveSession(ikm, th, role, peerPub) {
  const k = async (label, n = 32) => hkdf384(ikm, th, label, n);
  const raw = {
    chatIR: await k('chat I->R'), chatRI: await k('chat R->I'),
    audioIR: await k('audio I->R'), audioRI: await k('audio R->I'),
    videoIR: await k('video I->R'), videoRI: await k('video R->I'),
    fileIR: await k('file I->R'), fileRI: await k('file R->I'),
    sigIR: await k('signal I->R'), sigRI: await k('signal R->I'),
    confI: await k('confirm I'), confR: await k('confirm R'),
    sas: await k('sas', 6),
    pair: await k('pair'),
  };
  wipe(ikm);
  const I = role === 'I';
  return {
    role,
    peerPub,
    transcriptHash: th,
    sas: sasFromBytes(raw.sas),
    send: { chat: I ? raw.chatIR : raw.chatRI, audio: I ? raw.audioIR : raw.audioRI, video: I ? raw.videoIR : raw.videoRI, file: I ? raw.fileIR : raw.fileRI, signal: I ? raw.sigIR : raw.sigRI },
    recv: { chat: I ? raw.chatRI : raw.chatIR, audio: I ? raw.audioRI : raw.audioIR, video: I ? raw.videoRI : raw.videoIR, file: I ? raw.fileRI : raw.fileIR, signal: I ? raw.sigRI : raw.sigIR },
    confirmMine: await hmacKey(I ? raw.confI : raw.confR),
    confirmPeer: await hmacKey(I ? raw.confR : raw.confI),
    pairSecret: raw.pair, // only persisted if both users choose "keep"
  };
}

async function mac(key, th) { return new Uint8Array(await subtle.sign('HMAC', key, th)); }
async function checkMac(key, th, tag) {
  const ok = await subtle.verify('HMAC', key, tag, th);
  if (!ok) throw new Error('Key confirmation failed — possible man-in-the-middle');
}

function checkPin(expectPeer, gotPub) {
  if (expectPeer && !samePub(expectPeer, gotPub)) {
    throw new Error('Peer identity does not match the beacon / pinned contact — possible man-in-the-middle. Call aborted.');
  }
}

/** Initiator side. */
export async function initiate({ identity, room, expectPeer = null }) {
  const [x, p, k] = await Promise.all([x25519Keypair(), p384Keypair(), mlkemKeypair()]);
  const n = randomBytes(32);
  const hello = { t: 'hello', v: V, room, id: b64u(identity.pub), x: b64u(x.pub), p: b64u(p.pub), k: b64u(k.pub), n: b64u(n) };
  hello.s = b64u(await sign(identity.privateKey, lp(...helloFields(hello))));

  async function onReply(reply) {
    if (reply.t !== 'reply' || reply.v !== V) throw new Error('unexpected handshake message');
    const peerPub = unb64u(reply.id);
    checkPin(expectPeer, peerPub);
    const th = await transcriptHash(hello, reply);
    if (!(await verify(peerPub, unb64u(reply.s), lp('sig reply', th)))) throw new Error('Responder signature invalid — possible man-in-the-middle');
    const ikm = concat(
      await x.derive(unb64u(reply.x)),
      await p.derive(unb64u(reply.p)),
      await k.decapsulate(unb64u(reply.c)),
    );
    const session = await deriveSession(ikm, th, 'I', peerPub);
    await checkMac(session.confirmPeer, th, unb64u(reply.m));
    const finish = {
      t: 'finish', v: V,
      s: b64u(await sign(identity.privateKey, lp('sig finish', th))),
      m: b64u(await mac(session.confirmMine, th)),
    };
    return { finish, session };
  }
  return { hello, onReply };
}

/** Responder side. `expectPeer` = initiator identity sealed inside the beacon. */
export async function respond({ identity, room, hello, expectPeer = null }) {
  if (hello.t !== 'hello' || hello.v !== V) throw new Error('unexpected handshake message');
  if (hello.room !== room) throw new Error('handshake for a different room');
  const peerPub = unb64u(hello.id);
  checkPin(expectPeer, peerPub);
  if (!(await verify(peerPub, unb64u(hello.s), lp(...helloFields(hello))))) {
    throw new Error('Initiator signature invalid — possible man-in-the-middle');
  }
  const [x, p] = await Promise.all([x25519Keypair(), p384Keypair()]);
  const enc = await mlkemEncapsulate(unb64u(hello.k));
  const n = randomBytes(32);
  const reply = { t: 'reply', v: V, id: b64u(identity.pub), x: b64u(x.pub), p: b64u(p.pub), c: b64u(enc.ct), n: b64u(n) };
  const th = await transcriptHash(hello, reply);
  const ikm = concat(await x.derive(unb64u(hello.x)), await p.derive(unb64u(hello.p)), enc.ss);
  const session = await deriveSession(ikm, th, 'R', peerPub);
  reply.s = b64u(await sign(identity.privateKey, lp('sig reply', th)));
  reply.m = b64u(await mac(session.confirmMine, th));

  async function onFinish(fin) {
    if (fin.t !== 'finish' || fin.v !== V) throw new Error('unexpected handshake message');
    if (!(await verify(peerPub, unb64u(fin.s), lp('sig finish', th)))) throw new Error('Initiator transcript signature invalid — possible man-in-the-middle');
    await checkMac(session.confirmPeer, th, unb64u(fin.m));
    return session;
  }
  return { reply, onFinish };
}

export { ctEqual, te };
