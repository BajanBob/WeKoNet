// Run: node --test tests/
// The ML-KEM provider is swapped for a TEST-ONLY stand-in here so the protocol
// logic can be tested offline. When dependencies are installed (CI), the real
// @noble/post-quantum ML-KEM-768 is used automatically.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setKemProvider } from '../src/crypto/kex.js';
import { generateIdentity, safetyNumber, sign, verify } from '../src/crypto/identity.js';
import { initiate, respond } from '../src/crypto/handshake.js';
import { createBeacon, openBeacon } from '../src/crypto/beacon.js';
import { Chain, encryptMsg, decryptMsg } from '../src/crypto/ratchet.js';
import { b64u, unb64u, randomBytes } from '../src/crypto/util.js';
import { FrameCrypter } from '../src/crypto/frames.js';

let useRealKem = false;
try {
  const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
  setKemProvider(ml_kem768); useRealKem = true;
} catch {
  setKemProvider({ // INSECURE stand-in, tests only
    keygen() { const sk = randomBytes(32); const pk = new Uint8Array(1184); pk.set(sk); return { publicKey: pk, secretKey: sk }; },
    encapsulate(pk) { const ss = randomBytes(32); const ct = new Uint8Array(1088); for (let i = 0; i < 32; i++) ct[i] = ss[i] ^ pk[i]; return { cipherText: ct, sharedSecret: ss }; },
    decapsulate(ct, sk) { const ss = new Uint8Array(32); for (let i = 0; i < 32; i++) ss[i] = ct[i] ^ sk[i]; return ss; },
  });
}
console.log(`ML-KEM-768 provider: ${useRealKem ? '@noble/post-quantum (real)' : 'test stand-in'}`);

const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));

async function fullHandshake(opts = {}) {
  const A = await generateIdentity(), B = await generateIdentity();
  const room = 'room-1';
  const i = await initiate({ identity: A, room });
  const r = await respond({ identity: B, room, hello: i.hello, expectPeer: A.pub });
  const { finish, session: sA } = await i.onReply(opts.tamperReply ? opts.tamperReply(r.reply) : r.reply);
  const sB = await r.onFinish(finish);
  return { A, B, sA, sB };
}

test('identity: WKN id format and P-384 signatures', async () => {
  const id = await generateIdentity();
  assert.match(id.id, /^WKN-[A-Z2-9]{4}(-[A-Z2-9]{4}){3}$/);
  const msg = new TextEncoder().encode('hello');
  const sig = await sign(id.privateKey, msg);
  assert.ok(await verify(id.pub, sig, msg));
  assert.ok(!(await verify(id.pub, sig, new TextEncoder().encode('hellp'))));
});

test('handshake: both sides derive matching, direction-separated keys', async () => {
  const { A, B, sA, sB } = await fullHandshake();
  for (const k of ['chat', 'audio', 'video', 'file', 'signal']) {
    assert.ok(eq(sA.send[k], sB.recv[k]), `${k} I->R`);
    assert.ok(eq(sA.recv[k], sB.send[k]), `${k} R->I`);
    assert.ok(!eq(sA.send[k], sA.recv[k]), `${k} directions differ`);
  }
  assert.ok(!eq(sA.send.chat, sA.send.audio), 'purposes differ');
  assert.equal(sA.sas, sB.sas);
  assert.equal(sA.sas.split(' ').length, 6);
  assert.equal(await safetyNumber(A.pub, B.pub), await safetyNumber(B.pub, A.pub));
});

test('MITM: relay swapping the responder X25519 key is rejected', async () => {
  const evil = await import('../src/crypto/kex.js').then((m) => m.x25519Keypair());
  await assert.rejects(
    fullHandshake({ tamperReply: (r) => ({ ...r, x: b64u(evil.pub) }) }),
    /signature invalid|man-in-the-middle/i,
  );
});

test('MITM: relay swapping the ML-KEM ciphertext is rejected', async () => {
  await assert.rejects(
    fullHandshake({ tamperReply: (r) => { const c = unb64u(r.c); c[5] ^= 1; return { ...r, c: b64u(c) }; } }),
    /signature invalid|man-in-the-middle/i,
  );
});

test('MITM: impostor initiator does not match beacon identity', async () => {
  const realInviter = await generateIdentity(), impostor = await generateIdentity(), B = await generateIdentity();
  const i = await initiate({ identity: impostor, room: 'r' });
  await assert.rejects(respond({ identity: B, room: 'r', hello: i.hello, expectPeer: realInviter.pub }), /man-in-the-middle/);
});

test('MITM: forged key-confirmation MAC is rejected', async () => {
  await assert.rejects(
    fullHandshake({ tamperReply: (r) => { const m = unb64u(r.m); m[0] ^= 1; return { ...r, m: b64u(m) }; } }),
    /signature invalid|man-in-the-middle|confirmation/i,
  );
});

test('beacon: create → open round-trip; tamper, forgery and expiry fail', async () => {
  const id = await generateIdentity();
  const b = await createBeacon({ identity: id, signalUrl: 'wss://relay.example/ws', mode: 'video', linger: '2h', maxPeers: 3 });
  assert.match(b.link, /^https:\/\/wekonet-relay\.onrender\.com\/b\/#v1\./);
  const o = await openBeacon(b.link);
  assert.equal(o.payload.room, b.payload.room);
  assert.equal(o.payload.max, 3);
  assert.equal(o.keys.roomTag, b.keys.roomTag);
  assert.ok(eq(o.inviterPub, id.pub));

  const parts = b.link.split('.');
  const ct = unb64u(parts.at(-1)); ct[20] ^= 1;
  await assert.rejects(openBeacon(parts.slice(0, -1).join('.') + '.' + b64u(ct)), /tampered/);
  await assert.rejects(openBeacon(b.link, Date.now() + 31 * 60e3), /expired/);
  await assert.rejects(openBeacon('https://evil/#v1.abc.def'), /Not a WeKoNet beacon/);
  await assert.rejects(createBeacon({ identity: id, signalUrl: 'wss://x/', maxPeers: 4 }), /3 people/);
});

test('beacon: insecure relay URL refused', async () => {
  const id = await generateIdentity();
  const b = await createBeacon({ identity: id, signalUrl: 'ws://evil.example/ws' });
  await assert.rejects(openBeacon(b.link), /wss/);
});

test('ratchet: in-order, out-of-order, replay and tamper', async () => {
  const { sA, sB } = await fullHandshake();
  const tx = new Chain(sA.send.chat, 'chat'), rx = new Chain(sB.recv.chat, 'chat');
  const m0 = await encryptMsg(tx, 'text', { body: 'hi' });
  const m1 = await encryptMsg(tx, 'text', { body: 'second' });
  const m2 = await encryptMsg(tx, 'sos', { lat: 13.1, lon: -59.6 });
  assert.deepEqual(await decryptMsg(rx, m0), { body: 'hi' });
  assert.deepEqual(await decryptMsg(rx, m2), { lat: 13.1, lon: -59.6 });
  assert.deepEqual(await decryptMsg(rx, m1), { body: 'second' });
  await assert.rejects(decryptMsg(rx, m1), /replayed/);
  const m3 = await encryptMsg(tx, 'text', { body: 'x' });
  await assert.rejects(decryptMsg(rx, { ...m3, k: 'sos' })); // kind is authenticated
});

test('media frames: AES-256-GCM per frame, header kept clear, tamper fails', async () => {
  const key = randomBytes(32);
  const tx = await FrameCrypter.create(key), rx = await FrameCrypter.create(key);
  const frame = randomBytes(500);
  const enc = await tx.encrypt(frame, 10);
  assert.ok(eq(enc.subarray(0, 10), frame.subarray(0, 10)));
  assert.ok(!eq(enc.subarray(10, 500), frame.subarray(10)));
  assert.ok(eq(await rx.decrypt(enc, 10), frame));
  const enc2 = await tx.encrypt(frame, 10);
  assert.ok(!eq(enc, enc2), 'unique IV per frame');
  enc2[50] ^= 1;
  await assert.rejects(rx.decrypt(enc2, 10));
});
