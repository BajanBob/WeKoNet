// HARD tests: mutation fuzzing of every protocol message. The rule is simple:
// any change to any byte of any field must be REJECTED — never accepted,
// never crash with an unhandled error type, never silently produce keys.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setKemProvider, x25519Keypair, p384Keypair } from '../src/crypto/kex.js';
import { generateIdentity } from '../src/crypto/identity.js';
import { initiate, respond } from '../src/crypto/handshake.js';
import { createBeacon, openBeacon } from '../src/crypto/beacon.js';
import { Chain, encryptMsg, decryptMsg } from '../src/crypto/ratchet.js';
import { FrameCrypter } from '../src/crypto/frames.js';
import { contactLinks, sealMail, openMail } from '../src/crypto/contact.js';
import { b64u, unb64u, randomBytes, te, lp } from '../src/crypto/util.js';
import { aesKey, seal } from '../src/crypto/aead.js';

try {
  const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js');
  setKemProvider(ml_kem768);
} catch {
  setKemProvider({ // test stand-in when offline; CI uses the real ML-KEM-768
    keygen() { const sk = randomBytes(32); const pk = new Uint8Array(1184); pk.set(sk); return { publicKey: pk, secretKey: sk }; },
    encapsulate(pk) { const ss = randomBytes(32); const ct = new Uint8Array(1088); for (let i = 0; i < 32; i++) ct[i] = ss[i] ^ pk[i]; return { cipherText: ct, sharedSecret: ss }; },
    decapsulate(ct, sk) { const ss = new Uint8Array(32); for (let i = 0; i < 32; i++) ss[i] = ct[i] ^ sk[i]; return ss; },
  });
}

const ITER = +process.env.FUZZ_ITER || 40;
const rint = (n) => Math.floor(Math.random() * n);
const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));

/** Mutate one field of a message in one of many hostile ways. */
function mutate(msg, field) {
  const m = { ...msg };
  const v = m[field];
  const ways = [
    () => { delete m[field]; },
    () => { m[field] = null; },
    () => { m[field] = 12345; },
    () => { m[field] = {}; },
    () => { m[field] = ''; },
    () => { m[field] = 'A'.repeat(5000); },
    () => { m[field] = '!!not-base64!!'; },
  ];
  if (typeof v === 'string' && /^[A-Za-z0-9_-]+$/.test(v)) {
    ways.push(
      () => { const b = unb64u(v); if (!b.length) return; b[rint(b.length)] ^= 1 << rint(8); m[field] = b64u(b); }, // single bit flip
      () => { const b = unb64u(v); m[field] = b64u(b.subarray(0, Math.max(0, b.length - 1 - rint(8)))); }, // truncate
      () => { const b = unb64u(v); m[field] = b64u(new Uint8Array([...b, rint(256)])); }, // extend
      () => { m[field] = b64u(randomBytes(unb64u(v).length)); }, // same-length random
    );
  }
  if (typeof v === 'number') ways.push(() => { m[field] = v + 1; });
  if (field === 'room' || field === 't') ways.push(() => { m[field] = v + 'x'; });
  try { ways[rint(ways.length)](); } catch { m[field] = 'Z' + String(v); }
  return m;
}

async function pair() {
  const A = await generateIdentity(), B = await generateIdentity();
  return { A, B, room: b64u(randomBytes(16)) };
}

test(`fuzz HELLO: ${ITER} mutations per field are all rejected by the responder`, async () => {
  const { A, B, room } = await pair();
  const i = await initiate({ identity: A, room });
  for (const field of Object.keys(i.hello)) {
    for (let n = 0; n < ITER; n++) {
      const bad = mutate(i.hello, field);
      if (JSON.stringify(bad) === JSON.stringify(i.hello)) continue;
      await assert.rejects(respond({ identity: B, room, hello: bad, expectPeer: A.pub }), `hello.${field} mutation accepted: ${JSON.stringify(bad[field])?.slice(0, 60)}`);
    }
  }
});

test(`fuzz REPLY: ${ITER} mutations per field are all rejected by the initiator`, async () => {
  const { A, B, room } = await pair();
  for (const field of ['t', 'v', 'id', 'x', 'p', 'c', 'n', 's', 'm']) {
    for (let n = 0; n < ITER; n++) {
      const i = await initiate({ identity: A, room });
      const r = await respond({ identity: B, room, hello: i.hello });
      const bad = mutate(r.reply, field);
      if (JSON.stringify(bad) === JSON.stringify(r.reply)) continue;
      await assert.rejects(i.onReply(bad), `reply.${field} mutation accepted`);
    }
  }
});

test(`fuzz FINISH: ${ITER} mutations per field are all rejected by the responder`, async () => {
  const { A, B, room } = await pair();
  const i = await initiate({ identity: A, room });
  const r = await respond({ identity: B, room, hello: i.hello });
  const { finish } = await i.onReply(r.reply);
  for (const field of ['t', 'v', 's', 'm']) {
    for (let n = 0; n < ITER; n++) {
      const bad = mutate(finish, field);
      if (JSON.stringify(bad) === JSON.stringify(finish)) continue;
      await assert.rejects(r.onFinish(bad), `finish.${field} mutation accepted`);
    }
  }
  await r.onFinish(finish); // the genuine one still works
});

test('splice attacks: replies / finishes from a different session are rejected', async () => {
  const { A, B, room } = await pair();
  const i1 = await initiate({ identity: A, room }), i2 = await initiate({ identity: A, room });
  const r1 = await respond({ identity: B, room, hello: i1.hello });
  const r2 = await respond({ identity: B, room, hello: i2.hello });
  await assert.rejects(i1.onReply(r2.reply), 'reply from session 2 accepted by session 1');
  const { finish: f2 } = await i2.onReply(r2.reply);
  await assert.rejects(r1.onFinish(f2), 'finish from session 2 accepted by session 1');
  // Responder's own transcript signature reflected back as the initiator's finish
  await assert.rejects(r1.onFinish({ t: 'finish', v: 1, s: r1.reply.s, m: r1.reply.m }), 'reflection accepted');
  // hello for another room
  await assert.rejects(respond({ identity: B, room: room + 'x', hello: i1.hello }), /different room/);
});

test('third party with its own valid identity cannot impersonate a pinned peer', async () => {
  const { A, B, room } = await pair();
  const Mallory = await generateIdentity();
  const i = await initiate({ identity: A, room, expectPeer: B.pub });
  const evil = await respond({ identity: Mallory, room, hello: i.hello });
  await assert.rejects(i.onReply(evil.reply), /man-in-the-middle/);
});

test('invalid curve points: X25519 low-order and off-curve P-384 keys are rejected', async () => {
  const x = await x25519Keypair();
  const lowOrder = [new Uint8Array(32), Uint8Array.from([1, ...new Array(31).fill(0)])];
  for (const pt of lowOrder) await assert.rejects(x.derive(pt));
  const p = await p384Keypair();
  const offCurve = new Uint8Array(97); offCurve[0] = 4; offCurve.fill(7, 1);
  await assert.rejects(p.derive(offCurve));
  await assert.rejects(p.derive(new Uint8Array(96)));
});

test('key separation: 30 sessions → every derived key unique, both directions agree', async () => {
  const seen = new Set();
  for (let n = 0; n < 30; n++) {
    const { A, B, room } = await pair();
    const i = await initiate({ identity: A, room });
    const r = await respond({ identity: B, room, hello: i.hello });
    const { finish, session: sa } = await i.onReply(r.reply);
    const sb = await r.onFinish(finish);
    for (const k of ['chat', 'audio', 'video', 'file', 'signal']) {
      assert.ok(eq(sa.send[k], sb.recv[k]) && eq(sa.recv[k], sb.send[k]));
      for (const key of [sa.send[k], sa.recv[k]]) {
        const h = b64u(key);
        assert.ok(!seen.has(h), 'derived key repeated'); seen.add(h);
      }
    }
    assert.equal(sa.sas, sb.sas);
  }
  assert.equal(seen.size, 30 * 10);
});

test(`fuzz BEACON: ${ITER * 5} random corruptions of the link are all rejected`, async () => {
  const id = await generateIdentity();
  const b = await createBeacon({ identity: id, signalUrl: 'wss://relay.example/ws' });
  const frag = b.link.split('#')[1];
  for (let n = 0; n < ITER * 5; n++) {
    const chars = [...frag];
    const pos = 3 + rint(chars.length - 3);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.#%<>"\'';
    const choice = rint(4);
    if (choice === 0) chars[pos] = alphabet[rint(alphabet.length)];
    else if (choice === 1) chars.splice(pos, 1 + rint(5));
    else if (choice === 2) chars.splice(pos, 0, alphabet[rint(alphabet.length)]);
    else chars.length = pos;
    const bad = chars.join('');
    if (bad === frag) continue;
    let accepted = false;
    try { await openBeacon('https://x/b/#' + bad); accepted = true; } catch { /* expected */ }
    // Base64url has 0-4 "don't care" low bits in the last char; only a decode
    // to the IDENTICAL bytes may succeed.
    if (accepted) {
      const [, k1, c1] = frag.split('.'); const [, k2, c2] = bad.split('.');
      assert.ok(eq(unb64u(k1), unb64u(k2)) && eq(unb64u(c1), unb64u(c2)), `corrupted beacon accepted: ${bad.slice(0, 50)}`);
    }
  }
});

test('beacon: someone holding the link cannot redirect it to their own relay or re-sign it', async () => {
  const inviter = await generateIdentity(), mallory = await generateIdentity();
  const b = await createBeacon({ identity: inviter, signalUrl: 'wss://good.example/ws' });
  const key = await aesKey(b.beaconKey);
  const { sign } = await import('../src/crypto/identity.js');
  const reseal = async (obj) => `https://x/#v1.${b64u(b.beaconKey)}.${b64u(await seal(key, te.encode(JSON.stringify(obj)), te.encode('WeKoNet beacon v1')))}`;

  // 1. change relay, keep inviter's signature
  const evilBody = JSON.stringify({ ...b.payload, sig: 'wss://evil.example/ws' });
  const origSig = b64u(await sign(inviter.privateKey, lp('beacon', JSON.stringify(b.payload))));
  await assert.rejects(openBeacon(await reseal({ body: evilBody, s: origSig })), /signature invalid/);
  // 2. sign with Mallory's key but claim to be the inviter
  const malSig = b64u(await sign(mallory.privateKey, lp('beacon', evilBody)));
  await assert.rejects(openBeacon(await reseal({ body: evilBody, s: malSig })), /signature invalid/);
  // 3. extend expiry
  const longer = JSON.stringify({ ...b.payload, exp: b.payload.exp + 86400e3 });
  await assert.rejects(openBeacon(await reseal({ body: longer, s: origSig })), /signature invalid/);
  // 4. raise to 4 people
  const four = JSON.stringify({ ...b.payload, max: 4 });
  await assert.rejects(openBeacon(await reseal({ body: four, s: origSig })), /signature invalid/);
  // 5. junk JSON inside a correctly-encrypted beacon
  await assert.rejects(openBeacon(await reseal({ body: '{', s: origSig })));
  await assert.rejects(openBeacon(await reseal('just a string')));
});

test('ratchet: forged far-ahead message must NOT corrupt the chain (DoS resistance)', async () => {
  const key = randomBytes(32);
  const tx = new Chain(key, 'chat'), rx = new Chain(key, 'chat');
  const msgs = [];
  for (let n = 0; n < 5; n++) msgs.push(await encryptMsg(tx, 'text', { n }));
  // attacker injects garbage claiming counter 200
  await assert.rejects(decryptMsg(rx, { k: 'text', n: 200, c: b64u(randomBytes(40)) }));
  // every genuine message must still decrypt, in order
  for (let n = 0; n < 5; n++) assert.deepEqual(await decryptMsg(rx, msgs[n]), { n });
  // and the genuine message #200 must still work later
  for (let n = 5; n < 200; n++) await encryptMsg(tx, 'text', { n });
  const m200 = await encryptMsg(tx, 'text', { n: 200 });
  assert.deepEqual(await decryptMsg(rx, m200), { n: 200 });
});

test('ratchet: 300 messages delivered shuffled within the window all decrypt exactly once', async () => {
  const key = randomBytes(32);
  const tx = new Chain(key, 'chat'), rx = new Chain(key, 'chat');
  const msgs = [];
  for (let n = 0; n < 300; n++) msgs.push(await encryptMsg(tx, 'text', { n }));
  // shuffle within blocks of 100 (realistic reordering)
  for (let b = 0; b < 300; b += 100) {
    const blk = msgs.slice(b, b + 100).sort(() => Math.random() - 0.5);
    for (const m of blk) assert.equal((await decryptMsg(rx, m)).n, m.n);
  }
  for (const m of msgs.slice(0, 20)) await assert.rejects(decryptMsg(rx, m), /replayed|expired/);
});

test(`fuzz RATCHET envelope: ${ITER * 3} hostile envelopes rejected, chain still healthy`, async () => {
  const key = randomBytes(32);
  const tx = new Chain(key, 'chat'), rx = new Chain(key, 'chat');
  const good = await encryptMsg(tx, 'text', { body: 'ok' });
  for (let n = 0; n < ITER * 3; n++) {
    const field = ['k', 'n', 'c'][rint(3)];
    const bad = mutate(good, field);
    if (JSON.stringify(bad) === JSON.stringify(good)) continue;
    await assert.rejects(decryptMsg(rx, bad));
  }
  for (const n of [-1, 1.5, NaN, Infinity, 1e12, '0']) await assert.rejects(decryptMsg(rx, { ...good, n }));
  assert.deepEqual(await decryptMsg(rx, good), { body: 'ok' });
});

test('media frames: 20 000 frames → no IV reuse; truncated / random frames rejected', async () => {
  const key = randomBytes(32);
  const tx = await FrameCrypter.create(key), rx = await FrameCrypter.create(key);
  const ivs = new Set();
  const f = randomBytes(60);
  for (let n = 0; n < 20000; n++) {
    const e = await tx.encrypt(f, 1);
    ivs.add(b64u(e.subarray(e.length - 12)));
  }
  assert.equal(ivs.size, 20000);
  const e = await tx.encrypt(randomBytes(300), 10);
  for (let cut = 1; cut < e.length; cut += 7) await assert.rejects(rx.decrypt(e.subarray(0, e.length - cut), 10));
  for (let n = 0; n < 200; n++) await assert.rejects(rx.decrypt(randomBytes(rint(400)), 3));
  // header is authenticated: changing the clear codec header must fail
  const h = e.slice(); h[0] ^= 1; await assert.rejects(rx.decrypt(h, 10));
});

test('offline SOS mail: tampering, wrong box, stale and replayed mail rejected', async () => {
  const A = await generateIdentity(), B = await generateIdentity();
  const p = randomBytes(32);
  const la = await contactLinks(p, A.pub, B.pub), lb = await contactLinks(p, B.pub, A.pub);
  const other = await contactLinks(randomBytes(32), B.pub, A.pub);
  for (let n = 0; n < ITER; n++) {
    const sealed = unb64u(await sealMail(la, 'sos', { lat: 1, lon: 2 }));
    sealed[rint(sealed.length)] ^= 1 << rint(8);
    await assert.rejects(openMail(lb, b64u(sealed)));
  }
  const ok = await sealMail(la, 'sos', { lat: 1, lon: 2 });
  await assert.rejects(openMail(other, ok), 'mail opened by a different contact');
  await openMail(lb, ok);
  await assert.rejects(openMail(lb, ok), /replayed/);
  const old = await sealMail(la, 'sos', { lat: 1, lon: 2 });
  await assert.rejects(openMail(lb, old, -1), /stale/);
});

test('ciphertexts never repeat for identical plaintext (IV randomness)', async () => {
  const k = await aesKey(randomBytes(32));
  const seen = new Set();
  for (let n = 0; n < 2000; n++) seen.add(b64u(await seal(k, te.encode('same message'))));
  assert.equal(seen.size, 2000);
});

test('performance: hybrid handshake and message rate are fast enough for phones', async () => {
  const { A, B, room } = await pair();
  const t0 = performance.now();
  for (let n = 0; n < 10; n++) {
    const i = await initiate({ identity: A, room });
    const r = await respond({ identity: B, room, hello: i.hello });
    const { finish } = await i.onReply(r.reply);
    await r.onFinish(finish);
  }
  const hs = (performance.now() - t0) / 10;
  const key = randomBytes(32), tx = new Chain(key, 'c'), rx = new Chain(key, 'c');
  const t1 = performance.now();
  for (let n = 0; n < 1000; n++) await decryptMsg(rx, await encryptMsg(tx, 'text', { text: 'x'.repeat(200) }));
  const per = (performance.now() - t1) / 1000;
  console.log(`# handshake ${hs.toFixed(1)} ms · message enc+dec ${per.toFixed(3)} ms`);
  assert.ok(hs < 500, `handshake too slow: ${hs} ms`);
  assert.ok(per < 5, `message crypto too slow: ${per} ms`);
});
