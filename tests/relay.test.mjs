// Integration test for the blind relay using Node's built-in WebSocket client.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startRelay } from '../server/relay.js';
import { generateIdentity } from '../src/crypto/identity.js';
import { createBeacon, openBeacon } from '../src/crypto/beacon.js';

let server, url;
before(async () => { server = await startRelay({ port: 0, host: '127.0.0.1' }); url = `ws://127.0.0.1:${server.address().port}/ws`; });
after(() => server.close());

function client() {
  return new Promise((ok, fail) => {
    const ws = new WebSocket(url);
    const q = [], waiters = [];
    ws.onmessage = (e) => { const m = JSON.parse(e.data); const w = waiters.shift(); w ? w(m) : q.push(m); };
    ws.onopen = () => ok({
      send: (o) => ws.send(JSON.stringify(o)),
      next: () => new Promise((r) => (q.length ? r(q.shift()) : waiters.push(r))),
      close: () => ws.close(),
    });
    ws.onerror = fail;
  });
}

test('relay: beacon room admits holders of the link only, caps at 3, forwards ciphertext', async () => {
  const id = await generateIdentity();
  const b = await createBeacon({ identity: id, signalUrl: url, maxPeers: 3 });
  const A = await client();
  A.send({ op: 'create', room: b.keys.roomTag, proof: b.keys.joinProof, max: 3, linger: 'end', exp: b.payload.exp });
  const ja = await A.next(); assert.equal(ja.op, 'joined');

  const intruder = await client();
  intruder.send({ op: 'join', room: b.keys.roomTag, proof: 'A'.repeat(43) });
  assert.equal((await intruder.next()).code, 'no-such-beacon');

  const o = await openBeacon(b.link);
  const B = await client(); B.send({ op: 'join', room: o.keys.roomTag, proof: o.keys.joinProof });
  const jb = await B.next(); assert.deepEqual(jb.peers, [ja.peer]);
  assert.equal(jb.deadline, null, "'until call ends' must not impose a deadline");
  assert.equal((await A.next()).op, 'peer-joined');

  B.send({ op: 'signal', to: ja.peer, data: 'opaque-ciphertext' });
  assert.deepEqual(await A.next(), { op: 'signal', from: jb.peer, data: 'opaque-ciphertext' });

  const C = await client(); C.send({ op: 'join', room: o.keys.roomTag, proof: o.keys.joinProof });
  assert.equal((await C.next()).op, 'joined');
  const D = await client(); D.send({ op: 'join', room: o.keys.roomTag, proof: o.keys.joinProof });
  assert.equal((await D.next()).code, 'room-full');

  assert.equal((await A.next()).op, 'peer-joined');
  A.send({ op: 'end' });
  assert.equal((await A.next()).op, 'ended');
  const E = await client(); E.send({ op: 'join', room: o.keys.roomTag, proof: o.keys.joinProof });
  assert.equal((await E.next()).code, 'no-such-beacon', 'beacon expires when call ends');
  for (const c of [A, B, C, D, E, intruder]) c.close();
});

test('relay: SOS mailbox delivers to subscriber, ack deletes, nightly purge clears', async () => {
  const box = 'b'.repeat(43);
  const R = await client(); R.send({ op: 'sub', boxes: [box] });
  const S = await client(); S.send({ op: 'post', box, data: 'sealed-sos' });
  assert.equal((await R.next()).data, 'sealed-sos');
  assert.equal((await S.next()).op, 'posted');
  S.send({ op: 'post', box, data: 'second' }); await S.next(); await R.next();
  server.nightlyPurge();
  const R2 = await client(); R2.send({ op: 'sub', boxes: [box] }); R2.send({ op: 'ping' });
  assert.equal((await R2.next()).op, 'pong', 'nothing stored after purge');
  for (const c of [R, S, R2]) c.close();
});

test('relay: linger 1h gives a real deadline', async () => {
  const id = await generateIdentity();
  const b = await createBeacon({ identity: id, signalUrl: url, linger: '1h' });
  const A = await client(); A.send({ op: 'create', room: b.keys.roomTag, proof: b.keys.joinProof, max: 2, linger: '1h', exp: b.payload.exp });
  await A.next();
  const B = await client(); B.send({ op: 'join', room: b.keys.roomTag, proof: b.keys.joinProof });
  const jb = await B.next();
  assert.ok(jb.deadline > Date.now() + 3590e3 && jb.deadline <= Date.now() + 3600e3);
  A.close(); B.close();
});

test('relay: short-link stash holds ciphertext until expiry, rejects bad input', async () => {
  const A = await client();
  const id = 'abcdefghijklmnop';
  A.send({ op: 'stash', id, data: 'Q2lwaGVydGV4dA', exp: Date.now() + 60e3 });
  assert.equal((await A.next()).op, 'stashed');
  A.send({ op: 'stash', id, data: 'Zm9v', exp: Date.now() + 60e3 }); // id already taken
  assert.equal((await A.next()).code, 'bad-request');
  const B = await client();
  B.send({ op: 'fetch', id });
  const got = await B.next(); assert.equal(got.op, 'stash'); assert.equal(got.data, 'Q2lwaGVydGV4dA');
  B.send({ op: 'fetch', id: 'zzzzzzzzzzzzzzzz' });
  assert.equal((await B.next()).code, 'no-such-link');
  B.send({ op: 'stash', id: 'qrstuvwxyzABCDEF', data: 'x', exp: Date.now() - 1 });
  assert.equal((await B.next()).code, 'bad-request');
  A.close(); B.close();
});

test('relay: a caller whose connection died silently can come straight back (was = old peer id), even into a full 2-person room', async () => {
  const id = await generateIdentity();
  const b = await createBeacon({ identity: id, signalUrl: url, maxPeers: 2 });
  const A = await client(); // caller's first connection — goes "deaf" (never closed)
  A.send({ op: 'create', room: b.keys.roomTag, proof: b.keys.joinProof, max: 2, linger: 'end', exp: b.payload.exp });
  const ja = await A.next();
  const o = await openBeacon(b.link);
  const B = await client(); B.send({ op: 'join', room: o.keys.roomTag, proof: o.keys.joinProof });
  const jb = await B.next(); assert.deepEqual(jb.peers, [ja.peer]);
  // Without `was` the room is full (dead A + B).
  const X = await client(); X.send({ op: 'join', room: b.keys.roomTag, proof: b.keys.joinProof });
  assert.equal((await X.next()).code, 'room-full');
  // With `was` the dead connection is replaced and B is told: old one left, new one joined.
  const A2 = await client(); A2.send({ op: 'join', room: b.keys.roomTag, proof: b.keys.joinProof, was: ja.peer });
  const j2 = await A2.next(); assert.equal(j2.op, 'joined'); assert.deepEqual(j2.peers, [jb.peer]);
  const seen = [await B.next(), await B.next()].map((m) => m.op).sort();
  assert.deepEqual(seen, ['peer-joined', 'peer-left']);
  // A peer id from outside the room changes nothing.
  const Y = await client(); Y.send({ op: 'join', room: b.keys.roomTag, proof: b.keys.joinProof, was: 'AAAAAAAAAAA' });
  assert.equal((await Y.next()).code, 'room-full');
  // And the relay answers pings (the app's own heartbeat).
  A2.send({ op: 'ping' }); assert.equal((await A2.next()).op, 'pong');
  for (const c of [A, B, X, A2, Y]) c.close();
});
