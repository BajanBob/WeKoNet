// One-tap calling: decline / block links reach the caller sealed, and the relay
// serves the browser app with its strict CSP from a fixed allow-list.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startRelay, webApp } from '../server/relay.js';
import { generateIdentity } from '../src/crypto/identity.js';
import { createBeacon, openBeacon, splitAction, actionLink } from '../src/crypto/beacon.js';
import { CallSession, declineBeacon } from '../src/net/mesh.js';

test('links: answer / decline / block suffixes round-trip and never break the beacon', async () => {
  const id = await generateIdentity();
  const b = await createBeacon({ identity: id, signalUrl: 'wss://relay.example/ws', appBase: 'https://relay.example/b/', maxPeers: 2 });
  for (const a of ['answer', 'decline', 'block']) {
    const { link, action } = splitAction(actionLink(b.link, a));
    assert.equal(action, a); assert.equal(link, b.link);
    assert.equal((await openBeacon(link)).payload.room, b.payload.room);
  }
  assert.deepEqual(splitAction(b.link), { link: b.link, action: null });
  assert.equal(splitAction('#s.Q2hlY2tUaGlzUVJDb2RlMQ.block').action, 'block');
  assert.equal(splitAction('#s.Q2hlY2tUaGlzUVJDb2RlMQ.answerx').action, null);
});

test('decline link: caller is told, nobody joins, no media opened', async () => {
  const server = await startRelay({ port: 0, host: '127.0.0.1' });
  const url = `ws://127.0.0.1:${server.address().port}/ws`;
  try {
    const host = await generateIdentity();
    const b = await createBeacon({ identity: host, signalUrl: url, maxPeers: 2, mode: 'chat' });
    const call = new CallSession({ identity: host, beacon: b, role: 'host', iceServers: [] });
    const declined = new Promise((r) => call.addEventListener('declined', r));
    const joined = new Promise((r) => call.addEventListener('room', r));
    await call.start('chat');
    await joined;
    const guestView = await openBeacon(b.link);
    assert.equal(await declineBeacon(guestView), true);
    await declined;
    assert.equal(call.peers.size, 0);
    await call.end(true);
    // Nobody waiting any more → decline reports it could not tell anyone.
    assert.equal(await declineBeacon(guestView, { timeoutMs: 3000 }), false);
  } finally { server.close(); }
});

test('decline: a forged decline (wrong beacon key) is rejected as tampering', async () => {
  const server = await startRelay({ port: 0, host: '127.0.0.1' });
  const url = `ws://127.0.0.1:${server.address().port}/ws`;
  try {
    const host = await generateIdentity();
    const b = await createBeacon({ identity: host, signalUrl: url, maxPeers: 2, mode: 'chat' });
    const call = new CallSession({ identity: host, beacon: b, role: 'host', iceServers: [] });
    let declined = false; call.addEventListener('declined', () => { declined = true; });
    await call.start('chat');
    const sawTamper = new Promise((r) => call.addEventListener('security', r));
    const other = await createBeacon({ identity: host, signalUrl: url, maxPeers: 2, mode: 'chat' });
    // Right room + join proof, wrong signaling key: a relay-level attacker's best attempt.
    const forged = { ...(await openBeacon(b.link)), keys: { ...(await openBeacon(b.link)).keys, sigKey: other.keys.sigKey } };
    await declineBeacon(forged, { timeoutMs: 3000 });
    await sawTamper;
    assert.equal(declined, false);
    await call.end(true);
  } finally { server.close(); }
});

test('relay: serves the browser app only from its allow-list, with strict headers', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wkweb-'));
  const csp = "default-src 'none'; script-src 'self'; require-trusted-types-for 'script'";
  fs.mkdirSync(path.join(dir, 'b')); fs.mkdirSync(path.join(dir, 'assets'));
  fs.writeFileSync(path.join(dir, 'csp.txt'), csp);
  fs.writeFileSync(path.join(dir, 'index.html'), 'ROOT');
  fs.writeFileSync(path.join(dir, 'b', 'index.html'), '<!doctype html><title>WeKoNet</title>APP');
  fs.writeFileSync(path.join(dir, 'assets', 'main-abc.js'), 'console.log(1)');
  fs.writeFileSync(path.join(dir, 'secret.env'), 'TOKEN=1');
  assert.ok(webApp(dir).files['/b/']);
  process.env.WEB_DIR = dir;
  const server = await startRelay({ port: 0, host: '127.0.0.1' });
  delete process.env.WEB_DIR;
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const app = await fetch(`${base}/b/`);
    assert.equal(app.status, 200);
    assert.match(await app.text(), /APP/);
    assert.equal(app.headers.get('content-security-policy'), `${csp}; frame-ancestors 'none'`);
    assert.match(app.headers.get('permissions-policy'), /camera=\(self\)/);
    assert.equal(app.headers.get('cache-control'), 'no-store');
    const js = await fetch(`${base}/assets/main-abc.js`);
    assert.equal(js.status, 200); assert.match(js.headers.get('cache-control'), /immutable/);
    for (const bad of ['/secret.env', '/assets/../secret.env', '/%2e%2e/etc/passwd', '/csp.txt']) {
      assert.equal((await fetch(base + bad)).status, 404, bad);
    }
    assert.notEqual(await (await fetch(`${base}/`)).text(), 'ROOT'); // '/' stays the status page
  } finally { server.close(); }
  // A build with a weakened policy is refused outright.
  fs.writeFileSync(path.join(dir, 'csp.txt'), "script-src 'self' 'unsafe-inline'; require-trusted-types-for 'script'");
  assert.throws(() => webApp(dir), /not strict/);
});

test('caller whose relay connection drops while waiting reconnects and can still be reached', async () => {
  const server = await startRelay({ port: 0, host: '127.0.0.1' });
  const url = `ws://127.0.0.1:${server.address().port}/ws`;
  try {
    const host = await generateIdentity();
    const b = await createBeacon({ identity: host, signalUrl: url, maxPeers: 2, mode: 'chat' });
    const call = new CallSession({ identity: host, beacon: b, role: 'host', iceServers: [] });
    let rooms = 0;
    const back = new Promise((r) => call.addEventListener('room', () => { if (++rooms === 2) r(); }));
    await call.start('chat');
    await new Promise((r) => setTimeout(r, 200));
    call.sig.ws.close(); // phone lost its connection to the relay
    await back;          // …and came back into the same room by itself
    const declined = new Promise((r) => call.addEventListener('declined', r));
    assert.equal(await declineBeacon(await openBeacon(b.link)), true, 'guest must find the caller in the room');
    await declined;
    await call.end(true);
  } finally { server.close(); }
});
