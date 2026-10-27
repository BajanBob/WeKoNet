// The relay hands Cloudflare TURN credentials to room members (mocked API).
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('relay: joined message carries TURN servers, port 53 removed, token sent as Bearer', async () => {
  process.env.CF_TURN_KEY_ID = 'key123';
  process.env.CF_TURN_API_TOKEN = 'tok456';
  const realFetch = globalThis.fetch;
  let seen = null;
  globalThis.fetch = async (url, opts) => {
    seen = { url, auth: opts.headers.authorization, body: JSON.parse(opts.body) };
    return new Response(JSON.stringify({ iceServers: [
      { urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.cloudflare.com:53'] },
      { urls: ['turn:turn.cloudflare.com:3478?transport=udp', 'turn:turn.cloudflare.com:53?transport=udp', 'turns:turn.cloudflare.com:443?transport=tcp'], username: 'u', credential: 'c' },
    ] }), { status: 201 });
  };
  const { startRelay, turnConfigured } = await import('../server/relay.js?turn');
  const server = await startRelay({ port: 0, host: '127.0.0.1' });
  try {
    for (let i = 0; i < 50 && !turnConfigured(); i++) await new Promise((r) => setTimeout(r, 10));
    assert.equal(seen.url, 'https://rtc.live.cloudflare.com/v1/turn/keys/key123/credentials/generate-ice-servers');
    assert.equal(seen.auth, 'Bearer tok456');
    assert.ok(seen.body.ttl >= 3600);

    const ws = new WebSocket(`ws://127.0.0.1:${server.address().port}/ws`);
    await new Promise((ok) => (ws.onopen = ok));
    const msg = new Promise((ok) => (ws.onmessage = (e) => ok(JSON.parse(e.data))));
    ws.send(JSON.stringify({ op: 'create', room: 'R'.repeat(22), proof: 'P'.repeat(43), max: 2, linger: 'end', exp: Date.now() + 60e3 }));
    const joined = await msg;
    assert.equal(joined.op, 'joined');
    const urls = joined.ice.flatMap((s) => s.urls);
    assert.ok(urls.some((u) => u.startsWith('turns:')));
    assert.ok(!urls.some((u) => /:53(\?|$)/.test(u)), 'port 53 filtered');
    assert.equal(joined.ice[1].username, 'u');
    ws.close();
  } finally {
    server.close(); globalThis.fetch = realFetch;
    delete process.env.CF_TURN_KEY_ID; delete process.env.CF_TURN_API_TOKEN;
  }
});
