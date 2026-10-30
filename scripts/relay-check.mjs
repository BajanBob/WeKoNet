// Diagnoses the relay connection the same way the apps connect.
// Usage: node scripts/relay-check.mjs wss://host/ws
import https from 'node:https';
import crypto from 'node:crypto';

const url = new URL(process.argv[2] || 'wss://wekonet-relay.onrender.com/ws');
const origins = ['', 'https://localhost', 'app://wekonet', 'capacitor://localhost'];
const results = [];

function tryOrigin(origin) {
  return new Promise((done) => {
    const headers = {
      Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13',
      'Sec-WebSocket-Key': crypto.randomBytes(16).toString('base64'),
    };
    if (origin) headers.Origin = origin;
    const req = https.request({ host: url.hostname, port: 443, path: url.pathname, headers, timeout: 90e3 });
    req.on('upgrade', (res, sock) => { done(`${origin || '(no origin)'} -> ${res.statusCode} upgraded OK`); sock.destroy(); });
    req.on('response', (res) => { let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => done(`${origin || '(no origin)'} -> HTTP ${res.statusCode} ${b.slice(0, 120)}`)); });
    req.on('timeout', () => { req.destroy(); done(`${origin || '(no origin)'} -> timeout`); });
    req.on('error', (e) => done(`${origin || '(no origin)'} -> error ${e.code || e.message}`));
    req.end();
  });
}

const h = await fetch(`https://${url.hostname}/healthz`).then(async (r) => `${r.status} ${await r.text()}`, (e) => `error ${e.message}`);
results.push(`healthz -> ${h}`);
for (const o of origins) results.push(await tryOrigin(o));

// Browser calling page (served by the relay since v1.1)
const page = await fetch(`https://${url.hostname}/b/`).then(async (r) => {
  const t = await r.text();
  return `${r.status} ${/id="view"/.test(t) ? 'full WeKoNet app' : /incomplete or damaged|open\.js/.test(t) ? 'OLD landing page' : 'unknown page'}; CSP header ${r.headers.get('content-security-policy') ? 'present' : 'MISSING'}`;
}, (e) => `error ${e.message}`);
results.push(`/b/ -> ${page}`);

// Join a throwaway room and see what the relay hands to a caller (TURN or not).
// Only counts are printed — never credentials.
const turn = await new Promise((done) => {
  const ws = new WebSocket(url.href);
  const id = crypto.randomBytes(16).toString('base64url'), proof = crypto.randomBytes(33).toString('base64url');
  const t = setTimeout(() => { ws.close(); done('timeout'); }, 60e3);
  ws.onopen = () => {
    ws.send(JSON.stringify({ op: 'create', room: id, proof, max: 2, linger: 'end', exp: Date.now() + 120e3 }));
    ws.send(JSON.stringify({ op: 'join', room: id, proof }));
  };
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.op === 'error') { clearTimeout(t); ws.close(); return done(`relay error ${m.code}`); }
    if (m.op !== 'joined') return;
    clearTimeout(t);
    const urls = (m.ice || []).flatMap((s) => [].concat(s.urls));
    const kinds = { stun: 0, turnUdp: 0, turnTcp: 0, turns: 0 };
    for (const u of urls) {
      if (/^stun:/.test(u)) kinds.stun++;
      else if (/^turns:/.test(u)) kinds.turns++;
      else if (/^turn:/.test(u)) kinds[/transport=tcp/.test(u) ? 'turnTcp' : 'turnUdp']++;
    }
    ws.send(JSON.stringify({ op: 'end' })); ws.close();
    done(urls.length ? `TURN provided: ${JSON.stringify(kinds)} (credentials ${m.ice.some((s) => s.username && s.credential) ? 'present' : 'MISSING'})` : 'NO TURN servers — phones on mobile data / strict NAT will not connect (set CF_TURN_KEY_ID and CF_TURN_API_TOKEN on Render)');
  };
  ws.onerror = () => { clearTimeout(t); done('websocket error'); };
});
results.push(`turn -> ${turn}`);
console.log(results.join('\n'));
console.log(`::notice title=Relay check::${results.join('%0A')}`);
