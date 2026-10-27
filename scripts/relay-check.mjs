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
console.log(results.join('\n'));
console.log(`::notice title=Relay check::${results.join('%0A')}`);
