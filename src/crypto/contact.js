// "Keep connection" → a saved contact. Both sides derive the same mailbox IDs
// and SOS key from the handshake's pair secret, so an SOS can reach a contact
// even when no call is open. The relay only sees random-looking mailbox IDs.
import { lp, b64u, unb64u, sha384 } from './util.js';
import { hkdf384, aesKey, sealJSON, openJSON } from './aead.js';

const SALT = new Uint8Array(48);

async function boxId(pair, fromPub, toPub) {
  const info = b64u(await sha384(lp('box', fromPub, toPub)));
  return b64u(await hkdf384(pair, SALT, `mailbox ${info}`, 32));
}

export async function contactLinks(pairSecret, myPub, peerPub) {
  return {
    inbox: await boxId(pairSecret, peerPub, myPub),   // they → me
    outbox: await boxId(pairSecret, myPub, peerPub),  // me → they
    sosKey: await aesKey(await hkdf384(pairSecret, SALT, 'sos+mail key', 32)),
  };
}

/** Seal an offline message (SOS / location) for a saved contact's mailbox. */
export async function sealMail(links, kind, body) {
  const env = { kind, body, t: Date.now(), n: b64u(crypto.getRandomValues(new Uint8Array(12))) };
  return b64u(await sealJSON(links.sosKey, env, lp('mail', links.outbox)));
}

const seen = new Set();
export async function openMail(links, data, maxAgeMs = 24 * 3600e3) {
  const env = await openJSON(links.sosKey, unb64u(data), lp('mail', links.inbox));
  if (Date.now() - env.t > maxAgeMs) throw new Error('stale mail');
  if (seen.has(env.n)) throw new Error('replayed mail');
  seen.add(env.n);
  if (seen.size > 5000) seen.delete(seen.values().next().value); // bounded; stale mail is rejected by age anyway
  return env;
}
