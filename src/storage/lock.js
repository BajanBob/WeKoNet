// App lock: an optional 4–8 digit PIN that hides WeKoNet on this device until
// it is entered. The PIN is stored only as a salted PBKDF2-SHA-256 hash
// (600,000 iterations). Ten wrong PINs in a row erase WeKoNet.
// It protects against someone picking up an unlocked phone; stored data is
// additionally protected by the operating system and the release build.
import { b64u, unb64u, randomBytes, ctEqual, te } from '../crypto/util.js';

export const PIN_ITER = 600_000;
export const MAX_FAILS = 10;
export const LOCK_AFTER = { now: 0, '1m': 60e3, '5m': 5 * 60e3 };

export const validPin = (pin) => /^\d{4,8}$/.test(String(pin));

async function derive(pin, salt, iter) {
  const k = await crypto.subtle.importKey('raw', te.encode(String(pin)), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, k, 256));
}

export async function makePinRecord(pin, iter = PIN_ITER) {
  if (!validPin(pin)) throw new Error('Use 4 to 8 digits');
  const salt = randomBytes(16);
  return { salt: b64u(salt), hash: b64u(await derive(pin, salt, iter)), iter };
}

export async function checkPin(pin, rec) {
  if (!rec || !validPin(pin)) return false;
  return ctEqual(await derive(pin, unb64u(rec.salt), rec.iter), unb64u(rec.hash));
}
