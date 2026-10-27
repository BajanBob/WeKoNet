// Encrypted local vault (IndexedDB). Every record body is AES-256-GCM
// encrypted with a NON-extractable device key that lives only as a CryptoKey
// object — scripts (including any injected one) can use it but never read it.
import { generateIdentity, wekonetId } from '../crypto/identity.js';
import { sealJSON, openJSON } from '../crypto/aead.js';
import { te } from '../crypto/util.js';
import { isExpired, next1am, purgeOverdue, SWEEP_MS } from './retention.js';

const DB = 'wekonet';
const STORES = ['keys', 'records', 'settings'];
let dbp = null;

function db() {
  if (!dbp) {
    dbp = new Promise((ok, fail) => {
      const r = indexedDB.open(DB, 1);
      r.onupgradeneeded = () => {
        const d = r.result;
        for (const s of STORES) if (!d.objectStoreNames.contains(s)) d.createObjectStore(s);
        const recs = r.transaction.objectStore('records');
        if (!recs.indexNames.contains('type')) recs.createIndex('type', 'type');
      };
      r.onsuccess = () => ok(r.result);
      r.onerror = () => fail(r.error);
    });
  }
  return dbp;
}

async function tx(store, mode, fn) {
  const d = await db();
  return new Promise((ok, fail) => {
    const t = d.transaction(store, mode);
    const res = fn(t.objectStore(store));
    t.oncomplete = () => ok(res instanceof IDBRequest ? res.result : res);
    t.onerror = () => fail(t.error);
  });
}

const get = (s, k) => tx(s, 'readonly', (o) => o.get(k));
const put = (s, k, v) => tx(s, 'readwrite', (o) => o.put(v, k));
const del = (s, k) => tx(s, 'readwrite', (o) => o.delete(k));

let vaultKey = null;

export async function unlock() {
  vaultKey = await get('keys', 'vault');
  if (!vaultKey) {
    vaultKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    await put('keys', 'vault', vaultKey);
  }
  let identity = await get('keys', 'identity');
  if (!identity) {
    const g = await generateIdentity();
    identity = { privateKey: g.privateKey, pub: g.pub, id: g.id };
    await put('keys', 'identity', identity);
  }
  identity.id = await wekonetId(identity.pub);
  return identity;
}

// ---------- settings (small, not secret) ----------
export const settings = {
  async get(k, d) { const v = await get('settings', k); return v === undefined ? d : v; },
  set: (k, v) => put('settings', k, v),
};

// ---------- encrypted records ----------
const aad = (type, id) => te.encode(`rec|${type}|${id}`);

export async function save(type, body, extra = {}) {
  const id = extra.id || crypto.randomUUID();
  const createdAt = extra.createdAt || Date.now();
  const ct = await sealJSON(vaultKey, body, aad(type, id));
  await put('records', id, { id, type, createdAt, ct, ...extra.meta });
  return id;
}

export async function list(type) {
  const rows = await tx('records', 'readonly', (o) => o.index('type').getAll(type));
  const out = [];
  for (const r of rows || []) {
    if (isExpired(r)) continue;
    try { out.push({ id: r.id, createdAt: r.createdAt, ...(await openJSON(vaultKey, r.ct, aad(r.type, r.id))) }); } catch { /* corrupted → skip */ }
  }
  return out.sort((a, b) => a.createdAt - b.createdAt);
}

export const remove = (id) => del('records', id);

// ---------- purge ----------
// wipeGuest=false is used by the 5-minute sweep: it deletes expired records
// but never wipes a guest install in the middle of a call (that only happens
// at the 01:00 nightly purge or when the guest chooses "Remove everything").
export async function purgeExpired(now = Date.now(), { wipeGuest = true } = {}) {
  const guest = await settings.get('guest', false);
  if (guest && wipeGuest) return wipeAll();
  const rows = await tx('records', 'readonly', (o) => o.getAll());
  let n = 0;
  for (const r of rows || []) if (isExpired(r, now)) { await del('records', r.id); n++; }
  await settings.set('lastPurge', now);
  return n;
}

/** Full self-destruct: keys, identity, history, settings. */
export async function wipeAll() {
  const d = await db(); d.close(); dbp = null; vaultKey = null;
  await new Promise((ok) => { const r = indexedDB.deleteDatabase(DB); r.onsuccess = r.onerror = r.onblocked = () => ok(); });
  try { localStorage.clear(); sessionStorage.clear(); } catch { /* not available */ }
  if ('caches' in self) for (const k of await caches.keys()) await caches.delete(k);
  return 'wiped';
}

/** Schedule the 01:00 nightly purge (and catch up if the app was closed),
 *  plus a sweep of expired items every few minutes. */
export async function scheduleNightlyPurge(onPurged) {
  const last = await settings.get('lastPurge', 0);
  if (purgeOverdue(last)) onPurged?.(await purgeExpired());
  const arm = () => {
    const ms = next1am() - Date.now();
    setTimeout(async () => { onPurged?.(await purgeExpired()); arm(); }, ms);
  };
  arm();
  // History only lives 3 hours, so expired items are swept every 5 minutes
  // instead of waiting for 01:00.
  setInterval(() => { purgeExpired(Date.now(), { wipeGuest: false }).then((n) => { if (n > 0) onPurged?.(n); }, () => {}); }, SWEEP_MS);
}
