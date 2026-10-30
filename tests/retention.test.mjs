import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isExpired, next1am, purgeOverdue, HISTORY_MS, LOCATION_MS } from '../src/storage/retention.js';
import { contactLinks, sealMail, openMail } from '../src/crypto/contact.js';
import { generateIdentity } from '../src/crypto/identity.js';
import { randomBytes } from '../src/crypto/util.js';

const DAY = 86400e3;

test('retention: history and location kept 3 hours, beacons until expiry', () => {
  const now = Date.UTC(2026, 9, 26);
  const MIN = 60e3, HOUR = 3600e3;
  assert.equal(HISTORY_MS, 3 * HOUR);
  assert.equal(LOCATION_MS, 3 * HOUR);
  assert.equal(isExpired({ type: 'message', createdAt: now - (HISTORY_MS - MIN) }, now), false);
  assert.equal(isExpired({ type: 'message', createdAt: now - (HISTORY_MS + MIN) }, now), true);
  assert.equal(isExpired({ type: 'call', createdAt: now - 4 * HOUR }, now), true);
  assert.equal(isExpired({ type: 'sos', createdAt: now - 2 * HOUR }, now), false);
  assert.equal(isExpired({ type: 'sos', createdAt: now - DAY }, now), true);
  assert.equal(isExpired({ type: 'location', createdAt: now - 2 * HOUR }, now), false);
  assert.equal(isExpired({ type: 'location', createdAt: now - 4 * HOUR }, now), true);
  assert.equal(isExpired({ type: 'beacon', exp: now + 1000 }, now), false);
  assert.equal(isExpired({ type: 'beacon', exp: now - 1 }, now), true);
  assert.equal(isExpired({ type: 'temp', createdAt: now }, now), true);
});

test('nightly purge: next 01:00 and catch-up when app was closed', () => {
  const n = next1am(new Date(2026, 9, 26, 20, 17));
  assert.deepEqual([n.getDate(), n.getHours(), n.getMinutes()], [27, 1, 0]);
  const m = next1am(new Date(2026, 9, 27, 0, 30));
  assert.deepEqual([m.getDate(), m.getHours()], [27, 1]);
  assert.equal(purgeOverdue(new Date(2026, 9, 26, 22).getTime(), new Date(2026, 9, 27, 9)), true);
  assert.equal(purgeOverdue(new Date(2026, 9, 27, 2).getTime(), new Date(2026, 9, 27, 9)), false);
  assert.equal(purgeOverdue(0), true);
});

test('saved contact: both sides derive mirrored mailboxes; SOS mail sealed + replay-safe', async () => {
  const A = await generateIdentity(), B = await generateIdentity();
  const pair = randomBytes(32);
  const la = await contactLinks(pair, A.pub, B.pub), lb = await contactLinks(pair, B.pub, A.pub);
  assert.equal(la.outbox, lb.inbox);
  assert.equal(la.inbox, lb.outbox);
  assert.notEqual(la.inbox, la.outbox);
  const sealed = await sealMail(la, 'sos', { lat: 13.0975, lon: -59.6167, note: 'help' });
  const env = await openMail(lb, sealed);
  assert.equal(env.kind, 'sos'); assert.equal(env.body.note, 'help');
  await assert.rejects(openMail(lb, sealed), /replayed/);
  await assert.rejects(openMail(la, sealed)); // wrong direction / AAD
});

test('retention: saved contacts never expire; SOS retention can be extended', async () => {
  const { setSosRetention } = await import('../src/storage/retention.js');
  const now = Date.UTC(2026, 9, 27), HOUR = 3600e3;
  assert.equal(isExpired({ type: 'contact', createdAt: now - 400 * DAY }, now), false);
  assert.equal(isExpired({ type: 'blocked', createdAt: now - 400 * DAY }, now), false);
  setSosRetention('7d');
  assert.equal(isExpired({ type: 'sos', createdAt: now - 6 * DAY }, now), false);
  assert.equal(isExpired({ type: 'sos', createdAt: now - 8 * DAY }, now), true);
  assert.equal(isExpired({ type: 'message', createdAt: now - 4 * HOUR }, now), true, 'messages still 3 h');
  setSosRetention('30d');
  assert.equal(isExpired({ type: 'sos', createdAt: now - 29 * DAY }, now), false);
  setSosRetention('3h');
  assert.equal(isExpired({ type: 'sos', createdAt: now - 4 * HOUR }, now), true);
});

test('app lock: PIN stored as salted hash, wrong PIN rejected', async () => {
  const { makePinRecord, checkPin, validPin } = await import('../src/storage/lock.js');
  assert.equal(validPin('12'), false); assert.equal(validPin('1234'), true); assert.equal(validPin('12a4'), false);
  const rec = await makePinRecord('482915', 1000); // low iteration count keeps the test fast
  assert.ok(!JSON.stringify(rec).includes('482915'));
  assert.equal(await checkPin('482915', rec), true);
  assert.equal(await checkPin('482916', rec), false);
  const rec2 = await makePinRecord('482915', 1000);
  assert.notEqual(rec.hash, rec2.hash, 'salted');
  await assert.rejects(makePinRecord('12'), /4 to 8 digits/);
});
