import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isExpired, next1am, purgeOverdue, HISTORY_MS } from '../src/storage/retention.js';
import { contactLinks, sealMail, openMail } from '../src/crypto/contact.js';
import { generateIdentity } from '../src/crypto/identity.js';
import { randomBytes } from '../src/crypto/util.js';

const DAY = 86400e3;

test('retention: history kept 3 years, location 24 h, beacons until expiry', () => {
  const now = Date.UTC(2026, 9, 26);
  assert.equal(isExpired({ type: 'message', createdAt: now - (HISTORY_MS - DAY) }, now), false);
  assert.equal(isExpired({ type: 'message', createdAt: now - (HISTORY_MS + DAY) }, now), true);
  assert.equal(isExpired({ type: 'sos', createdAt: now - 2 * 365 * DAY }, now), false);
  assert.equal(isExpired({ type: 'location', createdAt: now - 25 * 3600e3 }, now), true);
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
