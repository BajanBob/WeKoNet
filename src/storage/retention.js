// Retention policy (pure functions → unit-tested).
//
//   • Message / call / SOS history: kept at most 3 years, then deleted.
//   • Every night at 01:00 local time WeKoNet purges itself:
//       – everything past its retention date
//       – expired beacons and lingering rooms
//       – live-location breadcrumbs older than 24 h
//       – temporary media / caches
//       – ALL data if this install is a guest install (opened from a beacon
//         and the person did not choose "Keep WeKoNet")
export const HISTORY_MS = Math.round(3 * 365.25 * 86400e3);
export const LOCATION_MS = 86400e3;

export function isExpired(rec, now = Date.now()) {
  switch (rec.type) {
    case 'beacon': return now > (rec.lingerUntil ?? rec.exp);
    case 'location': return now - rec.createdAt > LOCATION_MS;
    case 'temp': return true;
    default: return now - rec.createdAt > HISTORY_MS; // message, call, sos
  }
}

export function next1am(from = new Date()) {
  const n = new Date(from);
  n.setHours(1, 0, 0, 0);
  if (n <= from) n.setDate(n.getDate() + 1);
  return n;
}

/** True if a 01:00 boundary was crossed since the last purge (app was closed). */
export function purgeOverdue(lastPurge, now = new Date()) {
  if (!lastPurge) return true;
  return next1am(new Date(lastPurge)) <= now;
}
