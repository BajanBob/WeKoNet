// Retention policy (pure functions → unit-tested).
//
//   • Message / call / SOS history: kept at most 3 hours, then deleted.
//   • Live-location breadcrumbs: also at most 3 hours.
//   • SOS: 3 hours by default, or 7 / 30 days if chosen in Settings.
//   • Saved connections (contacts) never expire on their own.
//   • Expired items are hidden immediately and deleted every few minutes.
//   • Every night at 01:00 local time WeKoNet purges itself:
//       – everything past its retention date
//       – expired beacons and lingering rooms
//       – live-location breadcrumbs older than 3 h
//       – temporary media / caches
//       – ALL data if this install is a guest install (opened from a beacon
//         and the person did not choose "Keep WeKoNet")
export const HISTORY_MS = 3 * 3600e3;   // 3 hours
export const LOCATION_MS = 3 * 3600e3;  // 3 hours
export const SWEEP_MS = 5 * 60e3;       // delete expired items every 5 minutes

// SOS records can be kept longer as evidence (Settings → History).
export const SOS_KEEP = { '3h': HISTORY_MS, '7d': 7 * 86400e3, '30d': 30 * 86400e3 };
let sosMs = HISTORY_MS;
export function setSosRetention(key) { sosMs = SOS_KEEP[key] ?? HISTORY_MS; }

export function isExpired(rec, now = Date.now()) {
  switch (rec.type) {
    case 'beacon': return now > (rec.lingerUntil ?? rec.exp);
    case 'location': return now - rec.createdAt > LOCATION_MS;
    case 'temp': return true;
    case 'contact': return false;                     // saved connections stay until you remove them
    case 'sos': return now - rec.createdAt > sosMs;
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
