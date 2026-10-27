// Live location sharing + SOS help mode.
// Locations only ever travel inside per-peer ratchet encryption (calls) or
// contact-sealed mail (SOS to saved contacts). Nothing is sent in the clear.

export const SHARE_DURATIONS = { '15m': 15 * 60e3, '1h': 3600e3, '8h': 8 * 3600e3, until: Infinity };

function fix(p) {
  return { lat: p.coords.latitude, lon: p.coords.longitude, acc: p.coords.accuracy, t: p.timestamp || Date.now() };
}

export class LocationSharer extends EventTarget {
  constructor() { super(); this.watch = null; this.timer = null; this.lastSent = 0; this.until = 0; }

  get active() { return this.watch !== null; }

  start(durationKey, onFix, { minIntervalMs = 5000, highAccuracy = true } = {}) {
    this.stop();
    if (!('geolocation' in navigator)) throw new Error('Location is not available on this device');
    const ms = SHARE_DURATIONS[durationKey] ?? 3600e3;
    this.until = Date.now() + ms;
    this.watch = navigator.geolocation.watchPosition(
      (p) => {
        if (Date.now() > this.until) return this.stop();
        if (Date.now() - this.lastSent < minIntervalMs) return;
        this.lastSent = Date.now();
        onFix(fix(p));
      },
      (err) => this.dispatchEvent(new CustomEvent('error', { detail: err.message })),
      { enableHighAccuracy: highAccuracy, maximumAge: 5000, timeout: 20000 },
    );
    if (Number.isFinite(ms)) this.timer = setTimeout(() => this.stop(), ms);
    this.dispatchEvent(new CustomEvent('state', { detail: { active: true, until: this.until } }));
  }

  stop() {
    if (this.watch !== null) navigator.geolocation.clearWatch(this.watch);
    clearTimeout(this.timer);
    this.watch = null; this.timer = null;
    this.dispatchEvent(new CustomEvent('state', { detail: { active: false } }));
  }
}

/**
 * SOS: high-accuracy position, re-sent every 20 s (and on movement) to every
 * connected call peer AND every saved contact's mailbox, until cancelled.
 */
export class SOSBeacon extends LocationSharer {
  activate(send, note = '') {
    this.note = note;
    this.start('until', (f) => send({ ...f, note: this.note, sos: true }), { minIntervalMs: 20000 });
    navigator.vibrate?.([300, 100, 300, 100, 300]);
  }
}

/** Siren on the RECEIVING device (WebAudio — no audio file needed). */
export function playSiren(seconds = 6) {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.type = 'sawtooth'; o.connect(g); g.connect(ctx.destination); g.gain.value = 0.15;
    const t0 = ctx.currentTime;
    for (let i = 0; i < seconds * 2; i++) {
      o.frequency.setValueAtTime(880, t0 + i * 0.5);
      o.frequency.linearRampToValueAtTime(1320, t0 + i * 0.5 + 0.25);
    }
    o.start(); o.stop(t0 + seconds);
    o.onended = () => ctx.close();
    navigator.vibrate?.([500, 200, 500, 200, 500, 200, 500]);
  } catch { /* audio blocked until user gesture */ }
}
