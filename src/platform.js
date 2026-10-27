// Platform glue: receives beacon links from wherever they arrive.
//   • Web / PWA / Raspberry Pi browser: https://wekonet.app/b/#v2... or #s...
//   • Android / iOS (Capacitor):  App Links / Universal Links + wekonet:// scheme
//   • Windows / Linux (Electron): wekonet:// protocol handler via preload bridge
import { Capacitor, registerPlugin } from '@capacitor/core';
import { App } from '@capacitor/app';

export const platform = Capacitor.isNativePlatform()
  ? Capacitor.getPlatform()                 // 'android' | 'ios'
  : (globalThis.wekonetDesktop ? 'desktop' : 'web');

const BEACON_HASH = /^#(?:v1|v2|s)\./;
const BEACON_IN_URL = /#(?:v1|v2|s)\./;

export function onBeacon(cb) {
  const fromHash = () => {
    if (BEACON_HASH.test(location.hash)) {
      const frag = location.hash;
      // Remove the key from the address bar / history immediately.
      history.replaceState(null, '', location.pathname);
      cb(frag);
    }
  };
  fromHash();
  window.addEventListener('hashchange', fromHash);

  if (Capacitor.isNativePlatform()) {
    App.addListener('appUrlOpen', ({ url }) => {
      const i = url.search(BEACON_IN_URL);
      if (i >= 0) cb(url.slice(i));
    });
  }
  globalThis.wekonetDesktop?.onBeacon((url) => {
    const i = String(url).search(BEACON_IN_URL);
    if (i >= 0) cb(String(url).slice(i));
  });
}

export function shareToWhatsApp(text) {
  const url = `https://wa.me/?text=${encodeURIComponent(text)}`;
  window.open(url, '_blank', 'noopener,noreferrer');
}

export async function shareNative(text) {
  if (navigator.share) { try { await navigator.share({ text }); return true; } catch { return false; } }
  return false;
}

// ---------- keep running in the background (like WhatsApp) ----------
// While a call or a lingering beacon room is open — for every "Keep connection
// open" option — the app keeps its connection alive when it is sent to the
// background:
//   • Android: a foreground service with a "WeKoNet is connected" notification
//   • Windows / Linux / Pi: closing the window hides WeKoNet to the tray
//   • iOS: background audio/VoIP mode keeps an active call alive
const KeepAlive = Capacitor.isNativePlatform() && Capacitor.getPlatform() === 'android'
  ? registerPlugin('KeepAlive') : null;

export async function keepAlive(on, text = 'WeKoNet is connected') {
  try {
    if (KeepAlive) await (on ? KeepAlive.start({ text: String(text).slice(0, 80) }) : KeepAlive.stop());
    globalThis.wekonetDesktop?.setKeepAlive?.(!!on);
  } catch { /* background mode unavailable — the call still works in the foreground */ }
}
