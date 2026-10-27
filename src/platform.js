// Platform glue: receives beacon links from wherever they arrive.
//   • Web / PWA / Raspberry Pi browser: https://wekonet.app/b/#v1...
//   • Android / iOS (Capacitor):  App Links / Universal Links + wekonet:// scheme
//   • Windows / Linux (Electron): wekonet:// protocol handler via preload bridge
import { Capacitor } from '@capacitor/core';
import { App } from '@capacitor/app';

export const platform = Capacitor.isNativePlatform()
  ? Capacitor.getPlatform()                 // 'android' | 'ios'
  : (globalThis.wekonetDesktop ? 'desktop' : 'web');

export function onBeacon(cb) {
  const fromHash = () => {
    if (/^#v1\./.test(location.hash)) {
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
      const i = url.indexOf('#v1.');
      if (i >= 0) cb(url.slice(i));
    });
  }
  globalThis.wekonetDesktop?.onBeacon((url) => {
    const i = String(url).indexOf('#v1.');
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
