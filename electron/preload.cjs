// Minimal, frozen bridge. The page gets exactly two callbacks — nothing else
// from Node or Electron is reachable from web content.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('wekonetDesktop', Object.freeze({
  onBeacon(cb) {
    ipcRenderer.on('wekonet:beacon', (_e, url) => {
      if (typeof url === 'string' && /^wekonet:\/\/b#v1\./.test(url)) cb(url);
    });
  },
  onPurge(cb) { ipcRenderer.on('wekonet:purge', () => cb()); },
}));
