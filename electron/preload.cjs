// Minimal, frozen bridge. The page gets two callbacks and one on/off switch — nothing else
// from Node or Electron is reachable from web content.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('wekonetDesktop', Object.freeze({
  onBeacon(cb) {
    ipcRenderer.on('wekonet:beacon', (_e, url) => {
      if (typeof url === 'string' && /^wekonet:\/\/b#v1\./.test(url)) cb(url);
    });
  },
  onPurge(cb) { ipcRenderer.on('wekonet:purge', () => cb()); },
  setKeepAlive(on) { ipcRenderer.send('wekonet:keep-alive', on === true); },
}));
