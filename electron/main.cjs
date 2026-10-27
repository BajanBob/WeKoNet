// WeKoNet desktop shell (Windows .exe, Linux x64, Raspberry Pi arm64).
// Hardened Electron: sandboxed renderer, no Node in the page, context isolation,
// custom app:// origin (so CSP 'self' is meaningful), navigation locked down,
// only camera / microphone / geolocation permissions ever granted.
const { app, BrowserWindow, protocol, net, session, shell, Menu, Tray, nativeImage, ipcMain } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const DIST = path.join(__dirname, '..', 'dist');
let win = null;
let tray = null;
let keepAlive = false;   // true while a call / lingering beacon room is open
let quitting = false;
let pendingBeacon = process.argv.find((a) => a.startsWith('wekonet://')) || null;

protocol.registerSchemesAsPrivileged([
  { scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true, stream: true } },
]);

if (!app.requestSingleInstanceLock()) app.quit();
app.on('second-instance', (_e, argv) => {
  const url = argv.find((a) => a.startsWith('wekonet://'));
  if (url) deliverBeacon(url);
  if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
});
app.on('open-url', (e, url) => { e.preventDefault(); deliverBeacon(url); }); // macOS
app.setAsDefaultProtocolClient('wekonet');

function deliverBeacon(url) {
  if (!/^wekonet:\/\/b#v1\./.test(url)) return;
  if (win?.webContents && !win.webContents.isLoading()) win.webContents.send('wekonet:beacon', url);
  else pendingBeacon = url;
}

function createWindow() {
  win = new BrowserWindow({
    width: 1100, height: 760, minWidth: 360, minHeight: 560,
    backgroundColor: '#070b18', title: 'WeKoNet', autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true, sandbox: true, nodeIntegration: false,
      webSecurity: true, allowRunningInsecureContent: false,
      spellcheck: false, devTools: !app.isPackaged,
      backgroundThrottling: false, // keep the connection alive when hidden / minimised
    },
  });
  win.loadURL('app://wekonet/index.html');
  win.webContents.on('did-finish-load', () => { if (pendingBeacon) { win.webContents.send('wekonet:beacon', pendingBeacon); pendingBeacon = null; } });

  // Never navigate away from the app; open https links (WhatsApp, maps) externally.
  win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('app://wekonet/')) e.preventDefault(); });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//.test(url) || /^geo:/.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-attach-webview', (e) => e.preventDefault());

  // Like WhatsApp: while a call or lingering beacon is open, closing the
  // window hides WeKoNet to the tray instead of quitting.
  win.on('close', (e) => {
    if (keepAlive && !quitting) { e.preventDefault(); win.hide(); showTray(); }
  });
}

function showWindow() {
  if (!win) createWindow();
  win.show(); if (win.isMinimized()) win.restore(); win.focus();
}

function showTray() {
  if (tray) return;
  const icon = nativeImage.createFromPath(path.join(DIST, 'icon-192.png')).resize({ width: 16, height: 16 });
  tray = new Tray(icon);
  tray.setToolTip('WeKoNet — connected in the background');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Open WeKoNet', click: showWindow },
    { type: 'separator' },
    { label: 'Quit WeKoNet (ends the call)', click: () => { quitting = true; app.quit(); } },
  ]));
  tray.on('click', showWindow);
}

function hideTray() { tray?.destroy(); tray = null; }

ipcMain.on('wekonet:keep-alive', (e, on) => {
  if (!win || e.sender !== win.webContents) return;
  keepAlive = on === true;
  if (keepAlive) showTray(); else if (win.isVisible()) hideTray();
  if (!keepAlive && !win.isVisible()) { quitting = true; app.quit(); } // call ended while hidden
});

// Nightly 01:00 self-purge also runs from the main process (clears caches,
// storage of expired items happens in the renderer's scheduler).
function scheduleNightly() {
  const now = new Date(); const next = new Date(now); next.setHours(1, 0, 0, 0);
  if (next <= now) next.setDate(next.getDate() + 1);
  setTimeout(async () => {
    await session.defaultSession.clearCache();
    await session.defaultSession.clearStorageData({ storages: ['cachestorage', 'shadercache', 'serviceworkers'] });
    win?.webContents.send('wekonet:purge');
    scheduleNightly();
  }, next - now);
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);

  protocol.handle('app', (req) => {
    const { pathname } = new URL(req.url);
    const file = path.normalize(path.join(DIST, decodeURIComponent(pathname)));
    if (!file.startsWith(DIST)) return new Response('Forbidden', { status: 403 });
    return net.fetch(pathToFileURL(file).toString());
  });

  const ses = session.defaultSession;
  const allowed = new Set(['media', 'geolocation', 'clipboard-sanitized-write']);
  ses.setPermissionRequestHandler((wc, perm, cb) => cb(allowed.has(perm) && wc.getURL().startsWith('app://wekonet/')));
  ses.setPermissionCheckHandler((wc, perm) => allowed.has(perm));

  // Enforce CSP as a real header too (defence in depth over the <meta> tag).
  const fs = require('node:fs');
  let csp = '';
  try { csp = fs.readFileSync(path.join(DIST, 'csp.txt'), 'utf8'); } catch { /* dev */ }
  ses.webRequest.onHeadersReceived((d, cb) => {
    const h = { ...d.responseHeaders };
    if (csp) h['Content-Security-Policy'] = [`${csp}; frame-ancestors 'none'`];
    h['X-Content-Type-Options'] = ['nosniff'];
    h['Referrer-Policy'] = ['no-referrer'];
    cb({ responseHeaders: h });
  });

  createWindow();
  scheduleNightly();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('before-quit', () => { quitting = true; });
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('web-contents-created', (_e, wc) => wc.on('will-redirect', (e, url) => { if (!url.startsWith('app://wekonet/')) e.preventDefault(); }));
