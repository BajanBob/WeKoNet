// WeKoNet Connect — application shell.
// Rules followed everywhere in this file:
//   • no inline scripts, no inline event handlers (addEventListener only)
//   • no innerHTML with untrusted data (h() builds DOM with textContent;
//     the only HTML path is the sanitizer's richText())
import './styles/base.css';
import './styles/plates.css';
import { CONFIG } from './config.js';
import { h, setRich } from './ui/sanitize.js';
import * as vault from './storage/vault.js';
import { createBeacon, openBeacon } from './crypto/beacon.js';
import { b64u, unb64u } from './crypto/util.js';
import { contactLinks, sealMail, openMail } from './crypto/contact.js';
import { CallSession, E2EE_MEDIA } from './net/mesh.js';
import { MailboxClient, warmRelay } from './net/signaling.js';
import { LocationSharer, SOSBeacon, playSiren, SHARE_DURATIONS } from './features/geo.js';
import { onBeacon, shareToWhatsApp, shareNative, platform, keepAlive } from './platform.js';

const $ = (sel) => document.querySelector(sel);

const S = {
  identity: null, call: null, beacon: null, role: null,
  peers: new Map(), messages: [], contacts: [], map: null,
  sharer: new LocationSharer(), sos: new SOSBeacon(), mail: null,
  plate: 'aurora', hideIp: false, autoJoinContacts: true, view: 'connect',
};

// ============================================================ boot
async function boot() {
  S.identity = await vault.unlock();
  S.plate = await vault.settings.get('plate', 'aurora');
  S.hideIp = await vault.settings.get('hideIp', false);
  S.autoJoinContacts = await vault.settings.get('autoJoinContacts', true);
  document.documentElement.dataset.plate = S.plate;
  $('#my-id').textContent = S.identity.id;
  $('#platform').textContent = platform;

  await loadContacts();
  S.messages = (await vault.list('message')).slice(-200);
  await vault.scheduleNightlyPurge((r) => { if (r === 'wiped') location.reload(); else if (r > 0) toast(`${r} expired item(s) removed`); });
  warmRelay(CONFIG.relayUrl);
  startMailbox();
  globalThis.wekonetDesktop?.onPurge(() => vault.purgeExpired());

  for (const b of document.querySelectorAll('[data-nav]')) b.addEventListener('click', () => go(b.dataset.nav));
  $('#sos-fab').addEventListener('click', () => go('sos'));
  go('connect');

  onBeacon((frag) => receiveBeacon(frag));
}

function go(view) {
  S.view = view;
  for (const b of document.querySelectorAll('[data-nav]')) b.setAttribute('aria-current', b.dataset.nav === view ? 'page' : 'false');
  const root = $('#view');
  root.replaceChildren(VIEWS[view]());
  if (S.call && view !== 'call') root.prepend(inCallStrip());
  root.focus({ preventScroll: true });
  if (view === 'map') mountMap();
}

function toast(msg, kind = 'info') {
  const t = h('div', { class: `toast toast-${kind}`, role: 'status', text: msg });
  $('#toasts').append(t);
  setTimeout(() => t.remove(), kind === 'danger' ? 9000 : 4500);
}

function modal(title, body, actions) {
  const dlg = h('dialog', { class: 'modal' },
    h('h2', { text: title }), body,
    h('div', { class: 'modal-actions' }, actions.map(([label, fn, cls]) =>
      h('button', { class: `btn ${cls || ''}`, type: 'button', text: label, onclick: () => { dlg.close(); dlg.remove(); fn?.(); } }))));
  document.body.append(dlg);
  dlg.showModal();
  return dlg;
}

// ============================================================ contacts + mailbox
async function loadContacts() {
  const rows = await vault.list('contact');
  S.contacts = [];
  for (const c of rows) {
    const links = await contactLinks(unb64u(c.pair), S.identity.pub, unb64u(c.pub));
    S.contacts.push({ ...c, links });
  }
}

function startMailbox() {
  if (S.mail || !S.contacts.length) { S.mail?.subscribe(S.contacts.map((c) => c.links.inbox)); return; }
  S.mail = new MailboxClient(CONFIG.relayUrl);
  S.mail.addEventListener('mail', async (e) => {
    const c = S.contacts.find((x) => x.links.inbox === e.detail.box);
    if (!c) return;
    try {
      const env = await openMail(c.links, e.detail.data);
      S.mail.ack(e.detail.box);
      if (env.kind === 'sos') onSOS(c.name || c.wid, env.body);
      if (env.kind === 'beacon') onContactBeacon(c, env.body);
    } catch { /* stale / replayed / forged → ignore */ }
  });
  S.mail.start();
  S.mail.subscribe(S.contacts.map((c) => c.links.inbox));
}

async function saveContact(peer) {
  const p = S.call?.peers.get(peer.peerId);
  if (!p?.session) return;
  const pub = b64u(p.session.peerPub);
  if (S.contacts.some((c) => c.pub === pub)) return toast('Already saved');
  const name = peer.name || peer.id;
  await vault.save('contact', { wid: peer.id, name, pub, pair: b64u(p.session.pairSecret), verified: !!peer.verified });
  await loadContacts(); startMailbox();
  toast(`${name} saved — they can now receive your SOS`);
}

// ============================================================ beacons
async function hostCall({ mode, max, linger, ttl }) {
  if (S.call) return toast('End the current call first', 'warn');
  try {
    const b = await createBeacon({ identity: S.identity, signalUrl: CONFIG.relayUrl, appBase: CONFIG.appBase, mode, linger, ttlMinutes: ttl, maxPeers: max });
    S.beacon = b; S.role = 'host';
    await vault.save('beacon', { room: b.payload.room, mode, max, linger }, { meta: { exp: b.payload.exp } });
    await startCall(b, 'host', mode);
    showShare(b);
  } catch (e) { toast(e.message, 'danger'); }
}

function showShare(b) {
  const text = `Join my private WeKoNet ${b.payload.mode} call (end-to-end encrypted, expires in ${Math.round((b.payload.exp - Date.now()) / 60e3)} min): ${b.link}`;
  modal('Send your beacon', h('div', {},
    h('p', { text: 'Anyone with this link can join until it expires or the call ends. Send it only to the people you want in the call.' }),
    h('code', { class: 'beacon-link', text: b.link }),
    h('p', { class: 'muted', text: 'The encryption key is after the “#”: it never reaches any server.' })), [
    ['WhatsApp', () => shareToWhatsApp(text), 'btn-wa'],
    ['Share…', () => shareNative(text)],
    ['Copy link', () => navigator.clipboard?.writeText(b.link).then(() => toast('Copied'))],
    ['Done', null, 'btn-ghost'],
  ]);
}

async function receiveBeacon(frag) {
  let o;
  try { o = await openBeacon(frag); } catch (e) { return toast(e.message, 'danger'); }
  if (S.call) return toast('Finish the current call before joining another', 'warn');
  const contact = S.contacts.find((c) => c.pub === o.payload.from);
  const firstRun = !(await vault.settings.get('kept', false)) && S.contacts.length === 0;
  if (firstRun) await vault.settings.set('guest', true);
  const who = contact ? `${contact.name} (${o.payload.fromId})` : o.payload.fromId;
  const join = () => startCall(o, 'guest', o.payload.mode).then(() => go('call')).catch((e) => toast(e.message, 'danger'));
  if (contact && S.autoJoinContacts) { toast(`Joining ${contact.name}’s beacon…`); return join(); }
  modal('Incoming WeKoNet beacon', h('div', {},
    h('p', {}, 'From ', h('strong', { text: who })),
    h('p', { text: `${modeLabel(o.payload.mode)} · up to ${o.payload.max} people · ${lingerLabel(o.payload.linger)}` }),
    h('p', { class: 'muted', text: contact ? 'Saved contact ✓' : 'Not a saved contact — compare the security words once connected.' })), [
    ['Join encrypted call', join, 'btn-primary'],
    ['Decline', null, 'btn-ghost'],
  ]);
}

async function onContactBeacon(c, body) {
  if (body?.link) receiveBeacon(body.link);
  else toast(`${c.name} sent a beacon`);
}

async function beaconContact(c, mode) {
  await hostCall({ mode, max: 2, linger: 'end', ttl: 30 });
  if (!S.beacon) return;
  S.mail?.post(c.links.outbox, await sealMail(c.links, 'beacon', { link: S.beacon.link }));
  toast(`Beacon sent to ${c.name} through WeKoNet`);
}

// ============================================================ call session
async function startCall(beacon, role, mode) {
  const call = new CallSession({ identity: S.identity, beacon, role, iceServers: CONFIG.iceServers, hideIp: S.hideIp });
  S.call = call; S.role = role; S.peers.clear();
  call.addEventListener('local-stream', (e) => { S.localStream = e.detail.stream; refresh('call'); });
  call.addEventListener('peer', (e) => {
    const d = e.detail;
    const c = S.contacts.find((x) => x.wid === d.id);
    S.peers.set(d.peer, { ...d, peerId: d.peer, name: c?.name || d.id, verified: !!c?.verified });
    toast(`${c?.name || d.id} connected · end-to-end encrypted`);
    refresh('call');
  });
  call.addEventListener('remote-track', (e) => { const p = S.peers.get(e.detail.peer); if (p) { p.stream = e.detail.stream; refresh('call'); } });
  call.addEventListener('peer-left', (e) => { const p = S.peers.get(e.detail.peer); S.peers.delete(e.detail.peer); S.map?.remove(e.detail.peer); if (p) toast(`${p.name} left (${e.detail.reason})`); refresh('call'); });
  call.addEventListener('message', (e) => onPeerMessage(e.detail));
  call.addEventListener('room', (e) => { S.deadline = e.detail.deadline; refresh('call'); });
  call.addEventListener('security', (e) => toast(`Security: ${e.detail.message}`, 'danger'));
  call.addEventListener('warning', (e) => toast(e.detail.message, 'warn'));
  call.addEventListener('error', (e) => toast(e.detail.message, 'danger'));
  call.addEventListener('ended', () => onCallEnded());
  await call.start(mode);
  keepAlive(true, `WeKoNet ${modeLabel(mode).toLowerCase()} · ${lingerLabel(beacon.payload.linger)}`);
  if (S.view !== 'call') go('call');
}

async function onPeerMessage({ peer, from, kind, body }) {
  const p = S.peers.get(peer);
  const name = p?.name || from;
  if (kind === 'text') {
    const m = { from: name, wid: from, dir: 'in', text: String(body.text || '').slice(0, 4000), createdAt: Date.now() };
    S.messages.push(m); await persistMessage(m); refresh('chat');
    if (S.view !== 'chat') toast(`${name}: ${m.text.slice(0, 60)}`);
  } else if (kind === 'loc') {
    S.map?.upsert(peer, { ...body, label: name, kind: 'peer' });
    if (p) p.loc = body;
  } else if (kind === 'sos') {
    onSOS(name, body, peer);
  }
}

async function persistMessage(m) {
  if (await vault.settings.get('guest', false)) return; // guests keep nothing
  await vault.save('message', m);
}

function onSOS(name, body, key = `sos-${name}`) {
  playSiren();
  S.pendingSOS = { name, body, key };
  toast(`🚨 SOS from ${name}`, 'danger');
  vault.save('sos', { from: name, ...body });
  go('map');
}

async function sendChat(text) {
  text = text.trim();
  if (!text || !S.call) return;
  await S.call.broadcast('text', { text });
  const m = { from: 'You', wid: S.identity.id, dir: 'out', text, createdAt: Date.now() };
  S.messages.push(m); await persistMessage(m); refresh('chat');
}

async function onCallEnded() {
  const wasGuest = await vault.settings.get('guest', false);
  const peers = [...S.peers.values()];
  S.call = null; S.peers.clear(); S.localStream = null; S.deadline = null;
  S.sharer.stop();
  keepAlive(false);
  refresh('call');
  if (wasGuest) {
    modal('Call ended — beacon expired', h('p', { text: 'Keep WeKoNet on this device? If you remove it, every key, message and setting is erased now.' }), [
      ['Keep WeKoNet', async () => { await vault.settings.set('guest', false); await vault.settings.set('kept', true); toast('WeKoNet kept. Your history auto-deletes after 3 hours.'); }, 'btn-primary'],
      ['Remove everything', async () => { await vault.wipeAll(); document.body.replaceChildren(h('main', { class: 'goodbye' }, h('h1', { text: 'WeKoNet removed' }), h('p', { text: 'All keys and data were erased. You can uninstall the app or close this page.' }))); }, 'btn-danger'],
    ]);
  } else if (peers.some((p) => !S.contacts.some((c) => c.wid === p.id))) {
    toast('Call ended. The beacon has expired.');
  }
}

// ============================================================ map / location / SOS
async function mountMap() {
  const el = $('#map');
  if (!el) return;
  const { PeerMap } = await import('./features/map.js');
  S.map = new PeerMap(el, CONFIG.tileUrl);
  for (const [id, p] of S.peers) if (p.loc) S.map.upsert(id, { ...p.loc, label: p.name });
  if (S.myLoc) S.map.upsert('me', { ...S.myLoc, label: 'You', kind: 'me' });
  if (S.pendingSOS) S.map.upsert(S.pendingSOS.key, { ...S.pendingSOS.body, label: S.pendingSOS.name, kind: 'sos' });
  S.map.invalidate();
}

function startSharing(dur) {
  try {
    S.sharer.start(dur, (f) => {
      S.myLoc = f;
      S.map?.upsert('me', { ...f, label: 'You', kind: 'me' });
      S.call?.broadcast('loc', f);
    });
    toast(`Sharing location ${dur === 'until' ? 'until you stop' : `for ${dur}`}`);
  } catch (e) { toast(e.message, 'danger'); }
  refresh('map');
}

async function activateSOS(note) {
  if (!S.call && !S.contacts.length) toast('No call or saved contacts — SOS will show on your screen only. Save a contact after a call to enable SOS alerts.', 'warn');
  S.sos.activate(async (fix) => {
    S.myLoc = fix;
    S.map?.upsert('me', { ...fix, label: 'You (SOS)', kind: 'sos' });
    await S.call?.broadcast('sos', fix);
    for (const c of S.contacts) S.mail?.post(c.links.outbox, await sealMail(c.links, 'sos', fix));
  }, note);
  document.documentElement.dataset.sos = 'on';
  await vault.save('sos', { from: 'You', note, t: Date.now() });
  refresh('sos');
}

function cancelSOS() { S.sos.stop(); delete document.documentElement.dataset.sos; toast('SOS cancelled'); refresh('sos'); }

// ============================================================ views
const modeLabel = (m) => ({ voice: 'Voice call', video: 'Video call', chat: 'Encrypted chat', sos: 'SOS' })[m] || m;
const lingerLabel = (l) => ({ end: 'ends with the call', '1h': 'open 1 hour', '2h': 'open 2 hours', day: 'open all day', live: 'kept live' })[l];

function refresh(view) { if (S.view === view) go(view); }

function endCall() {
  if (!S.call) return;
  S.call.end(S.role === 'host'); // the host ends it for everyone; a guest just leaves
}

/** Shown at the top of Connect / Chat / Map / Settings while a call is open. */
function inCallStrip() {
  return h('div', { class: 'incall' },
    h('span', { class: 'incall-dot' }),
    h('span', { class: 'incall-text', text: `${modeLabel(S.call.payload.mode)} in progress` }),
    h('button', { class: 'btn btn-sm', type: 'button', text: 'Open', onclick: () => go('call') }),
    h('button', { class: 'btn btn-danger btn-sm', type: 'button', text: 'End', 'aria-label': 'End call', onclick: endCall }));
}

function seg(name, options, initial) {
  const wrap = h('div', { class: 'seg', role: 'radiogroup', 'aria-label': name });
  for (const [val, label] of options) {
    const id = `${name}-${val}`;
    wrap.append(
      h('input', { type: 'radio', name, id, value: val, checked: val === initial }),
      h('label', { for: id, text: label }));
  }
  return wrap;
}
const segVal = (root, name) => root.querySelector(`input[name="${name}"]:checked`)?.value;

const VIEWS = {
  connect() {
    const form = h('section', { class: 'card hero' },
      h('p', { class: 'tagline', text: 'WeKoNet — the Disposable Chat Software' }),
      h('h2', { text: 'Start a WeKoNet call' }),
      h('p', { class: 'muted', text: 'No phone number. No email. A one-time encrypted beacon is the only way in.' }),
      h('div', { class: 'field' }, h('span', { class: 'label', text: 'Type' }), seg('mode', [['voice', 'Voice'], ['video', 'Video'], ['chat', 'Chat']], 'video')),
      h('div', { class: 'field' }, h('span', { class: 'label', text: 'People' }), seg('max', [['2', 'Two'], ['3', 'Three']], '2')),
      h('div', { class: 'field' }, h('span', { class: 'label', text: 'Keep connection open' }),
        seg('linger', [['end', 'Until call ends'], ['1h', '1 hr'], ['2h', '2 hr'], ['day', 'All day'], ['live', 'Keep live']], 'end')),
      h('div', { class: 'field' }, h('span', { class: 'label', text: 'Beacon valid for' }), seg('ttl', [['10', '10 min'], ['30', '30 min'], ['120', '2 hr']], '30')),
      h('button', {
        class: 'btn btn-primary btn-xl', type: 'button', text: 'Create beacon',
        onclick: () => hostCall({ mode: segVal(form, 'mode'), max: +segVal(form, 'max'), linger: segVal(form, 'linger'), ttl: +segVal(form, 'ttl') }),
      }));

    const input = h('input', { type: 'text', placeholder: 'Paste a WeKoNet beacon link', autocomplete: 'off', 'aria-label': 'Beacon link' });
    const join = h('section', { class: 'card' },
      h('h2', { text: 'Join with a beacon' }),
      h('div', { class: 'row' }, input, h('button', { class: 'btn', type: 'button', text: 'Join', onclick: () => receiveBeacon(input.value) })));

    const contacts = h('section', { class: 'card' }, h('h2', { text: 'Saved connections' }),
      S.contacts.length ? h('ul', { class: 'list' }, S.contacts.map((c) => h('li', { class: 'contact' },
        h('div', {}, h('strong', { text: c.name }), h('div', { class: 'mono muted', text: c.wid }), c.verified ? h('span', { class: 'badge ok', text: 'Verified' }) : h('span', { class: 'badge', text: 'Not verified' })),
        h('div', { class: 'row' },
          h('button', { class: 'btn btn-sm', type: 'button', text: 'Voice', onclick: () => beaconContact(c, 'voice') }),
          h('button', { class: 'btn btn-sm', type: 'button', text: 'Video', onclick: () => beaconContact(c, 'video') }),
          h('button', { class: 'btn btn-sm btn-ghost', type: 'button', text: 'Remove', onclick: async () => { await vault.remove(c.id); await loadContacts(); go('connect'); } })))))
        : h('p', { class: 'muted', text: 'After a call, tap “Save connection” to keep someone. Saved connections can receive your SOS.' }));
    return h('div', { class: 'stack' }, form, join, contacts);
  },

  call() {
    if (!S.call) {
      return h('div', { class: 'stack' }, h('section', { class: 'card empty' },
        h('h2', { text: 'No active call' }),
        h('p', { class: 'muted', text: 'Create a beacon or open one you were sent.' }),
        h('button', { class: 'btn btn-primary', type: 'button', text: 'Create a beacon', onclick: () => go('connect') })));
    }
    const tiles = h('div', { class: `grid n${1 + S.peers.size}` });
    const me = h('video', { class: 'tile-video', autoplay: true, playsinline: true, muted: true });
    if (S.localStream) me.srcObject = S.localStream;
    tiles.append(h('figure', { class: 'tile me' }, me, h('figcaption', { text: 'You' })));
    for (const p of S.peers.values()) {
      const v = h('video', { class: 'tile-video', autoplay: true, playsinline: true });
      if (p.stream) v.srcObject = p.stream;
      tiles.append(h('figure', { class: 'tile' }, v, h('figcaption', {},
        h('span', { text: p.name }),
        p.verified ? h('span', { class: 'badge ok', text: 'Verified' }) : h('span', { class: 'badge warn', text: 'Check words' }))));
    }
    const waiting = S.peers.size === 0 ? h('div', { class: 'waiting' },
      h('div', { class: 'pulse' }), h('p', { text: S.role === 'host' ? 'Waiting for your contact to open the beacon…' : 'Connecting securely…' }),
      S.role === 'host' && S.beacon ? h('button', { class: 'btn', type: 'button', text: 'Share beacon again', onclick: () => showShare(S.beacon) }) : null) : null;

    const verify = [...S.peers.values()].filter((p) => !p.verified).map((p) => h('section', { class: 'card sas' },
      h('h3', { text: `Read these words aloud with ${p.name}` }),
      h('p', { class: 'sas-words', text: p.sas }),
      h('p', { class: 'muted', text: 'If they see the same six words, nobody is intercepting the call.' }),
      h('div', { class: 'row' },
        h('button', { class: 'btn btn-primary btn-sm', type: 'button', text: 'Words match', onclick: () => { p.verified = true; refresh('call'); } }),
        h('button', { class: 'btn btn-danger btn-sm', type: 'button', text: 'They don’t match', onclick: () => { toast('Words differ — possible interception. Call ended.', 'danger'); S.call.end(true); } }))));

    let micOn = S.localStream?.getAudioTracks()[0]?.enabled ?? true;
    let camOn = S.localStream?.getVideoTracks()[0]?.enabled ?? true;
    const ctl = h('div', { class: 'controls' },
      h('button', { class: `ctl ${micOn ? '' : 'off'}`, type: 'button', 'aria-label': 'Microphone', text: micOn ? 'Mic' : 'Muted', onclick: (e) => { micOn = !micOn; S.call.toggleMic(micOn); e.currentTarget.textContent = micOn ? 'Mic' : 'Muted'; e.currentTarget.classList.toggle('off', !micOn); } }),
      h('button', { class: `ctl ${camOn ? '' : 'off'}`, type: 'button', 'aria-label': 'Camera', text: camOn ? 'Cam' : 'Cam off', onclick: (e) => { camOn = !camOn; S.call.toggleCam(camOn); e.currentTarget.textContent = camOn ? 'Cam' : 'Cam off'; e.currentTarget.classList.toggle('off', !camOn); } }),
      h('button', { class: 'ctl', type: 'button', text: 'Flip', 'aria-label': 'Switch camera', onclick: () => S.call.switchCamera() }),
      h('button', { class: 'ctl', type: 'button', text: 'Chat', onclick: () => go('chat') }),
      h('button', { class: 'ctl end', type: 'button', text: 'End', 'aria-label': 'End call', onclick: endCall }));

    const status = h('div', { class: 'callbar' },
      h('span', { class: 'lock', text: E2EE_MEDIA ? 'E2EE · X25519 + P-384 + ML-KEM-768' : 'DTLS-SRTP only on this device' }),
      h('span', { text: S.deadline ? `Open until ${new Date(S.deadline).toLocaleTimeString()}` : lingerLabel(S.call.payload.linger) }),
      h('button', { class: 'btn btn-danger btn-sm', type: 'button', text: S.role === 'host' ? 'End for all' : 'Leave', 'aria-label': 'End call', onclick: endCall }));

    const save = [...S.peers.values()].filter((p) => !S.contacts.some((c) => c.wid === p.id)).map((p) =>
      h('button', { class: 'btn btn-sm', type: 'button', text: `Save connection: ${p.name}`, onclick: () => saveContact(p) }));

    return h('div', { class: 'stack call' }, status, tiles, waiting, ...verify, ctl, save.length ? h('div', { class: 'row wrap' }, save) : null);
  },

  chat() {
    const log = h('ol', { class: 'chat', 'aria-live': 'polite' });
    for (const m of S.messages.slice(-200)) {
      const bubble = h('div', { class: 'bubble' });
      setRich(bubble, m.text); // sanitized: tiny tag allow-list, zero attributes
      log.append(h('li', { class: `msg ${m.dir}` },
        h('span', { class: 'who', text: `${m.from} · ${new Date(m.createdAt).toLocaleString()}` }), bubble));
    }
    const input = h('input', { type: 'text', placeholder: S.call ? 'Encrypted message…' : 'Start a call to chat', maxlength: 4000, disabled: !S.call, 'aria-label': 'Message' });
    const send = () => { sendChat(input.value); input.value = ''; };
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
    setTimeout(() => { log.lastElementChild?.scrollIntoView({ block: 'end' }); input.focus(); }, 0);
    return h('div', { class: 'chat-wrap' }, log,
      h('div', { class: 'composer' }, input,
        h('button', { class: 'btn btn-primary', type: 'button', text: 'Send', disabled: !S.call, onclick: send })));
  },

  map() {
    const root = h('div', { class: 'map-wrap' });
    const durs = Object.keys(SHARE_DURATIONS);
    const bar = h('div', { class: 'mapbar' },
      S.sharer.active
        ? h('button', { class: 'btn btn-danger btn-sm', type: 'button', text: 'Stop sharing location', onclick: () => { S.sharer.stop(); refresh('map'); } })
        : h('div', { class: 'row' }, h('span', { class: 'label', text: 'Share location:' }),
          durs.map((d) => h('button', { class: 'btn btn-sm', type: 'button', text: d === 'until' ? 'Until I stop' : d, onclick: () => startSharing(d) }))),
      h('button', { class: 'btn btn-sm btn-ghost', type: 'button', text: 'Fit all', onclick: () => S.map?.fit() }));
    const sosBanner = S.pendingSOS ? h('div', { class: 'sos-banner', role: 'alert' },
      h('strong', { text: `SOS — ${S.pendingSOS.name} needs help` }),
      h('span', { text: S.pendingSOS.body.note || '' }),
      h('button', { class: 'btn btn-sm', type: 'button', text: 'Acknowledge', onclick: () => { S.pendingSOS = null; refresh('map'); } })) : null;
    root.append(bar, sosBanner || '', h('div', { id: 'map', class: 'map', role: 'application', 'aria-label': 'Map' }));
    return root;
  },

  sos() {
    const active = S.sos.active;
    const note = h('input', { type: 'text', placeholder: 'Optional note, e.g. “car broke down”', maxlength: 140, 'aria-label': 'SOS note' });
    return h('div', { class: 'stack' }, h('section', { class: `card sos-card ${active ? 'live' : ''}` },
      h('h2', { text: active ? 'SOS is ON' : 'SOS help mode' }),
      h('p', { text: active
        ? `Your live location is being sent every 20 s to ${S.peers.size} call participant(s) and ${S.contacts.length} saved connection(s).`
        : 'Sends your live location, encrypted, to everyone in your call and to every saved WeKoNet connection. Their device sounds an alarm and opens the map.' }),
      active ? null : note,
      active
        ? h('button', { class: 'btn btn-xl', type: 'button', text: 'Cancel SOS', onclick: cancelSOS })
        : h('button', { class: 'btn btn-danger btn-xl sos-big', type: 'button', text: 'SEND SOS', onclick: () => activateSOS(note.value) }),
      h('p', { class: 'muted', text: 'WeKoNet is not an emergency service. If you are in danger, also call your local emergency number.' })));
  },

  settings() {
    const plates = [['aurora', 'Aurora', 'Deep night glass'], ['graphite', 'Graphite', 'Matte, high contrast'], ['daylight', 'Daylight', 'Warm and bright']];
    const plateRow = h('div', { class: 'plates' }, plates.map(([id, name, desc]) => h('button', {
      class: `plate-pick ${S.plate === id ? 'sel' : ''}`, type: 'button', dataset: { p: id }, 'aria-pressed': String(S.plate === id),
      onclick: async () => { S.plate = id; document.documentElement.dataset.plate = id; await vault.settings.set('plate', id); go('settings'); },
    }, h('span', { class: `swatch sw-${id}` }), h('strong', { text: name }), h('span', { class: 'muted', text: desc }))));

    const toggle = (label, key, val, hint) => {
      const cb = h('input', { type: 'checkbox', checked: val });
      cb.addEventListener('change', async () => { S[key] = cb.checked; await vault.settings.set(key, cb.checked); });
      return h('label', { class: 'toggle' }, cb, h('span', {}, h('strong', { text: label }), h('span', { class: 'muted', text: hint })));
    };

    return h('div', { class: 'stack' },
      h('section', { class: 'card' }, h('h2', { text: 'Face plate' }), plateRow),
      h('section', { class: 'card' }, h('h2', { text: 'Your WeKoNet ID' }),
        h('p', { class: 'mono big', text: S.identity.id }),
        h('p', { class: 'muted', text: 'Derived from your device’s P-384 identity key. People connect to you through beacons, never by phone number or email.' })),
      h('section', { class: 'card' }, h('h2', { text: 'Privacy' }),
        toggle('Hide my IP address', 'hideIp', S.hideIp, 'Route calls through the TURN relay so peers never see your IP (slightly higher latency).'),
        toggle('Auto-join saved connections', 'autoJoinContacts', S.autoJoinContacts, 'Beacons from saved, known contacts open straight into the call.')),
      h('section', { class: 'card' }, h('h2', { text: 'History & self-purge' }),
        h('ul', { class: 'facts' },
          h('li', { text: 'History (messages, calls, SOS) is encrypted on this device and deleted automatically after 3 hours.' }),
          h('li', { text: 'Expired items are removed every few minutes. Every night at 1:00 AM WeKoNet also purges expired beacons, location trails and temporary data (or everything, on a guest install).' }),
          h('li', { text: 'Beacons expire when the call ends unless you chose 1 hr, 2 hr, all day or keep live.' })),
        h('div', { class: 'row wrap' },
          h('button', { class: 'btn', type: 'button', text: 'Purge expired now', onclick: async () => toast(`Removed ${await vault.purgeExpired()} item(s)`) }),
          h('button', { class: 'btn btn-danger', type: 'button', text: 'Erase everything', onclick: () => modal('Erase WeKoNet?', h('p', { text: 'This destroys your identity, contacts and history on this device. It cannot be undone.' }), [
            ['Erase', async () => { await vault.wipeAll(); location.reload(); }, 'btn-danger'], ['Cancel', null, 'btn-ghost']]) }))),
      h('section', { class: 'card' }, h('h2', { text: 'Security' }),
        h('ul', { class: 'facts' },
          h('li', { text: 'Handshake: X25519 + ECDH P-384 + ML-KEM-768, HKDF-SHA-384 → separate keys per purpose and direction.' }),
          h('li', { text: 'Messages, locations, SOS: AES-256-GCM with a per-message ratchet (forward secrecy).' }),
          h('li', { text: `Voice/video: per-frame AES-256-GCM ${E2EE_MEDIA ? '(active on this device)' : '(not supported here — DTLS-SRTP only)'} inside DTLS-SRTP.` }),
          h('li', { text: 'Anti-MITM: signed transcripts, key confirmation, beacon-pinned inviter identity, 6-word voice check.' }),
          h('li', { text: 'Strict CSP + Trusted Types: no inline script, no inline handlers, no remote code.' }))));
  },
};

boot().catch((e) => {
  console.error(e);
  document.body.replaceChildren(h('main', { class: 'goodbye' }, h('h1', { text: 'WeKoNet could not start' }), h('p', { text: e.message })));
});
