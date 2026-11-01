// Hover info: point at any button or link (computer), tab to it (keyboard), or press and hold it
// for half a second (phone) to see what it does. Text comes from data-tip, then this list, then
// (for links) where the link goes. Built with textContent only — no HTML.
const TIPS = {
  // navigation
  Connect: 'Start a call or open a beacon you were sent',
  Call: 'Your current call',
  Chat: 'End-to-end encrypted messages in this call',
  Map: 'Share your live location with the people in the call',
  Settings: 'Your ID, photo, PIN lock, blocked callers and privacy',
  SOS: 'Send an emergency alert with your location to your saved connections',
  // starting and answering
  'Create beacon': 'Make a one-time encrypted invite link to send on WhatsApp',
  'Create a beacon': 'Make a one-time encrypted invite link to send on WhatsApp',
  Join: 'Open a beacon link you were sent',
  Voice: 'Ring this saved connection for a voice call',
  Video: 'Turn on your camera so they can see you (also a quick way to check it’s really them)',
  Remove: 'Delete this saved connection from this device',
  Answer: 'Answer the call (end-to-end encrypted)',
  Decline: 'Tell the caller you can’t take it; the invite stops working',
  Block: 'Decline and block this caller on this device',
  'Share beacon again': 'Send the invite again: ask them to use only the newest link',
  WhatsApp: 'Send the invite in WhatsApp',
  'Share…': 'Send the invite with another app',
  'Copy invite': 'Copy the invite message to paste anywhere',
  'Copy link': 'Copy just the short invite link',
  'Copy full link': 'Copy the long link: still works if the relay restarts',
  Done: 'Close this window',
  // in a call
  Mic: 'Mute your microphone',
  Muted: 'Unmute your microphone',
  Cam: 'Turn your camera off',
  'Cam off': 'Turn your camera back on',
  Flip: 'Switch between front and back camera',
  End: 'Hang up',
  'End for all': 'End the call for everyone; the invite stops working',
  Leave: 'Leave the call',
  'Switch to video': 'Turn on video to see who you’re talking to: rules out a cloned voice or someone in the middle',
  'Not now': 'Hide this check for now',
  'Words match': 'Mark this person as checked',
  'They don’t match': 'Someone may be intercepting: end the call now',
  'Yes, it’s them': 'You can see them: mark this person as checked',
  'No — end call': 'Not who you expected: end the call now',
  Send: 'Send your message (end-to-end encrypted)',
  'Stop sharing location': 'Stop sending your location',
  Unlock: 'Open WeKoNet with your PIN',
  OK: 'Close this message',
};
const PREFIX = [[/^Save connection/, 'Keep this person so you can call them and send them SOS alerts']];

const tip = document.createElement('div');
tip.className = 'tip'; tip.setAttribute('role', 'tooltip'); tip.id = 'wkn-tip'; tip.hidden = true;

function textFor(el) {
  if (el.dataset.tip) return el.dataset.tip;
  const label = (el.getAttribute('aria-label') && !TIPS[el.textContent.trim()] ? el.getAttribute('aria-label') : el.textContent).replace(/\s+/g, ' ').trim();
  if (TIPS[label]) return TIPS[label];
  for (const [re, t] of PREFIX) if (re.test(label)) return t;
  if (el.tagName === 'A' && el.href) {
    try {
      const u = new URL(el.href);
      if (/(^|\.)wa\.me$|whatsapp\.com$/.test(u.hostname)) return 'Opens WhatsApp';
      if (/github\.com$/.test(u.hostname)) return 'Opens GitHub (WeKoNet downloads)';
      if (/openstreetmap\.org$/.test(u.hostname)) return 'Opens OpenStreetMap, who make the map';
      if (u.origin !== location.origin) return `Opens ${u.hostname.replace(/^www\./, '')} in a new tab`;
    } catch { /* not a URL */ }
  }
  return null;
}

let current = null, hideTimer = null, press = null;
function show(el) {
  const t = textFor(el);
  if (!t) return;
  current = el;
  if (!tip.isConnected) document.body.append(tip);
  tip.textContent = t; tip.hidden = false;
  el.setAttribute('aria-describedby', 'wkn-tip');
  const host = el.closest('dialog[open]') || document.body; // inside a dialog, the tip must live there to show on top
  if (tip.parentNode !== host) host.append(tip);
  const r = el.getBoundingClientRect(), w = Math.min(280, innerWidth - 16);
  tip.style.maxWidth = `${w}px`;
  const tw = tip.offsetWidth, th = tip.offsetHeight;
  const x = Math.max(8, Math.min(innerWidth - tw - 8, r.left + r.width / 2 - tw / 2));
  let y = r.top - th - 8; if (y < 8) y = r.bottom + 8;
  tip.style.left = `${x}px`; tip.style.top = `${y}px`;
}
function hide() { current?.removeAttribute('aria-describedby'); current = null; tip.hidden = true; }
const target = (e) => e.target.closest?.('[data-tip], a[href], button, summary');

export function installTips() {
  document.addEventListener('pointerover', (e) => { if (e.pointerType === 'mouse') { const el = target(e); if (el && el !== current) show(el); } });
  document.addEventListener('pointerout', (e) => { if (e.pointerType === 'mouse' && current && !current.contains(e.relatedTarget)) hide(); });
  document.addEventListener('focusin', (e) => { const el = target(e); if (el && el.matches(':focus-visible')) show(el); });
  document.addEventListener('focusout', hide);
  document.addEventListener('click', hide, true);
  addEventListener('scroll', hide, { passive: true, capture: true });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hide(); });
  // Phones: press and hold to see what a button does.
  document.addEventListener('touchstart', (e) => {
    const el = target(e); if (!el) return;
    clearTimeout(press); press = setTimeout(() => { show(el); clearTimeout(hideTimer); hideTimer = setTimeout(hide, 2500); }, 500);
  }, { passive: true });
  for (const ev of ['touchend', 'touchmove', 'touchcancel']) document.addEventListener(ev, () => clearTimeout(press), { passive: true });
}
