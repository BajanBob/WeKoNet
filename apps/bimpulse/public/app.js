// Bim Pulse front end. No frameworks, no inline code, and every piece of text people
// submit is put on the page with textContent only (never parsed as HTML).
import { drawQR } from './qr.js';

const $ = (s) => document.querySelector(s);
const MAX = 100;
const ISLAND = [13.17, -59.55];
const state = { cats: [], summary: [], cat: null, rating: 0, lat: null, lon: null, photo: null, pickMap: null, pickPin: null, seeMap: null };

function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(e.dataset, v);
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k);
  return e;
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg; t.hidden = false;
  clearTimeout(toast.t); toast.t = setTimeout(() => { t.hidden = true; }, 3800);
}

async function api(path, body) {
  const r = await fetch(path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `Something went wrong (${r.status})`);
  return j;
}

const tone = (s) => `c${Math.min(5, Math.max(1, Math.round(s)))}`;
const ago = (t) => {
  const m = Math.round((Date.now() - t) / 60e3);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} hr ago`;
  return new Date(t).toLocaleDateString();
};
const catOf = (id) => state.cats.find((c) => c.id === id);

// ---------------- faceplate ----------------
async function loadPlate() {
  try {
    const [cats, sum] = await Promise.all([state.cats.length ? state.cats : api('/api/categories'), api('/api/summary')]);
    state.cats = cats; state.summary = sum.categories;
    renderPlate();
  } catch (e) {
    $('#plate').replaceChildren(el('p', { class: 'loading', text: `Could not load the scores. ${e.message}` }));
  }
}

function renderPlate() {
  const keys = state.summary.map((s) => {
    const c = catOf(s.id);
    const filled = s.score ? Math.round(s.score) : 0;
    const top = c.kind === 'best'
      ? (s.top ? `Top: ${s.top.name} · ${s.top.score.toFixed(1)}` : 'No ratings yet — be the first')
      : (s.count ? `${s.count} live ${s.count === 1 ? 'report' : 'reports'}${c.keepHours && c.keepHours < 24 ? ` · last ${c.keepHours} hr` : ''}` : 'Nothing reported yet');
    return el('button', { class: 'key', type: 'button', 'aria-label': `${s.name}: score ${s.score ?? 'none'}, ${s.count} reports`, onclick: () => openCat(s.id) },
      el('span', { class: 'key-name', text: s.name }),
      el('span', { class: 'lcd' },
        el('span', { class: `lcd-score ${s.score ? '' : 'none'}`, text: s.score ? s.score.toFixed(1) : '-.-' }),
        el('span', { class: 'lcd-count', text: `${s.count} ${s.count === 1 ? 'report' : 'reports'}` })),
      el('span', {},
        el('span', { class: `meter ${s.score ? tone(s.score) : ''}`, dataset: { s: String(filled) } }, el('i'), el('i'), el('i'), el('i'), el('i')),
        el('span', { class: 'key-top', text: top })));
  });
  keys.push(el('button', { class: 'key key-share', type: 'button', onclick: openShare },
    el('span', { class: 'key-name', text: 'Share Bim Pulse' }),
    el('span', { class: 'lcd' }, el('span', { class: 'lcd-score', text: 'QR' }), el('span', { class: 'lcd-count', text: 'WhatsApp' })),
    el('span', { class: 'key-top', text: 'Send it to friends — no sign-up' })));
  $('#plate').replaceChildren(...keys);
}

// ---------------- a section ----------------
function openCat(id, tab = 'add') {
  const c = catOf(id);
  if (!c) return;
  state.cat = c; state.rating = 0; state.photo = null; state.lat = state.lon = null;
  $('#sheet-title').textContent = c.name;
  $('#report-form').reset(); updateCount();
  $('#form-msg').textContent = ''; $('#form-msg').className = 'msg';
  $('#subject-wrap').hidden = !c.subject;
  $('#subject-label').textContent = c.subject ? `Name of the ${c.subject.toLowerCase()}` : '';
  $('#text').placeholder = c.kind === 'map'
    ? (c.id === 'potholes' ? 'Where is it and how bad? e.g. Deep hole by the bus stop, Hwy 7 Hastings' : 'Where and how slow? e.g. ABC Hwy backed up to Warrens')
    : 'Why this score? e.g. Friendly staff, fair price, quick service';
  $('#scale-low').textContent = `1 ${c.low}`; $('#scale-high').textContent = `5 ${c.high}`;
  $('#score-hint').textContent = c.kind === 'map' ? (c.id === 'potholes' ? '(how safe is the road?)' : '(how is traffic moving?)') : '';
  renderRating();
  $('#geo-block').hidden = c.kind !== 'map';
  $('#preview').hidden = true; $('#preview').removeAttribute('src');
  $('#loc-status').textContent = 'No location yet. Tap “Use my location”, or tap the map to drop a pin.';
  const dlg = $('#sheet');
  if (!dlg.open) dlg.showModal();
  setTab(tab);
  if (location.hash !== `#${c.id}`) history.replaceState(null, '', `#${c.id}`);
}

function setTab(which) {
  const add = which === 'add';
  $('#tab-add').setAttribute('aria-selected', String(add));
  $('#tab-see').setAttribute('aria-selected', String(!add));
  $('#pane-add').hidden = !add; $('#pane-see').hidden = add;
  if (add && state.cat.kind === 'map') setTimeout(mountPickMap, 0);
  if (!add) loadReports();
}

function renderRating() {
  const box = $('#rating');
  box.replaceChildren(...[1, 2, 3, 4, 5].map((n) => el('button', {
    class: `star c${n}`, type: 'button', role: 'radio', 'aria-checked': String(state.rating === n), 'aria-label': `${n}`, text: String(n),
    onclick: () => { state.rating = n; renderRating(); },
  })));
}

function updateCount() {
  const n = $('#text').value.length;
  const c = $('#count');
  c.textContent = `${n} / ${MAX}`;
  c.classList.toggle('full', n >= MAX);
}

// ---------------- photo + location ----------------
async function shrinkPhoto(file) {
  const bmp = await createImageBitmap(file);
  const scale = Math.min(1, 1280 / Math.max(bmp.width, bmp.height));
  const cv = document.createElement('canvas');
  cv.width = Math.round(bmp.width * scale); cv.height = Math.round(bmp.height * scale);
  cv.getContext('2d').drawImage(bmp, 0, 0, cv.width, cv.height);
  bmp.close?.();
  for (let q = 0.75; q >= 0.35; q -= 0.1) {
    const blob = await new Promise((r) => cv.toBlob(r, 'image/jpeg', q));
    if (blob && blob.size < 580 * 1024) return blob; // re-encoding also strips EXIF (hidden GPS, phone model)
  }
  throw new Error('Could not make that photo small enough');
}

const blobToB64 = (blob) => new Promise((ok, fail) => {
  const fr = new FileReader();
  fr.onload = () => ok(String(fr.result).split(',')[1]);
  fr.onerror = () => fail(new Error('Could not read the photo'));
  fr.readAsDataURL(blob);
});

function setPin(lat, lon, how) {
  state.lat = lat; state.lon = lon;
  $('#loc-status').textContent = `Pinned ${how}: ${lat.toFixed(5)}, ${lon.toFixed(5)}. Tap the map to move the pin.`;
  if (state.pickMap && window.L) {
    if (!state.pickPin) state.pickPin = L.circleMarker([lat, lon], { radius: 10, color: '#00267f', weight: 3, fillColor: '#ffc726', fillOpacity: 1 }).addTo(state.pickMap);
    else state.pickPin.setLatLng([lat, lon]);
    state.pickMap.setView([lat, lon], Math.max(state.pickMap.getZoom(), 16));
  }
}

function locate() {
  if (!navigator.geolocation) return toast('Location is not available on this device — tap the map instead');
  $('#loc-status').textContent = 'Finding your location…';
  navigator.geolocation.getCurrentPosition(
    (p) => setPin(p.coords.latitude, p.coords.longitude, `from your phone (±${Math.round(p.coords.accuracy)} m)`),
    () => { $('#loc-status').textContent = 'Location was not allowed. Tap the map to drop a pin instead.'; },
    { enableHighAccuracy: true, timeout: 15000, maximumAge: 30000 });
}

function baseMap(node) {
  if (!window.L) { node.classList.add('map-off'); node.textContent = 'Map unavailable — your location from “Use my location” is still saved with the report.'; return null; }
  const m = L.map(node, { zoomControl: true, attributionControl: true }).setView(ISLAND, 10);
  L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19, attribution: '© OpenStreetMap contributors' }).addTo(m);
  return m;
}

function mountPickMap() {
  const node = $('#pick-map');
  if (!state.pickMap) {
    state.pickMap = baseMap(node);
    state.pickMap?.on('click', (e) => setPin(e.latlng.lat, e.latlng.lng, 'on the map'));
  }
  if (state.pickPin) { state.pickPin.remove(); state.pickPin = null; }
  state.pickMap?.invalidateSize();
  state.pickMap?.setView(ISLAND, 10);
}

// ---------------- submit ----------------
async function submit(e) {
  e.preventDefault();
  const c = state.cat, msg = $('#form-msg');
  msg.className = 'msg err';
  const text = $('#text').value.trim();
  if (c.subject && !$('#subject').value.trim()) return (msg.textContent = `Name the ${c.subject.toLowerCase()} first.`);
  if (!text) return (msg.textContent = 'Write a short note — up to 100 characters.');
  if (text.length > MAX) return (msg.textContent = 'Keep it to 100 characters.');
  if (!state.rating) return (msg.textContent = 'Choose a score from 1 to 5.');
  if (c.needLoc && state.lat == null) return (msg.textContent = 'Pin the location: tap “Use my location” or tap the map.');
  const btn = $('#submit'); btn.disabled = true; btn.textContent = 'Sending…';
  try {
    await api('/api/submit', {
      cat: c.id, text, rating: state.rating, subject: c.subject ? $('#subject').value : undefined,
      lat: state.lat ?? undefined, lon: state.lon ?? undefined,
      photo: state.photo ? await blobToB64(state.photo) : undefined,
    });
    msg.className = 'msg'; msg.textContent = '';
    toast('Thanks — your report is live');
    await loadPlate();
    openCat(c.id, 'see');
  } catch (err) {
    msg.textContent = err.message;
  } finally { btn.disabled = false; btn.textContent = 'Send report'; }
}

// ---------------- see reports ----------------
async function loadReports() {
  const c = state.cat;
  const list = $('#reports'), leaders = $('#leaders'), mapNode = $('#see-map');
  list.replaceChildren(el('li', { class: 'empty', text: 'Loading…' }));
  leaders.hidden = c.kind !== 'best';
  mapNode.hidden = c.kind !== 'map';
  try {
    const { reports, leaders: top } = await api(`/api/reports?cat=${encodeURIComponent(c.id)}`);
    if (state.cat !== c) return;
    if (c.kind === 'best') {
      leaders.replaceChildren(...(top.length ? top.slice(0, 10).map((g) => el('li', {},
        el('span', { class: 'who' }, g.name, el('span', { class: 'n', text: `${g.count} ${g.count === 1 ? 'rating' : 'ratings'}` })),
        el('span', { class: `chip ${tone(g.score)}`, text: g.score.toFixed(1) })))
        : [el('li', { class: 'empty', text: 'No rankings yet. Add the first rating.' })]));
    }
    if (c.kind === 'map') drawSeeMap(reports);
    list.replaceChildren(...(reports.length ? reports.map((r) => reportItem(r, c)) : [el('li', { class: 'empty', text: 'No reports yet. Be the first.' })]));
  } catch (e) { list.replaceChildren(el('li', { class: 'empty', text: e.message })); }
}

function reportItem(r, c) {
  const where = r.lat != null ? el('a', { href: `https://www.google.com/maps?q=${r.lat},${r.lon}`, target: '_blank', rel: 'noopener noreferrer', text: 'Open in Maps' }) : null;
  const fixed = c.id === 'potholes' ? el('button', { class: 'linkbtn', type: 'button', text: r.fixed ? `Fixed? (${r.fixed} said yes)` : 'Mark as fixed', onclick: async (e) => {
    e.currentTarget.disabled = true;
    try { const j = await api('/api/fixed', { id: r.id }); toast(j.already ? 'You already marked this one' : 'Thanks — after 3 people say fixed, it comes off the map'); loadReports(); loadPlate(); } catch (err) { toast(err.message); }
  } }) : null;
  return el('li', { class: 'report' },
    el('span', { class: `chip ${tone(r.rating)}`, text: String(r.rating), 'aria-label': `Score ${r.rating} of 5` }),
    el('div', { class: 'body' },
      r.subject ? el('span', { class: 'subj', text: r.subject }) : null,
      el('span', { class: 'txt', text: r.text }),
      r.photo ? el('img', { src: `/photos/${r.id}.jpg`, alt: `Photo: ${r.text}`, loading: 'lazy' }) : null,
      el('span', { class: 'meta' }, el('span', { text: ago(r.at) }), where, fixed)));
}

function drawSeeMap(reports) {
  const node = $('#see-map');
  if (!state.seeMap) state.seeMap = baseMap(node);
  const m = state.seeMap;
  if (!m) return;
  state.seeLayer?.remove();
  const colours = { 1: '#d64545', 2: '#e7833a', 3: '#d9b31f', 4: '#6db33f', 5: '#2e9d5b' };
  const pts = reports.filter((r) => r.lat != null);
  state.seeLayer = L.layerGroup(pts.map((r) => L.circleMarker([r.lat, r.lon], { radius: 9, color: '#0a1e31', weight: 2, fillColor: colours[r.rating], fillOpacity: .95 })
    .bindPopup(() => el('div', {}, el('strong', { text: `Score ${r.rating}/5` }), el('br'), document.createTextNode(r.text), r.photo ? el('img', { src: `/photos/${r.id}.jpg`, alt: '', class: 'pop-img' }) : null, el('br'), document.createTextNode(ago(r.at)))))).addTo(m);
  setTimeout(() => {
    m.invalidateSize();
    if (pts.length) m.fitBounds(L.latLngBounds(pts.map((r) => [r.lat, r.lon])).pad(0.3), { maxZoom: 15 });
    else m.setView(ISLAND, 10);
  }, 0);
}

// ---------------- share ----------------
function openShare() {
  const url = `${location.origin}/`;
  const text = 'Bim Pulse — report potholes and traffic, and rate the best places in Barbados. Scores from 1 to 5, no sign-up:';
  $('#share-url').textContent = url;
  try { drawQR($('#qr'), url, { px: 8 }); } catch { /* never happens for a short URL */ }
  $('#wa').href = `https://wa.me/?text=${encodeURIComponent(`${text} ${url}`)}`;
  const ns = $('#native-share');
  ns.hidden = !navigator.share;
  ns.onclick = () => navigator.share({ title: 'Bim Pulse', text, url }).catch(() => {});
  $('#copy').onclick = () => navigator.clipboard?.writeText(url).then(() => toast('Link copied'), () => toast('Long-press the link to copy it'));
  $('#share-sheet').showModal();
}

// ---------------- wiring ----------------
function wire() {
  $('#share-btn').addEventListener('click', openShare);
  $('#share-close').addEventListener('click', () => $('#share-sheet').close());
  $('#sheet-close').addEventListener('click', () => $('#sheet').close());
  $('#sheet').addEventListener('close', () => { state.cat = null; history.replaceState(null, '', location.pathname); });
  $('#tab-add').addEventListener('click', () => setTab('add'));
  $('#tab-see').addEventListener('click', () => setTab('see'));
  $('#text').addEventListener('input', updateCount);
  $('#report-form').addEventListener('submit', submit);
  $('#locate').addEventListener('click', locate);
  $('#photo').addEventListener('change', async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      state.photo = await shrinkPhoto(f);
      const img = $('#preview');
      if (img.src) URL.revokeObjectURL(img.src);
      img.src = URL.createObjectURL(state.photo); img.hidden = false;
      if (state.lat == null) locate(); // point and shoot: pin where the photo was taken
    } catch (err) { toast(err.message); }
  });
  window.addEventListener('hashchange', () => { const id = location.hash.slice(1); if (catOf(id)) openCat(id); });
}

wire();
await loadPlate();
{ const id = location.hash.slice(1); if (catOf(id)) openCat(id); }
setInterval(() => { if (!document.hidden) loadPlate(); }, 60e3);
