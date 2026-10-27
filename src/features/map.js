// Map for SOS beacons and shared locations (Leaflet, bundled — no CDN).
// Markers are vector circles (no image assets, nothing for CSP to load).
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { h } from '../ui/sanitize.js';

export class PeerMap {
  constructor(container, tileUrl) {
    this.map = L.map(container, { zoomControl: true, attributionControl: true, worldCopyJump: true })
      .setView([13.1, -59.6], 11);
    L.tileLayer(tileUrl, { maxZoom: 19, attribution: '© OpenStreetMap contributors' }).addTo(this.map);
    this.marks = new Map();
  }

  /** Place / move a person's marker. kind: 'me' | 'peer' | 'sos' */
  upsert(key, { lat, lon, acc = 0, label, kind = 'peer', t = Date.now() }) {
    if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return;
    const color = kind === 'sos' ? '#ff2d55' : kind === 'me' ? '#2dd4bf' : '#818cf8';
    let m = this.marks.get(key);
    if (!m) {
      m = {
        dot: L.circleMarker([lat, lon], { radius: kind === 'sos' ? 12 : 8, color, fillColor: color, fillOpacity: 0.9, weight: 3, className: kind === 'sos' ? 'sos-pulse' : '' }).addTo(this.map),
        ring: L.circle([lat, lon], { radius: acc, color, weight: 1, fillOpacity: 0.08 }).addTo(this.map),
      };
      this.marks.set(key, m);
    }
    m.dot.setLatLng([lat, lon]); m.ring.setLatLng([lat, lon]); m.ring.setRadius(acc);
    m.dot.setStyle({ color, fillColor: color });
    // Popup content is a DOM node built with textContent — never an HTML string.
    const pop = h('div', { class: 'map-pop' },
      h('strong', { text: kind === 'sos' ? `SOS — ${label}` : label }),
      h('div', { text: `${lat.toFixed(5)}, ${lon.toFixed(5)} (±${Math.round(acc)} m)` }),
      h('div', { text: new Date(t).toLocaleTimeString() }),
      h('div', { class: 'map-links' },
        h('button', { class: 'btn-link', type: 'button', text: 'Open in maps', onclick: () => openExternalMap(lat, lon) })));
    m.dot.bindPopup(pop);
    if (kind === 'sos') { this.map.setView([lat, lon], 16); m.dot.openPopup(); }
  }

  remove(key) { const m = this.marks.get(key); if (m) { m.dot.remove(); m.ring.remove(); this.marks.delete(key); } }
  fit() { const pts = [...this.marks.values()].map((m) => m.dot.getLatLng()); if (pts.length) this.map.fitBounds(L.latLngBounds(pts).pad(0.3), { maxZoom: 16 }); }
  invalidate() { setTimeout(() => this.map.invalidateSize(), 50); }
}

export function openExternalMap(lat, lon) {
  const geo = `geo:${lat},${lon}?q=${lat},${lon}`;
  const web = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=17/${lat}/${lon}`;
  const isMobile = /Android|iPhone|iPad/i.test(navigator.userAgent);
  window.open(isMobile ? geo : web, '_blank', 'noopener,noreferrer');
}
