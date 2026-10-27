// Client for the blind relay. Every payload is AES-256-GCM sealed with the
// beacon-derived signaling key before it leaves the device, and bound (AAD) to
// the room + sender + recipient so the relay cannot replay it to someone else.
import { lp, b64u, unb64u } from '../crypto/util.js';
import { sealJSON, openJSON } from '../crypto/aead.js';

export class Signaling extends EventTarget {
  constructor(url, keys) {
    super();
    if (!/^wss:\/\//.test(url) && !/^ws:\/\/(localhost|127\.0\.0\.1)/.test(url)) throw new Error('relay must use wss://');
    this.url = url; this.keys = keys; this.peer = null; this.ws = null; this.pending = [];
  }

  connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.url);
      this.ws = ws;
      ws.onopen = () => { for (const m of this.pending.splice(0)) ws.send(m); resolve(); };
      ws.onerror = () => reject(new Error('Cannot reach the WeKoNet relay'));
      ws.onclose = () => this.dispatchEvent(new CustomEvent('closed'));
      let chain = Promise.resolve(); // keep relay messages in order
      ws.onmessage = (e) => {
        chain = chain.then(() => this.#onMessage(e.data)).catch((err) => this.#emit('warning', { message: err.message }));
      };
    });
  }

  #emit(type, detail) { this.dispatchEvent(new CustomEvent(type, { detail })); }

  raw(obj) {
    const s = JSON.stringify(obj);
    if (this.ws?.readyState === 1) this.ws.send(s); else this.pending.push(s);
  }

  create({ max, linger, exp }) {
    this.raw({ op: 'create', room: this.keys.roomTag, proof: this.keys.joinProof, max, linger, exp });
  }

  join() { this.raw({ op: 'join', room: this.keys.roomTag, proof: this.keys.joinProof }); }

  async send(to, obj) {
    const aad = lp(this.keys.roomTag, this.peer, to);
    const data = b64u(await sealJSON(this.keys.sigKey, obj, aad));
    this.raw({ op: 'signal', to, data });
  }

  leave() { this.raw({ op: 'leave' }); }
  endForAll() { this.raw({ op: 'end' }); }
  close() { try { this.ws?.close(); } catch { /* already closed */ } }

  async #onMessage(text) {
    const m = JSON.parse(text);
    switch (m.op) {
      case 'joined': this.peer = m.peer; return this.#emit('joined', m);
      case 'peer-joined': return this.#emit('peer-joined', m);
      case 'peer-left': return this.#emit('peer-left', m);
      case 'ended': return this.#emit('ended', m);
      case 'error': return this.#emit('relay-error', m);
      case 'mail': return this.#emit('mail', m);
      case 'signal': {
        const aad = lp(this.keys.roomTag, m.from, this.peer);
        let obj;
        try { obj = await openJSON(this.keys.sigKey, unb64u(m.data), aad); }
        catch { return this.#emit('tampered', { from: m.from }); } // failed AES-GCM authentication
        return this.#emit('signal', { from: m.from, msg: obj });
      }
      default: return undefined;
    }
  }
}

/** Separate long-lived connection used only for SOS / contact mailboxes. */
export class MailboxClient extends EventTarget {
  constructor(url) { super(); this.url = url; this.boxes = new Set(); this.ws = null; this.backoff = 1000; }

  start() {
    const ws = new WebSocket(this.url);
    this.ws = ws;
    ws.onopen = () => { this.backoff = 1000; if (this.boxes.size) ws.send(JSON.stringify({ op: 'sub', boxes: [...this.boxes] })); };
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.op === 'mail') this.dispatchEvent(new CustomEvent('mail', { detail: m }));
    };
    ws.onclose = () => { this.ws = null; setTimeout(() => this.start(), (this.backoff = Math.min(this.backoff * 2, 60e3))); };
  }

  subscribe(boxes) {
    for (const b of boxes) this.boxes.add(b);
    if (this.ws?.readyState === 1) this.ws.send(JSON.stringify({ op: 'sub', boxes }));
  }

  post(box, data) { this.ws?.readyState === 1 && this.ws.send(JSON.stringify({ op: 'post', box, data })); }
  ack(box) { this.ws?.readyState === 1 && this.ws.send(JSON.stringify({ op: 'ack', box })); }
}
