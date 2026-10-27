// Per-frame AES-256-GCM for voice/video (end-to-end, on top of DTLS-SRTP).
// Frame layout:  [clear codec header][ciphertext + 16-byte tag][12-byte IV]
// IV = 4-byte random sender salt ‖ 64-bit counter → never repeats under one key.
// Used inside the media worker (RTCRtpScriptTransform / Insertable Streams).

export class FrameCrypter {
  static async create(rawKey) {
    const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return new FrameCrypter(key);
  }

  constructor(key) {
    this.key = key;
    this.salt = crypto.getRandomValues(new Uint8Array(4));
    this.counter = 0n;
  }

  async encrypt(frame, clearBytes) {
    const n = Math.min(clearBytes, frame.length);
    const iv = new Uint8Array(12);
    iv.set(this.salt, 0);
    new DataView(iv.buffer).setBigUint64(4, this.counter++);
    const header = frame.subarray(0, n);
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 }, this.key, frame.subarray(n),
    ));
    const out = new Uint8Array(n + ct.length + 12);
    out.set(header, 0); out.set(ct, n); out.set(iv, n + ct.length);
    return out;
  }

  async decrypt(frame, clearBytes) {
    const n = Math.min(clearBytes, frame.length);
    if (frame.length < n + 16 + 12) throw new Error('frame too short');
    const iv = frame.subarray(frame.length - 12);
    const header = frame.subarray(0, n);
    const pt = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: header, tagLength: 128 }, this.key, frame.subarray(n, frame.length - 12),
    ));
    const out = new Uint8Array(n + pt.length);
    out.set(header, 0); out.set(pt, n);
    return out;
  }
}

/** Bytes left unencrypted so the RTP packetizer still works (VP8 / Opus). */
export function clearHeaderBytes(kind, frameType) {
  if (kind === 'audio') return 1;            // Opus TOC byte
  return frameType === 'key' ? 10 : 3;       // VP8 payload header
}
