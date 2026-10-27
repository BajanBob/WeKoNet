// Media E2EE worker: encrypts outgoing / decrypts incoming encoded audio+video
// frames with AES-256-GCM. Supports both the standard RTCRtpScriptTransform
// (Safari, Firefox, iOS) and Chromium Insertable Streams (Android, Windows, Pi).
import { FrameCrypter, clearHeaderBytes } from '../crypto/frames.js';

async function pipe(readable, writable, { op, key, kind }) {
  const fc = await FrameCrypter.create(new Uint8Array(key));
  const ts = new TransformStream({
    async transform(frame, ctl) {
      const data = new Uint8Array(frame.data);
      const clear = clearHeaderBytes(kind, frame.type);
      try {
        const out = op === 'encrypt' ? await fc.encrypt(data, clear) : await fc.decrypt(data, clear);
        frame.data = out.buffer;
        ctl.enqueue(frame);
      } catch {
        // Undecryptable frame (tampered, wrong key, or unencrypted): drop it.
        // We NEVER pass plaintext through on decrypt failure.
      }
    },
  });
  readable.pipeThrough(ts).pipeTo(writable).catch(() => {});
}

// Standard API
self.onrtctransform = (event) => {
  const t = event.transformer;
  pipe(t.readable, t.writable, t.options);
};

// Chromium Insertable Streams
self.onmessage = (e) => {
  const { readable, writable, op, key, kind } = e.data || {};
  if (readable && writable) pipe(readable, writable, { op, key, kind });
};
