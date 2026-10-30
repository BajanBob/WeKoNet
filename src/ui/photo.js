// Caller photos: shrunk on this device to a small JPEG (≈5 KB) before it is ever
// stored or sent, and shown only through blob: URLs (no HTML, no remote images).
import { CARD_PHOTO_MAX } from '../crypto/beacon.js';

const SIZE = 112;

/** Picture file → small square JPEG bytes (centre-cropped, metadata/EXIF dropped). */
export async function makeThumb(file) {
  if (!file || !/^image\//.test(file.type)) throw new Error('Choose a picture file');
  if (file.size > 25e6) throw new Error('That picture is too large');
  const bmp = await createImageBitmap(file);
  const c = document.createElement('canvas');
  c.width = c.height = SIZE;
  const g = c.getContext('2d');
  const side = Math.min(bmp.width, bmp.height);
  g.drawImage(bmp, (bmp.width - side) / 2, (bmp.height - side) / 2, side, side, 0, 0, SIZE, SIZE);
  bmp.close?.();
  for (let q = 0.82; q >= 0.3; q -= 0.12) {
    const blob = await new Promise((r) => c.toBlob(r, 'image/jpeg', q));
    if (blob && blob.size <= CARD_PHOTO_MAX) return new Uint8Array(await blob.arrayBuffer());
  }
  throw new Error('Could not make that picture small enough');
}

/** True for plausible JPEG bytes within the size limit (received photos are checked again here). */
export const isPhoto = (b) => b instanceof Uint8Array && b.length > 4 && b.length <= CARD_PHOTO_MAX && b[0] === 0xff && b[1] === 0xd8;

/** <img> for photo bytes; the blob URL is released once the image has loaded. */
export function photoImg(bytes, cls = 'avatar', alt = '') {
  const img = document.createElement('img');
  img.className = cls;
  img.alt = alt;
  img.decoding = 'async';
  if (!isPhoto(bytes)) return img;
  const url = URL.createObjectURL(new Blob([bytes], { type: 'image/jpeg' }));
  img.addEventListener('load', () => URL.revokeObjectURL(url), { once: true });
  img.addEventListener('error', () => { URL.revokeObjectURL(url); img.remove(); }, { once: true });
  img.src = url;
  return img;
}
