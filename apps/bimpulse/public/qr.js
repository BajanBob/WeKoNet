// Minimal QR code encoder (byte mode, versions 1–25, error correction M or L).
// No dependencies, no network, no HTML: returns a boolean matrix and can paint
// it onto a <canvas>. Follows ISO/IEC 18004 (same structure as Nayuki's
// reference implementation).

const ECC = {
  M: { bits: 0, perBlock: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28],
    blocks: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21] },
  L: { bits: 1, perBlock: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26],
    blocks: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12] },
};
const MAX_VERSION = 25;

function rawModules(ver) {
  let r = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2;
    r -= (25 * n - 10) * n - 55;
    if (ver >= 7) r -= 36;
  }
  return r;
}
const dataCodewords = (ver, e) => Math.floor(rawModules(ver) / 8) - ECC[e].perBlock[ver] * ECC[e].blocks[ver];

// ---------- Reed–Solomon over GF(256), polynomial 0x11D ----------
function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}
function rsDivisor(degree) {
  const r = new Array(degree).fill(0);
  r[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < r.length; j++) {
      r[j] = gfMul(r[j], root);
      if (j + 1 < r.length) r[j] ^= r[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return r;
}
export function rsRemainder(data, degree) {
  const div = rsDivisor(degree);
  const r = new Array(degree).fill(0);
  for (const b of data) {
    const f = b ^ r.shift();
    r.push(0);
    div.forEach((c, i) => { r[i] ^= gfMul(c, f); });
  }
  return r;
}

// ---------- codewords ----------
function encodeData(bytes, ver, e) {
  const bits = [];
  const put = (v, n) => { for (let i = n - 1; i >= 0; i--) bits.push((v >>> i) & 1); };
  put(0b0100, 4);                       // byte mode
  put(bytes.length, ver <= 9 ? 8 : 16); // character count
  for (const b of bytes) put(b, 8);
  const cap = dataCodewords(ver, e) * 8;
  put(0, Math.min(4, cap - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) put(pad, 8);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) out.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  return out;
}

function interleave(data, ver, e) {
  const nBlocks = ECC[e].blocks[ver], eccLen = ECC[e].perBlock[ver];
  const raw = Math.floor(rawModules(ver) / 8);
  const nShort = nBlocks - (raw % nBlocks), shortLen = Math.floor(raw / nBlocks);
  const blocks = [];
  for (let i = 0, k = 0; i < nBlocks; i++) {
    const len = shortLen - eccLen + (i < nShort ? 0 : 1);
    const d = data.slice(k, k + len); k += len;
    const ecc = rsRemainder(d, eccLen);
    if (i < nShort) d.push(0); // placeholder so all blocks line up
    blocks.push(d.concat(ecc));
  }
  const out = [];
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((b, j) => { if (i !== shortLen - eccLen || j >= nShort) out.push(b[i]); });
  }
  return out;
}

// ---------- matrix ----------
function alignmentPositions(ver) {
  if (ver === 1) return [];
  const n = Math.floor(ver / 7) + 2;
  const step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (n * 2 - 2)) * 2;
  const out = [6];
  for (let p = ver * 4 + 10; out.length < n; p -= step) out.splice(1, 0, p);
  return out;
}

function build(codewords, ver, e, mask) {
  const size = ver * 4 + 17;
  const m = Array.from({ length: size }, () => new Array(size).fill(false));
  const fn = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, v) => { m[y][x] = v; fn[y][x] = true; };

  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); } // timing
  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy;
      if (x < 0 || y < 0 || x >= size || y >= size) continue;
      const d = Math.max(Math.abs(dx), Math.abs(dy));
      set(x, y, d !== 2 && d !== 4);
    }
  };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
  const al = alignmentPositions(ver);
  for (let i = 0; i < al.length; i++) for (let j = 0; j < al.length; j++) {
    if ((i === 0 && j === 0) || (i === 0 && j === al.length - 1) || (i === al.length - 1 && j === 0)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(al[i] + dx, al[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  drawFormat(m, fn, size, e, mask, set);
  if (ver >= 7) {
    let rem = ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (ver << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = ((bits >>> i) & 1) === 1;
      const a = size - 11 + (i % 3), b = Math.floor(i / 3);
      set(a, b, bit); set(b, a, bit);
    }
  }

  // data, zig-zag from the bottom-right
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!fn[y][x] && i < codewords.length * 8) {
          m[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
          i++;
        }
      }
    }
  }
  // mask
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    if (fn[y][x]) continue;
    let inv;
    switch (mask) {
      case 0: inv = (x + y) % 2 === 0; break;
      case 1: inv = y % 2 === 0; break;
      case 2: inv = x % 3 === 0; break;
      case 3: inv = (x + y) % 3 === 0; break;
      case 4: inv = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
      case 5: inv = ((x * y) % 2) + ((x * y) % 3) === 0; break;
      case 6: inv = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
      default: inv = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0; break;
    }
    if (inv) m[y][x] = !m[y][x];
  }
  return m;
}

function drawFormat(m, fn, size, e, mask, set) {
  const data = (ECC[e].bits << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const bit = (i) => ((bits >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) set(8, i, bit(i));
  set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
  set(8, size - 8, true); // dark module
}

function penalty(m) {
  const size = m.length;
  let p = 0;
  const runs = (get) => {
    for (let a = 0; a < size; a++) {
      let run = 1;
      for (let b = 1; b <= size; b++) {
        if (b < size && get(a, b) === get(a, b - 1)) run++;
        else { if (run >= 5) p += run - 2; run = 1; }
      }
      // finder-like 1:1:3:1:1 with 4 light modules on a side
      for (let b = 0; b + 10 < size; b++) {
        const s = [];
        for (let k = 0; k < 11; k++) s.push(get(a, b + k) ? 1 : 0);
        const t = s.join('');
        if (t === '10111010000' || t === '00001011101') p += 40;
      }
    }
  };
  runs((a, b) => m[a][b]);
  runs((a, b) => m[b][a]);
  for (let y = 0; y + 1 < size; y++) for (let x = 0; x + 1 < size; x++) {
    const c = m[y][x];
    if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) p += 3;
  }
  let dark = 0;
  for (const row of m) for (const v of row) if (v) dark++;
  const total = size * size;
  p += Math.floor(Math.abs(dark * 20 - total * 10) / total) * 10;
  return p;
}

/** Encode text → square boolean matrix (true = dark). Throws if it cannot fit. */
export function qrMatrix(text) {
  const bytes = [...new TextEncoder().encode(String(text))];
  for (const e of ['M', 'L']) {
    for (let ver = 1; ver <= MAX_VERSION; ver++) {
      const header = 4 + (ver <= 9 ? 8 : 16);
      if (header + bytes.length * 8 > dataCodewords(ver, e) * 8) continue;
      const cw = interleave(encodeData(bytes, ver, e), ver, e);
      let best = null, bestP = Infinity;
      for (let mask = 0; mask < 8; mask++) {
        const m = build(cw, ver, e, mask);
        const p = penalty(m);
        if (p < bestP) { best = m; bestP = p; }
      }
      return best;
    }
  }
  throw new Error('Link too long for a QR code');
}

/** Paint a QR code onto a canvas (with the required 4-module quiet zone). */
export function drawQR(canvas, text, { px = 6, dark = '#000', light = '#fff' } = {}) {
  const m = qrMatrix(text);
  const n = m.length + 8;
  canvas.width = canvas.height = n * px;
  const g = canvas.getContext('2d');
  g.fillStyle = light; g.fillRect(0, 0, n * px, n * px);
  g.fillStyle = dark;
  m.forEach((row, y) => row.forEach((v, x) => { if (v) g.fillRect((x + 4) * px, (y + 4) * px, px, px); }));
  return canvas;
}
