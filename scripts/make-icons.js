/**
 * Draws the icons the page needs and writes them into public/.
 *
 * They are committed, so this only runs when the mark changes — but it lives
 * here so the binaries are reproducible instead of arriving from nowhere:
 *
 *   node scripts/make-icons.js
 *
 * PNGs are assembled by hand (zlib is the only thing needed for that), which is
 * cheaper than dragging in an image library for four files.
 */

import { deflateSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

/* ------------------------------------------------------------------ *
 * PNG
 * ------------------------------------------------------------------ */

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = -1;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

/** @param {Uint8Array} rgba  width × height × 4 bytes */
function encodePng(width, height, rgba) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;    // bit depth
  header[9] = 6;    // colour type: RGBA
  // compression, filter and interlace stay at 0

  // Each scanline is prefixed with its filter type; 0 (none) keeps this simple.
  const raw = Buffer.alloc(height * (width * 4 + 1));
  for (let y = 0; y < height; y++) {
    const from = y * width * 4;
    raw[y * (width * 4 + 1)] = 0;
    Buffer.from(rgba.buffer, rgba.byteOffset + from, width * 4)
      .copy(raw, y * (width * 4 + 1) + 1);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** An ICO carrying a single PNG — every browser since Vista reads this. */
function encodeIco(png, size) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);        // type: icon
  header.writeUInt16LE(1, 4);        // one image

  const entry = Buffer.alloc(16);
  entry[0] = size >= 256 ? 0 : size; // width, 0 meaning 256
  entry[1] = size >= 256 ? 0 : size;
  entry.writeUInt16LE(1, 4);         // colour planes
  entry.writeUInt16LE(32, 6);        // bits per pixel
  entry.writeUInt32LE(png.length, 8);
  entry.writeUInt32LE(22, 12);       // offset of the image data

  return Buffer.concat([header, entry, png]);
}

/* ------------------------------------------------------------------ *
 * Drawing
 * ------------------------------------------------------------------ */

const ACCENT = [0x38, 0xbd, 0xf8];
const ACCENT2 = [0x81, 0x8c, 0xf8];
const BACKDROP = [0x0a, 0x0e, 0x16];

/** Supersampling: every pixel is averaged over SS × SS sub-samples. */
const SS = 4;

const mix = (a, b, t) => a.map((value, i) => value + (b[i] - value) * t);

/** Distance to a rounded rectangle: negative inside, positive outside. */
function roundedRect(x, y, cx, cy, halfWidth, halfHeight, radius) {
  const dx = Math.abs(x - cx) - (halfWidth - radius);
  const dy = Math.abs(y - cy) - (halfHeight - radius);
  const outside = Math.hypot(Math.max(dx, 0), Math.max(dy, 0));
  return outside + Math.min(Math.max(dx, dy), 0) - radius;
}

/**
 * The mark: a rounded square in the brand gradient with a padlock cut into it.
 * `size` is the canvas edge; `pad` leaves room around the badge.
 *
 * @returns {(x:number, y:number) => [number,number,number,number]|null}
 *   colour at a point, or null where the badge is not drawn
 */
function padlockBadge(size, { pad = 0 } = {}) {
  const badge = size - pad * 2;
  const cx = size / 2;
  const cy = size / 2;
  const radius = badge * 0.235;

  const bodyHalfW = badge * 0.225;
  const bodyHalfH = badge * 0.165;
  const bodyCy = cy + badge * 0.115;
  const bodyRadius = badge * 0.055;

  const shackleCy = cy - badge * 0.085;
  const shackleOuter = badge * 0.175;
  const shackleInner = badge * 0.105;

  const keyholeCy = bodyCy - badge * 0.02;
  const keyholeR = badge * 0.038;

  return (x, y) => {
    if (roundedRect(x, y, cx, cy, badge / 2, badge / 2, radius) > 0) return null;

    // Diagonal gradient across the badge.
    const t = Math.min(1, Math.max(0, ((x - pad) / badge + (y - pad) / badge) / 2));
    const base = mix(ACCENT, ACCENT2, t);

    const inBody = roundedRect(x, y, cx, bodyCy, bodyHalfW, bodyHalfH, bodyRadius) <= 0;
    const ringDistance = Math.hypot(x - cx, y - shackleCy);
    const inShackle = y <= shackleCy &&
      ringDistance <= shackleOuter && ringDistance >= shackleInner;

    if (inBody || inShackle) {
      const keyhole = Math.hypot(x - cx, y - keyholeCy) <= keyholeR ||
        (Math.abs(x - cx) <= keyholeR * 0.42 &&
         y >= keyholeCy && y <= keyholeCy + badge * 0.075);
      return keyhole ? [...base, 255] : [255, 255, 255, 255];
    }
    return [...base, 255];
  };
}

/**
 * Renders a canvas.
 * @param {number} width
 * @param {number} height
 * @param {(x:number, y:number) => [number,number,number,number]|null} paint
 * @param {[number,number,number,number]} background
 */
function render(width, height, paint, background = [0, 0, 0, 0]) {
  const rgba = new Uint8Array(width * height * 4);
  for (let py = 0; py < height; py++) {
    for (let px = 0; px < width; px++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const sample = paint(px + (sx + 0.5) / SS, py + (sy + 0.5) / SS) || background;
          r += sample[0] * sample[3];
          g += sample[1] * sample[3];
          b += sample[2] * sample[3];
          a += sample[3];
        }
      }
      const i = (py * width + px) * 4;
      // Weighted by alpha, so edges do not darken towards black.
      rgba[i] = a ? Math.round(r / a) : 0;
      rgba[i + 1] = a ? Math.round(g / a) : 0;
      rgba[i + 2] = a ? Math.round(b / a) : 0;
      rgba[i + 3] = Math.round(a / (SS * SS));
    }
  }
  return rgba;
}

/* ------------------------------------------------------------------ *
 * The files
 * ------------------------------------------------------------------ */

/** The scalable version, which is what browsers actually use these days. */
const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="myssl">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#38bdf8"/>
      <stop offset="1" stop-color="#818cf8"/>
    </linearGradient>
  </defs>
  <rect width="64" height="64" rx="15" fill="url(#g)"/>
  <path d="M32 13c-6.1 0-11 4.9-11 11v5h6v-5c0-2.8 2.2-5 5-5s5 2.2 5 5v5h6v-5c0-6.1-4.9-11-11-11z" fill="#fff"/>
  <rect x="17.5" y="28.5" width="29" height="22" rx="4" fill="#fff"/>
  <path d="M32 34.5a2.9 2.9 0 0 0-1.5 5.4V44a1.5 1.5 0 0 0 3 0v-4.1a2.9 2.9 0 0 0-1.5-5.4z" fill="url(#g)"/>
</svg>
`;

function write(name, data) {
  writeFileSync(path.join(PUBLIC_DIR, name), data);
  console.log(`  ${name.padEnd(22)} ${String(data.length).padStart(7)} bytes`);
}

console.log('writing icons into public/');
write('icon.svg', ICON_SVG);

for (const [name, size] of [['apple-touch-icon.png', 180], ['icon-512.png', 512], ['icon-192.png', 192]]) {
  write(name, encodePng(size, size, render(size, size, padlockBadge(size))));
}

const faviconPng = encodePng(32, 32, render(32, 32, padlockBadge(32)));
write('favicon.ico', encodeIco(faviconPng, 32));

/* The social preview: the mark on the page's own background. */
const OG_WIDTH = 1200;
const OG_HEIGHT = 630;
const badgeSize = 320;
const badgeX = (OG_WIDTH - badgeSize) / 2;
const badgeY = (OG_HEIGHT - badgeSize) / 2;
const badge = padlockBadge(badgeSize);

write('og-image.png', encodePng(OG_WIDTH, OG_HEIGHT, render(OG_WIDTH, OG_HEIGHT, (x, y) => {
  const inside = badge(x - badgeX, y - badgeY);
  if (inside) return inside;

  // The same two glows the page draws behind its content.
  const glow = (gx, gy, radius, strength) =>
    Math.max(0, 1 - Math.hypot((x - gx) / radius, (y - gy) / (radius * 0.55))) * strength;
  const light = glow(OG_WIDTH * 0.18, -60, 620, 0.30) + glow(OG_WIDTH * 0.86, -30, 520, 0.26);
  return [...mix(BACKDROP, mix(ACCENT, ACCENT2, 0.5), Math.min(0.5, light)), 255];
})));

console.log('done');
