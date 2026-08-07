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

/* Palette from the sharapov.biz design system. */
const INK = [0x14, 0x11, 0x0c];
const PAPER = [0xf5, 0xef, 0xe2];
const BRAND = [0x3a, 0x3a, 0xa6];
const BG = [0xf9, 0xf4, 0xea];
const WASH_INDIGO = [0xd8, 0xd8, 0xf2];

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
 * The mark, in the same proportions as public/icon.svg: an ink tile carrying a
 * paper-coloured padlock with the one indigo accent in its keyhole.
 *
 * @param {number} size canvas edge
 * @returns {(x:number, y:number) => [number,number,number,number]|null}
 */
function padlockBadge(size) {
  const u = size / 1024;                       // the SVG is drawn at 1024
  const at = value => value * u;

  return (x, y) => {
    if (roundedRect(x, y, size / 2, size / 2, size / 2, size / 2, at(336)) > 0) return null;

    // Shackle: a stroked arc, so the test is distance to its centre line.
    const ring = Math.hypot(x - at(512), y - at(456));
    const inShackle = y <= at(456) && Math.abs(ring - at(176)) <= at(44);
    // Its legs run straight down to where the body swallows them.
    const inLegs = y > at(456) && y <= at(552) &&
      (Math.abs(x - at(336)) <= at(44) || Math.abs(x - at(688)) <= at(44));
    const inBody = roundedRect(x, y, at(512), at(708), at(264), at(188), at(104)) <= 0;

    if (inBody) {
      const keyholeRound = Math.hypot(x - at(512), y - at(692)) <= at(56);
      const keyholeStem = Math.abs(x - at(512)) <= at(28) && y >= at(692) && y <= at(812);
      return keyholeRound || keyholeStem ? [...BRAND, 255] : [...PAPER, 255];
    }
    if (inShackle || inLegs) return [...PAPER, 255];
    return [...INK, 255];
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

function write(name, data) {
  writeFileSync(path.join(PUBLIC_DIR, name), data);
  console.log(`  ${name.padEnd(22)} ${String(data.length).padStart(7)} bytes`);
}

console.log('writing icons into public/');
console.log('  icon.svg is hand-written and left alone');

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

  // The page wash: an indigo glow top-right over warm paper.
  const glow = Math.max(0, 1 - Math.hypot((x - OG_WIDTH) / 760, y / 420));
  return [...mix(BG, WASH_INDIGO, Math.min(1, glow * 1.1)), 255];
})));

console.log('done');
