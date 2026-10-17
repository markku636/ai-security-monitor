// 產生 1024×1024 的盾牌圖示（無外部依賴）；再用 `tauri icon` 轉出各尺寸。
// 用法：node scripts/make-icon.mjs src-tauri/icons/source.png
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const N = 1024;
const out = process.argv[2] ?? 'icon-source.png';
const px = Buffer.alloc(N * N * 4);

const TEAL = [13, 148, 136];
const DARK = [15, 23, 42];
const WHITE = [240, 253, 250];

/** 盾牌：上緣圓角矩形，下半收成尖底。回傳 0..1 覆蓋率（簡單超取樣）。 */
function inShield(x, y, inset) {
  const l = 160 + inset, r = N - 160 - inset, t = 120 + inset, mid = 560, b = 930 - inset * 1.4;
  if (y < t || y > b || x < l || x > r) return false;
  if (y <= mid) {
    const rad = 90 - inset * 0.5;
    if (y < t + rad && (x < l + rad || x > r - rad)) {
      const cx = x < l + rad ? l + rad : r - rad;
      return (x - cx) ** 2 + (y - (t + rad)) ** 2 <= rad * rad;
    }
    return true;
  }
  // 下半：左右往中心收，曲線底
  const k = (y - mid) / (b - mid);
  const half = ((r - l) / 2) * Math.cos((k * Math.PI) / 2) ** 0.8;
  return Math.abs(x - N / 2) <= half;
}

/** 勾勾（筆畫寬 70）。 */
function inCheck(x, y) {
  const seg = (ax, ay, bx, by, w) => {
    const dx = bx - ax, dy = by - ay;
    const t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)));
    return (x - ax - t * dx) ** 2 + (y - ay - t * dy) ** 2 <= w * w;
  };
  return seg(350, 520, 470, 650, 38) || seg(470, 650, 690, 400, 38);
}

const SS = 2;
for (let y = 0; y < N; y++) {
  for (let x = 0; x < N; x++) {
    let a = 0, cr = 0, cg = 0, cb = 0;
    for (let sy = 0; sy < SS; sy++) {
      for (let sx = 0; sx < SS; sx++) {
        const fx = x + (sx + 0.5) / SS, fy = y + (sy + 0.5) / SS;
        let c = null;
        if (inShield(fx, fy, 0)) c = inShield(fx, fy, 36) ? (inCheck(fx, fy) ? WHITE : TEAL) : DARK;
        if (c) {
          a += 1; cr += c[0]; cg += c[1]; cb += c[2];
        }
      }
    }
    const i = (y * N + x) * 4;
    if (a) {
      px[i] = cr / a; px[i + 1] = cg / a; px[i + 2] = cb / a;
    }
    px[i + 3] = Math.round((a / (SS * SS)) * 255);
  }
}

function crc32(buf) {
  let c, crc = 0xffffffff;
  for (let n = 0; n < buf.length; n++) {
    c = (crc ^ buf[n]) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
const raw = Buffer.alloc((N * 4 + 1) * N);
for (let y = 0; y < N; y++) {
  raw[y * (N * 4 + 1)] = 0;
  px.copy(raw, y * (N * 4 + 1) + 1, y * N * 4, (y + 1) * N * 4);
}
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(N, 0);
ihdr.writeUInt32BE(N, 4);
ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
const png = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  chunk('IHDR', ihdr),
  chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);
fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
fs.writeFileSync(out, png);
console.log('wrote', out, png.length, 'bytes');
