// Builds tests/fixture.nso: a tiny synthetic Switch NSO (LZ4-compressed segments,
// hand-encoded AArch64, a string xref, dynsym symbols). No real game data.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function lz4Compress(src) {
  const out = [], table = new Map();
  let anchor = 0, i = 0;
  const emit = (litEnd, matchLen, off) => {
    const lit = litEnd - anchor, ml = matchLen ? matchLen - 4 : 0;
    out.push((Math.min(lit, 15) << 4) | (matchLen ? Math.min(ml, 15) : 0));
    if (lit >= 15) { let r = lit - 15; while (r >= 255) { out.push(255); r -= 255; } out.push(r); }
    for (let k = anchor; k < litEnd; k++) out.push(src[k]);
    if (!matchLen) return;
    out.push(off & 255, off >> 8);
    if (ml >= 15) { let r = ml - 15; while (r >= 255) { out.push(255); r -= 255; } out.push(r); }
  };
  while (i + 12 < src.length) {
    const key = src[i] | (src[i + 1] << 8) | (src[i + 2] << 16) | (src[i + 3] << 24);
    const cand = table.get(key); table.set(key, i);
    if (cand !== undefined && i - cand < 65536) {
      let len = 4; while (i + len + 5 < src.length && src[cand + len] === src[i + len]) len++;
      emit(i, len, i - cand); i += len; anchor = i; continue;
    }
    i++;
  }
  emit(src.length, 0, 0);
  return Buffer.from(out);
}

const TEXT = 0x1000, RO = 0x1000, DATA = 0x100, BSS = 0x100;
const text = Buffer.alloc(TEXT);
for (let o = 0; o < TEXT; o += 4) text.writeUInt32LE(0xd503201f, o); // nop sled -> exercises LZ4 matches
const put = (o, w) => text.writeUInt32LE(w >>> 0, o);
put(0x00, 0xd503201f);                                        // nnMain: nop
put(0x04, 0x90000000 | (1 << 29) | 0);                        // adrp x0, 0x1000
put(0x08, 0x91000000 | (0x100 << 10) | (0 << 5) | 0);         // add  x0, x0, #0x100  -> "Hello..."
put(0x0c, 0x94000000 | (0x14 / 4));                           // bl   0x20
put(0x10, 0xd65f03c0);                                        // ret
put(0x20, 0xd65f03c0);                                        // SleepThread: ret

const ro = Buffer.alloc(RO);
const modPath = "D:\\home\\fixture\\main.nss";
ro.writeUInt32LE(0, 0); ro.writeUInt32LE(modPath.length, 4); ro.write(modPath, 8, "latin1");
ro.write("Hello Switch error %d\0", 0x100, "latin1");
const names = ["", "nnMain", "_ZN2nn2os11SleepThreadENS_8TimeSpanE", "_ZN2nn2fs8MountRomEPKcPvm"];
let strOff = 0x200, dynstr = Buffer.alloc(0x100), nameOffs = [];
let p = 1; for (const n of names.slice(1)) { nameOffs.push(p); dynstr.write(n + "\0", p, "latin1"); p += n.length + 1; }
dynstr.copy(ro, strOff);
const symOff = 0x300, sym = (i, nameOff, info, shndx, value) => {
  const o = symOff + i * 24; ro.writeUInt32LE(nameOff, o); ro[o + 4] = info; ro.writeUInt16LE(shndx, o + 6); ro.writeBigUInt64LE(BigInt(value), o + 8); ro.writeBigUInt64LE(4n, o + 16);
};
sym(1, nameOffs[0], 0x12, 1, 0x00); sym(2, nameOffs[1], 0x12, 1, 0x20); sym(3, nameOffs[2], 0x12, 0, 0);
const data = Buffer.alloc(DATA, 0xab);

const segs = [text, ro, data].map((s) => lz4Compress(s));
const hdr = Buffer.alloc(0x100);
hdr.write("NSO0", 0, "latin1"); hdr.writeUInt32LE(7, 0x0c);
let fo = 0x100; const mem = [0, TEXT, TEXT + RO], sizes = [TEXT, RO, DATA];
[0x10, 0x20, 0x30].forEach((h, i) => { hdr.writeUInt32LE(fo, h); hdr.writeUInt32LE(mem[i], h + 4); hdr.writeUInt32LE(sizes[i], h + 8); hdr.writeUInt32LE(segs[i].length, 0x60 + i * 4); fo += segs[i].length; });
hdr.writeUInt32LE(BSS, 0x3c);
Buffer.from("0123456789abcdef0123456789abcdef", "hex").copy(hdr, 0x40);
hdr.writeUInt32LE(strOff, 0x90); hdr.writeUInt32LE(p, 0x94); hdr.writeUInt32LE(symOff, 0x98); hdr.writeUInt32LE(4 * 24, 0x9c);
const out = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixture.nso");
fs.writeFileSync(out, Buffer.concat([hdr, ...segs]));
console.log(`wrote ${out} (${fs.statSync(out).size} bytes; text compressed ${TEXT} -> ${segs[0].length})`);
