// Switch asset-format helpers: decompression (zstd/gzip/zlib/Yaz0) and parsers
// for BYML (-> JSON), BNTX and BFRES (structure/contents). Zero npm deps.
import zlib from "node:zlib";
import { hex } from "./core.mjs";

// ---------- decompression ----------

// Yaz0: Nintendo RLE used across GC/Wii/Switch. Header: "Yaz0", u32 BE outSize.
export function yaz0Decompress(buf) {
  if (buf.toString("latin1", 0, 4) !== "Yaz0") throw new Error("not Yaz0");
  const outLen = buf.readUInt32BE(4);
  const out = Buffer.alloc(outLen);
  let src = 16, dst = 0, group = 0, bits = 0;
  while (dst < outLen) {
    if (bits === 0) { group = buf[src++]; bits = 8; }
    if (group & 0x80) { out[dst++] = buf[src++]; }
    else {
      const b1 = buf[src++], b2 = buf[src++];
      let dist = ((b1 & 0x0f) << 8) | b2, count = b1 >> 4;
      if (count === 0) count = buf[src++] + 0x12; else count += 2;
      let copy = dst - dist - 1;
      for (let i = 0; i < count && dst < outLen; i++) out[dst++] = out[copy++];
    }
    group <<= 1; bits--;
  }
  return out;
}

export function decompress(buf) {
  const m4 = buf.subarray(0, 4);
  if (m4.toString("latin1") === "Yaz0") return { data: yaz0Decompress(buf), format: "Yaz0" };
  if (buf[0] === 0x28 && buf[1] === 0xb5 && buf[2] === 0x2f && buf[3] === 0xfd) {
    if (typeof zlib.zstdDecompressSync !== "function") throw new Error("Zstandard needs Node 22.15+/23.8+ (no zstdDecompressSync here)");
    return { data: zlib.zstdDecompressSync(buf), format: "Zstandard" };
  }
  if (buf[0] === 0x1f && buf[1] === 0x8b) return { data: zlib.gunzipSync(buf), format: "gzip" };
  if (buf[0] === 0x78 && (buf[1] === 0x01 || buf[1] === 0x9c || buf[1] === 0xda)) return { data: zlib.inflateSync(buf), format: "zlib" };
  throw new Error("unrecognized compression (supported: Zstandard, Yaz0, gzip, zlib)");
}

// ---------- BYML (binary YAML) -> JS ----------

const BYML = { STRING: 0xa0, BINARY: 0xa1, ARRAY: 0xc0, DICT: 0xc1, STRTAB: 0xc2, BOOL: 0xd0, S32: 0xd1, F32: 0xd2, U32: 0xd3, S64: 0xd4, U64: 0xd5, F64: 0xd6, NULL: 0xff };

export function parseByml(buf) {
  const magic = buf.toString("latin1", 0, 2);
  const le = magic === "YB";
  if (!le && magic !== "BY") throw new Error("not BYML (magic must be BY/YB)");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u16 = (o) => dv.getUint16(o, le), u32 = (o) => dv.getUint32(o, le), s32 = (o) => dv.getInt32(o, le);
  const f32 = (o) => dv.getFloat32(o, le), f64 = (o) => dv.getFloat64(o, le);
  const u64 = (o) => dv.getBigUint64(o, le), s64 = (o) => dv.getBigInt64(o, le);
  const version = u16(2), keyTabOff = u32(4), strTabOff = u32(8), rootOff = u32(12);

  const readStrTable = (off) => {
    if (!off) return [];
    if (buf[off] !== BYML.STRTAB) throw new Error(`bad string table @${hex(off)}`);
    const count = le ? (u32(off) >>> 8) : (u32(off) & 0xffffff);
    const offs = [];
    for (let i = 0; i <= count; i++) offs.push(u32(off + 4 + i * 4));
    const out = [];
    for (let i = 0; i < count; i++) out.push(buf.toString("utf8", off + offs[i], off + offs[i + 1]).replace(/\0.*$/, ""));
    return out;
  };
  const keys = readStrTable(keyTabOff), strs = readStrTable(strTabOff);

  const count24 = (off) => le ? (u32(off) >>> 8) : (u32(off) & 0xffffff);
  const readValue = (type, vOff) => {
    switch (type) {
      case BYML.STRING: return strs[u32(vOff)];
      case BYML.BOOL: return u32(vOff) !== 0;
      case BYML.S32: return s32(vOff);
      case BYML.U32: return u32(vOff);
      case BYML.F32: return f32(vOff);
      case BYML.S64: return Number(s64(u32(vOff)));
      case BYML.U64: return Number(u64(u32(vOff)));
      case BYML.F64: return f64(u32(vOff));
      case BYML.NULL: return null;
      case BYML.ARRAY: case BYML.DICT: return readNode(type, u32(vOff));
      default: return `<type 0x${type.toString(16)}>`;
    }
  };
  const readNode = (type, off) => {
    if (type === BYML.ARRAY) {
      const n = count24(off), out = [];
      const typesOff = off + 4, valsOff = off + 4 + ((n + 3) & ~3);
      for (let i = 0; i < n; i++) out.push(readValue(buf[typesOff + i], valsOff + i * 4));
      return out;
    }
    if (type === BYML.DICT) {
      const n = count24(off), out = {};
      for (let i = 0; i < n; i++) {
        const e = off + 4 + i * 8;
        const keyIdx = le ? (u32(e) & 0xffffff) : (u32(e) >>> 8);
        const childType = le ? (buf[e + 3]) : (buf[e]);
        out[keys[keyIdx]] = readValue(childType, e + 4);
      }
      return out;
    }
    return readValue(type, off);
  };

  if (!rootOff) return { version, root: null };
  return { version, le, root: readNode(buf[rootOff], rootOff) };
}

// ---------- BNTX (texture container) ----------

export function parseBntx(buf) {
  if (buf.toString("latin1", 0, 4) !== "BNTX") throw new Error("not BNTX");
  const le = buf.readUInt16LE(0x0c) === 0xfeff;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u16 = (o) => dv.getUint16(o, le), u32 = (o) => dv.getUint32(o, le), u64 = (o) => Number(dv.getBigUint64(o, le));
  const cstr = (o) => { let e = o; while (e < buf.length && buf[e]) e++; return buf.toString("utf8", o, e); };
  const out = { version: u32(0x08), fileName: cstr(u32(0x10) + 2), textures: [] };
  // 'NX  ' block at 0x20: texture count + pointer array
  if (buf.toString("latin1", 0x20, 0x24) !== "NX  ") return out;
  const count = u32(0x24), ptrArr = u64(0x28);
  for (let i = 0; i < count && i < 4096; i++) {
    const brti = u64(ptrArr + i * 8);
    if (buf.toString("latin1", brti, brti + 4) !== "BRTI") continue;
    // BRTI fixed fields (stable layout): format @0x20, width @0x28, height @0x2c,
    // depth @0x30, arrayCount @0x34, mipCount @0x18, name via ptr @0x60.
    const t = {
      name: (() => { const p = u64(brti + 0x60); return p ? cstr(p + 2) : `tex${i}`; })(),
      format: "0x" + u32(brti + 0x20).toString(16),
      width: u32(brti + 0x28), height: u32(brti + 0x2c), depth: u32(brti + 0x30),
      mipCount: u16(brti + 0x18), arrayCount: u32(brti + 0x34),
    };
    out.textures.push(t);
  }
  return out;
}

// ---------- BFRES (model/resource container, Switch 'FRES') ----------

export function parseBfres(buf) {
  if (buf.toString("latin1", 0, 4) !== "FRES") throw new Error("not BFRES (FRES)");
  const le = buf.readUInt16LE(0x0c) === 0xfeff;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u16 = (o) => dv.getUint16(o, le), u64 = (o) => Number(dv.getBigUint64(o, le));
  const cstr = (o) => { let e = o; while (e < buf.length && buf[e]) e++; return buf.toString("utf8", o, e); };
  const verMajor = buf[0x0b], verMinor = buf[0x0a];
  const out = { version: `${verMajor}.${verMinor}`, name: "", models: [], embeddedFiles: [], textureContainer: null };
  try { out.name = cstr(u64(0x20) + 2); } catch { /* name ptr layout varies by version */ }
  // Scan for recognizable sub-block magics so output is robust across versions.
  for (const magic of ["FMDL", "FSKL", "FSHP", "FMAT", "BNTX"]) {
    const idx = buf.indexOf(Buffer.from(magic), 0x30);
    if (idx > 0) { if (magic === "BNTX") out.textureContainer = { offset: hex(idx) }; else out.models.push({ block: magic, offset: hex(idx) }); }
  }
  return out;
}
