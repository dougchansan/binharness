// Shared binary-analysis toolkit used by the MCP server and the DeepSeek harness.
// Zero npm dependencies. Nintendo Switch focused (NSO/NRO/NSP/XCI, AArch64),
// with generic support for any file.
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { RE_TOOLS, listFunctions, callGraphTool, scanSyscallsTool, scanSyscalls, functionAt, SVC_NAMES, findServices, findServicesTool, parseNpdm, npdmTool, scanRtti, findRttiTool, getRelocations, collectSymbols, emitGhidra, emitIda, resolveThunk } from "./re.mjs";

export const MAX_CHUNK = 64 * 1024;
export const DEFAULT_SWITCH_BASE = 0x7100000000;
const STATE_DIR = path.join(os.homedir(), ".binharness");

// ---------- basic file access ----------

export function resolvePath(p) {
  if (typeof p !== "string" || !p) throw new Error("path is required");
  if (p.startsWith("~")) p = path.join(os.homedir(), p.slice(1));
  return path.resolve(p);
}

export function readRange(file, offset, length) {
  const st = fs.statSync(file);
  if (!st.isFile()) throw new Error(`${file} is not a regular file`);
  offset = Math.max(0, Math.min(Math.floor(offset || 0), st.size));
  length = Math.max(0, Math.min(Math.floor(length), st.size - offset));
  const buf = Buffer.alloc(length);
  if (length) {
    const fd = fs.openSync(file, "r");
    try { fs.readSync(fd, buf, 0, length, offset); } finally { fs.closeSync(fd); }
  }
  return { buf, offset, size: st.size, mtime: st.mtimeMs };
}

export const hex = (n, w = 0) => "0x" + n.toString(16).padStart(w, "0");
const parseNum = (v) => (typeof v === "number" ? v : typeof v === "string" && v.trim() ? Number(v.trim().replace(/_/g, "")) : undefined);

export function hexdump(buf, base, maxLines = Infinity) {
  const lines = [];
  const w = Math.max(8, (base + buf.length).toString(16).length);
  for (let i = 0; i < buf.length && lines.length < maxLines; i += 16) {
    const row = buf.subarray(i, i + 16);
    const h = [...row].map((b) => b.toString(16).padStart(2, "0"));
    const ascii = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${(base + i).toString(16).padStart(w, "0")}  ${h.slice(0, 8).join(" ").padEnd(23)}  ${h.slice(8).join(" ").padEnd(23)}  |${ascii}|`);
  }
  return lines.join("\n");
}

// ---------- format detection ----------

export function detectFormat(b, size, name = "") {
  const s = (o, n) => b.subarray(o, o + n).toString("latin1");
  const u32be = (o) => (b.length >= o + 4 ? b.readUInt32BE(o) : -1);
  const ext = path.extname(name).toLowerCase();
  // Nintendo Switch
  if (s(0, 4) === "NSO0") return "Switch NSO executable";
  if (s(0x10, 4) === "NRO0") return "Switch NRO executable";
  if (s(0, 4) === "PFS0") return "Switch PFS0 container (NSP / ExeFS)";
  if (s(0, 4) === "HFS0") return "Switch HFS0 partition";
  if (s(0x100, 4) === "HEAD") return "Switch XCI cartridge image";
  if (s(0, 4) === "META") return "Switch NPDM (program metadata)";
  if (s(0, 4) === "SARC") return "SARC archive";
  if (s(0, 4) === "BNTX") return "BNTX texture container";
  if (s(0, 4) === "BNSH") return "BNSH shader container";
  if (s(0, 4) === "FRES") return "BFRES model";
  if (s(0, 4) === "FSTM") return "BFSTM audio stream";
  if (s(0, 4) === "FWAV") return "BFWAV audio";
  if (s(0, 4) === "FWSD") return "BFWSD";
  if (s(0, 8) === "MsgStdBn") return "MSBT message table";
  if (s(0, 8) === "MsgPrjBn") return "MSBP message project";
  if (s(0, 2) === "BY" || s(0, 2) === "YB") return "BYML";
  if (s(0, 4) === "AAMP") return "AAMP parameter archive";
  if (s(0, 4) === "\x28\xb5\x2f\xfd") return "Zstandard (often .zs-compressed Switch asset)";
  if (ext === ".nca") return "Switch NCA (encrypted; decryption not supported)";
  if (ext === ".nacp" && size === 0x4000) return "Switch NACP (title control data)";
  // Generic
  if (s(0, 4) === "\x7fELF") return `ELF ${b[4] === 2 ? "64" : "32"}-bit ${b[5] === 2 ? "big" : "little"}-endian`;
  const m = u32be(0);
  if (m === 0xfeedface || m === 0xcefaedfe) return "Mach-O 32-bit";
  if (m === 0xfeedfacf || m === 0xcffaedfe) return "Mach-O 64-bit";
  if (m === 0xcafebabe) return b.length >= 8 && b.readUInt32BE(4) < 40 ? "Mach-O universal binary" : "Java class";
  if (s(0, 2) === "MZ") return "PE/DOS executable";
  if (s(0, 8) === "\x89PNG\r\n\x1a\n") return "PNG image";
  if (s(0, 3) === "\xff\xd8\xff") return "JPEG image";
  if (s(0, 4) === "GIF8") return "GIF image";
  if (s(0, 4) === "RIFF") return `RIFF (${s(8, 4)})`;
  if (s(0, 4) === "PK\x03\x04") return "ZIP archive";
  if (s(0, 2) === "\x1f\x8b") return "gzip";
  if (s(0, 6) === "7z\xbc\xaf\x27\x1c") return "7-Zip archive";
  if (s(0, 4) === "%PDF") return "PDF";
  if (s(0, 16) === "SQLite format 3\0") return "SQLite database";
  if (s(0, 4) === "\0asm") return "WebAssembly";
  if (s(0, 8) === "!<arch>\n") return "ar archive / static library";
  // GameCube / Wii
  if (s(0, 4) === "Yaz0") return `Yaz0 compressed (decompressed size 0x${u32be(4).toString(16)})`;
  if (s(0, 4) === "Yay0") return "Yay0 compressed";
  if (s(0, 4) === "RARC") return "RARC archive";
  if (s(0, 4) === "U\xaa8-") return "U8 archive";
  if (u32be(0x1c) === 0xc2339f3d) return `GameCube disc image (${s(0, 6)})`;
  if (u32be(0x18) === 0x5d1c9ea3) return `Wii disc image (${s(0, 6)})`;
  if (ext === ".dol" && b.length >= 0x100) return `GameCube DOL (entry 0x${u32be(0xe0).toString(16)})`;
  if (ext === ".rel" && b.length >= 0x40) return `GameCube REL (module ${u32be(0)})`;
  if (s(0, 4) === "bres") return "BRRES";
  if (s(0, 4) === "J3D2") return `J3D model (${s(4, 4)})`;
  return null;
}

// ---------- LZ4 (block format, as used by NSO segments) ----------

export function lz4Decompress(src, outLen) {
  const dst = new Uint8Array(outLen);
  let s = 0, d = 0;
  while (s < src.length) {
    const tok = src[s++];
    let lit = tok >> 4;
    if (lit === 15) { let b; do { b = src[s++]; lit += b; } while (b === 255); }
    if (d + lit > outLen) throw new Error("LZ4: output overrun");
    dst.set(src.subarray(s, s + lit), d); s += lit; d += lit;
    if (s >= src.length) break;
    const off = src[s] | (src[s + 1] << 8); s += 2;
    if (!off || off > d) throw new Error("LZ4: bad match offset");
    let ml = tok & 15;
    if (ml === 15) { let b; do { b = src[s++]; ml += b; } while (b === 255); }
    ml += 4;
    if (d + ml > outLen) throw new Error("LZ4: output overrun");
    for (let m = d - off, e = d + ml; d < e;) dst[d++] = dst[m++];
  }
  if (d !== outLen) throw new Error(`LZ4: decompressed ${d} bytes, expected ${outLen}`);
  return dst;
}

// ---------- Switch containers ----------

function readCStr(b, off, max = 512) {
  let e = off;
  while (e < b.length && e - off < max && b[e]) e++;
  return Buffer.from(b.subarray(off, e)).toString("utf8");
}

export function parsePfs0(file, base = 0) {
  const h = readRange(file, base, 16).buf;
  if (h.toString("latin1", 0, 4) !== "PFS0" && h.toString("latin1", 0, 4) !== "HFS0") throw new Error("not a PFS0/HFS0");
  const hfs = h.toString("latin1", 0, 4) === "HFS0";
  const n = h.readUInt32LE(4), strSize = h.readUInt32LE(8), esz = hfs ? 0x40 : 0x18;
  const t = readRange(file, base + 16, n * esz + strSize).buf;
  const dataStart = base + 16 + n * esz + strSize;
  const files = [];
  for (let i = 0; i < n; i++) {
    const e = i * esz;
    files.push({
      name: readCStr(t, n * esz + t.readUInt32LE(e + 16)),
      offset: dataStart + Number(t.readBigUInt64LE(e)),
      size: Number(t.readBigUInt64LE(e + 8)),
    });
  }
  return { type: hfs ? "HFS0" : "PFS0", files };
}

export function parseXci(file) {
  const h = readRange(file, 0x100, 0x100).buf;
  if (h.toString("latin1", 0, 4) !== "HEAD") throw new Error("not an XCI");
  const root = Number(h.readBigUInt64LE(0x30));
  const parts = parsePfs0(file, root);
  return { rootOffset: root, partitions: parts.files.map((p) => { try { return { ...p, files: parsePfs0(file, p.offset).files }; } catch { return p; } }) };
}

// Executable image (NSO / NRO / raw / ELF-less blob) with segments + symbols.
const imageCache = new Map();

export function openImage(file, opts = {}) {
  file = resolvePath(file);
  const st = fs.statSync(file);
  const baseOpt = parseNum(opts.base);
  const key = `${file}|${st.mtimeMs}|${baseOpt ?? ""}|${opts.arch ?? ""}`;
  if (imageCache.has(key)) return imageCache.get(key);
  const raw = fs.readFileSync(file);
  let img;
  if (raw.toString("latin1", 0, 4) === "NSO0") img = loadNso(raw, baseOpt ?? DEFAULT_SWITCH_BASE);
  else if (raw.length >= 0x80 && raw.toString("latin1", 0x10, 0x14) === "NRO0") img = loadNro(raw, baseOpt ?? DEFAULT_SWITCH_BASE);
  else {
    img = {
      kind: "raw", base: baseOpt ?? 0, data: new Uint8Array(raw.buffer, raw.byteOffset, raw.length),
      segments: [{ name: "file", start: 0, size: raw.length, perm: "r-x" }], symbols: [],
    };
  }
  img.arch = opts.arch || (img.kind === "raw" ? "aarch64" : "aarch64");
  img.file = file;
  img.key = projectKey(file, img);
  finishSymbols(img);
  if (imageCache.size > 8) imageCache.delete(imageCache.keys().next().value);
  imageCache.set(key, img);
  return img;
}

function loadNso(b, base) {
  const flags = b.readUInt32LE(0x0c);
  const seg = (h, fsz, i, name, perm) => ({
    name, perm, fileOffset: b.readUInt32LE(h), memOffset: b.readUInt32LE(h + 4), size: b.readUInt32LE(h + 8),
    fileSize: b.readUInt32LE(fsz), compressed: !!(flags & (1 << i)),
  });
  const segs = [seg(0x10, 0x60, 0, "text", "r-x"), seg(0x20, 0x64, 1, "rodata", "r--"), seg(0x30, 0x68, 2, "data", "rw-")];
  const bss = b.readUInt32LE(0x3c);
  const end = Math.max(...segs.map((s) => s.memOffset + s.size));
  const data = new Uint8Array(end + bss);
  for (const s of segs) {
    const src = b.subarray(s.fileOffset, s.fileOffset + s.fileSize);
    data.set(s.compressed ? lz4Decompress(src, s.size) : src.subarray(0, s.size), s.memOffset);
  }
  const ro = segs[1].memOffset;
  const img = {
    kind: "nso", base, data, bssSize: bss,
    buildId: Buffer.from(b.subarray(0x40, 0x60)).toString("hex").replace(/(00)+$/, ""),
    segments: [...segs.map((s) => ({ name: s.name, start: s.memOffset, size: s.size, perm: s.perm, compressed: s.compressed })),
      { name: "bss", start: end, size: bss, perm: "rw-" }],
    dynstr: { off: ro + b.readUInt32LE(0x90), size: b.readUInt32LE(0x94) },
    dynsym: { off: ro + b.readUInt32LE(0x98), size: b.readUInt32LE(0x9c) },
  };
  // Module path usually sits at the start of rodata: u32 0, u32 len, chars.
  const dv = new DataView(data.buffer);
  const plen = data.length >= ro + 8 ? dv.getUint32(ro + 4, true) : 0;
  if (plen > 0 && plen < 0x200) img.modulePath = readCStr(data, ro + 8, plen);
  return img;
}

function loadNro(b, base) {
  const segs = ["text", "rodata", "data"].map((name, i) => ({
    name, start: b.readUInt32LE(0x20 + i * 8), size: b.readUInt32LE(0x24 + i * 8), perm: ["r-x", "r--", "rw-"][i],
  }));
  const bss = b.readUInt32LE(0x38);
  const end = Math.max(...segs.map((s) => s.start + s.size));
  const data = new Uint8Array(end + bss);
  data.set(b.subarray(0, Math.min(end, b.length)));
  const ro = segs[1].start;
  return {
    kind: "nro", base, data, bssSize: bss,
    buildId: Buffer.from(b.subarray(0x40, 0x60)).toString("hex").replace(/(00)+$/, ""),
    segments: [...segs, { name: "bss", start: end, size: bss, perm: "rw-" }],
    dynstr: { off: ro + b.readUInt32LE(0x70), size: b.readUInt32LE(0x74) },
    dynsym: { off: ro + b.readUInt32LE(0x78), size: b.readUInt32LE(0x7c) },
  };
}

function finishSymbols(img) {
  const syms = [];
  if (img.dynsym && img.dynsym.size && img.dynstr.size) {
    const d = img.data, dv = new DataView(d.buffer, d.byteOffset);
    for (let o = img.dynsym.off; o + 24 <= img.dynsym.off + img.dynsym.size && o + 24 <= d.length; o += 24) {
      const nameOff = dv.getUint32(o, true), info = d[o + 4], shndx = dv.getUint16(o + 6, true);
      const value = Number(dv.getBigUint64(o + 8, true)), size = Number(dv.getBigUint64(o + 16, true));
      if (!nameOff) continue;
      const name = readCStr(d, img.dynstr.off + nameOff);
      const type = ["notype", "object", "func", "section", "file"][info & 15] || "other";
      syms.push({ name, addr: shndx ? img.base + value : 0, size, type, imported: !shndx });
    }
  }
  demangleAll(syms);
  img.symbols = syms;
  const ann = loadAnnotations(img);
  img.addrNames = new Map();
  for (const s of syms) if (s.addr && !img.addrNames.has(s.addr)) img.addrNames.set(s.addr, s.demangled || s.name);
  for (const [a, n] of Object.entries(ann.labels)) img.addrNames.set(Number(a), n);
  img.sortedNamed = [...img.addrNames.entries()].sort((a, b) => a[0] - b[0]);
}

function demangleAll(syms) {
  const mangled = syms.filter((s) => s.name.startsWith("_Z"));
  if (!mangled.length) return;
  const r = spawnSync("c++filt", ["-n"], { input: mangled.map((s) => s.name).join("\n"), encoding: "utf8", maxBuffer: 256 << 20 });
  if (r.status !== 0 || !r.stdout) return;
  const out = r.stdout.split("\n");
  mangled.forEach((s, i) => { if (out[i] && out[i] !== s.name) s.demangled = out[i]; });
}

// ---------- address helpers ----------

export function segmentAt(img, addr) {
  const off = addr - img.base;
  return img.segments.find((s) => off >= s.start && off < s.start + s.size);
}
const seg = (img, name) => img.segments.find((s) => s.name === name) || img.segments[0];

function nearestName(img, addr, maxDist = 0x100000) {
  const a = img.sortedNamed;
  let lo = 0, hi = a.length - 1, best = -1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (a[mid][0] <= addr) { best = mid; lo = mid + 1; } else hi = mid - 1; }
  if (best < 0) return null;
  const [base, name] = a[best];
  if (addr - base >= maxDist || segmentAt(img, addr) !== segmentAt(img, base)) return null;
  return addr === base ? name : `${name}+${hex(addr - base)}`;
}

function stringAt(img, addr, max = 80) {
  const off = addr - img.base;
  if (off < 0 || off >= img.data.length) return null;
  let e = off;
  while (e < img.data.length && e - off < 400) {
    const c = img.data[e];
    if (c === 0) break;
    if (c < 0x20 && c !== 9 && c !== 10 && c !== 13) return null;
    e++;
  }
  if (e - off < 3 || img.data[e] !== 0) return null;
  const sstr = Buffer.from(img.data.subarray(off, e)).toString("utf8");
  return JSON.stringify(sstr.length > max ? sstr.slice(0, max) + "…" : sstr);
}

// ---------- AArch64 decoding (just enough for xrefs + annotations) ----------

const sext = (v, bits) => (v << (32 - bits)) >> (32 - bits);
const page = (a) => a - (a % 4096);

function decodeRef(w, pc, regs) {
  // returns {kind, target} for branch/data refs; updates regs for ADRP/ADR/ADD
  if (((w & 0xfc000000) >>> 0) === 0x94000000) return { kind: "call", target: pc + sext(w & 0x3ffffff, 26) * 4 };
  if (((w & 0xfc000000) >>> 0) === 0x14000000) return { kind: "jump", target: pc + sext(w & 0x3ffffff, 26) * 4 };
  if (((w & 0xff000010) >>> 0) === 0x54000000) return { kind: "jump", target: pc + sext((w >>> 5) & 0x7ffff, 19) * 4 };
  if (((w & 0x7e000000) >>> 0) === 0x34000000) return { kind: "jump", target: pc + sext((w >>> 5) & 0x7ffff, 19) * 4 }; // CBZ/CBNZ
  if (((w & 0x1f000000) >>> 0) === 0x10000000) { // ADR / ADRP
    const imm = sext((((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3), 21);
    const isPage = (w >>> 31) & 1;
    regs[w & 31] = isPage ? page(pc) + imm * 4096 : pc + imm;
    return isPage ? null : { kind: "data", target: regs[w & 31] };
  }
  if (((w & 0xff000000) >>> 0) === 0x91000000) { // ADD Xd, Xn, #imm
    const rn = (w >>> 5) & 31, rd = w & 31;
    if (regs[rn] === undefined) { regs[rd] = undefined; return null; }
    const v = regs[rn] + (((w >>> 10) & 0xfff) << (((w >>> 22) & 1) ? 12 : 0));
    regs[rd] = v;
    return { kind: "data", target: v };
  }
  if (((w & 0x3b000000) >>> 0) === 0x39000000) { // LDR/STR (unsigned imm)
    const rn = (w >>> 5) & 31, rt = w & 31;
    const size = w >>> 30, v = (w >>> 26) & 1, opc = (w >>> 22) & 3;
    const isLoad = (opc & 1) || (!v && opc === 2) || (v && opc === 3);
    const base = regs[rn];
    if (isLoad && !v) regs[rt] = undefined;
    if (base === undefined) return null;
    const scale = v && size === 0 && (opc & 2) ? 4 : size;
    return { kind: isLoad ? "read" : "write", target: base + (((w >>> 10) & 0xfff) << scale) };
  }
  if (((w & 0x3b000000) >>> 0) === 0x18000000) { regs[w & 31] = undefined; return { kind: "read", target: pc + sext((w >>> 5) & 0x7ffff, 19) * 4 }; } // LDR literal
  regs[w & 31] = undefined; // most other instructions write Rd/Rt in bits 0-4
  return null;
}

// ---------- disassembly via objdump (Apple/LLVM) on a minimal ELF wrapper ----------

function wrapElf(code, vaddr, machine) {
  const shstr = Buffer.from("\0.text\0.shstrtab\0");
  const textOff = 0x40, strOff = textOff + code.length, shOff = (strOff + shstr.length + 7) & ~7;
  const out = Buffer.alloc(shOff + 3 * 64);
  out.write("\x7fELF", 0, "latin1"); out[4] = 2; out[5] = 1; out[6] = 1;
  out.writeUInt16LE(1, 16); out.writeUInt16LE(machine, 18); out.writeUInt32LE(1, 20);
  out.writeBigUInt64LE(BigInt(shOff), 40); out.writeUInt16LE(64, 52); out.writeUInt16LE(64, 58);
  out.writeUInt16LE(3, 60); out.writeUInt16LE(2, 62);
  Buffer.from(code).copy(out, textOff); shstr.copy(out, strOff);
  const sh = (i, name, type, flags, addr, off, size) => {
    const o = shOff + i * 64;
    out.writeUInt32LE(name, o); out.writeUInt32LE(type, o + 4); out.writeBigUInt64LE(BigInt(flags), o + 8);
    out.writeBigUInt64LE(BigInt(addr), o + 16); out.writeBigUInt64LE(BigInt(off), o + 24); out.writeBigUInt64LE(BigInt(size), o + 32);
    out.writeBigUInt64LE(4n, o + 48);
  };
  sh(1, 1, 1, 6, vaddr, textOff, code.length);
  sh(2, 7, 3, 0, 0, strOff, shstr.length);
  return out;
}

const ARCHES = { aarch64: { machine: 183, triple: "aarch64", step: 4 }, "x86-64": { machine: 62, triple: "x86_64", step: 1 } };

export function disassemble(img, addr, count = 64) {
  const a = ARCHES[img.arch] || ARCHES.aarch64;
  const off = addr - img.base;
  if (off < 0 || off >= img.data.length) throw new Error(`address ${hex(addr)} is outside the image`);
  const len = Math.min(count * (a.step === 4 ? 4 : 15), img.data.length - off);
  const code = img.data.subarray(off, off + len);
  const tmp = path.join(os.tmpdir(), `binharness-${process.pid}-${crypto.randomBytes(4).toString("hex")}.o`);
  fs.writeFileSync(tmp, wrapElf(code, addr, a.machine));
  let r;
  try { r = spawnSync("objdump", ["-d", `--triple=${a.triple}`, "--no-show-raw-insn", "--print-imm-hex", tmp], { encoding: "utf8", maxBuffer: 64 << 20 }); }
  finally { fs.rmSync(tmp, { force: true }); }
  if (r.error || r.status !== 0) throw new Error(`objdump failed: ${r.error?.message || r.stderr}`);
  const insns = [];
  for (const l of r.stdout.split("\n")) {
    const m = l.match(/^\s*([0-9a-f]+):\s+(\S.*)$/);
    if (m) insns.push([parseInt(m[1], 16), m[2].trim().replace(/\s*<\.text[^>]*>/, "").replace(/\s+/, " ")]);
  }
  insns.length = Math.min(insns.length, count);
  const lines = [], regs = [];
  const dv = new DataView(img.data.buffer, img.data.byteOffset);
  for (const [pc, insn] of insns) {
    const name = img.addrNames.get(pc);
    if (name) lines.push(`\n${name}:`);
    let note = "";
    if (img.arch === "aarch64" && pc - img.base + 4 <= img.data.length) {
      const ref = decodeRef(dv.getUint32(pc - img.base, true), pc, regs);
      if (ref && ref.target !== undefined) {
        const isCode = ref.kind === "call" || ref.kind === "jump";
        const n = nearestName(img, ref.target, isCode ? 0x100000 : 0x200), str = ref.kind !== "call" && ref.kind !== "jump" ? stringAt(img, ref.target) : null;
        if (ref.kind === "call" || ref.kind === "jump") { if (n) note = n; }
        else note = [hex(ref.target), n, str].filter(Boolean).join(" ");
      }
      if (/^(bl|blr|ret)\b/.test(insn)) regs.length = 0;
    }
    const cmt = img.comments?.[pc];
    lines.push(`  ${pc.toString(16)}:  ${insn.padEnd(36)}${note ? " ; " + note : ""}${cmt ? " // " + cmt : ""}`);
  }
  return lines.join("\n").replace(/^\n/, "");
}

// Scan executable segment for references to target (calls, branches, ADRP-based data refs).
export function findXrefs(img, targets, max = 200) {
  if (img.arch !== "aarch64") throw new Error("xrefs are only supported for aarch64");
  const set = new Set(Array.isArray(targets) ? targets : [targets]);
  const text = seg(img, "text"), dv = new DataView(img.data.buffer, img.data.byteOffset);
  const out = [];
  let regs = [];
  for (let o = text.start; o + 4 <= text.start + text.size; o += 4) {
    const pc = img.base + o, w = dv.getUint32(o, true);
    const ref = decodeRef(w, pc, regs);
    if (ref && set.has(ref.target)) {
      out.push({ from: pc, kind: ref.kind, target: ref.target, func: nearestName(img, pc) });
      if (out.length >= max) break;
    }
    if (((w & 0xfc000000) >>> 0) === 0x94000000 || w === 0xd65f03c0) regs = [];
  }
  return out;
}

// ---------- annotations (persisted per build id) ----------

function projectKey(file, img) {
  if (img.buildId) return img.buildId;
  return crypto.createHash("sha1").update(file + "|" + img.data.length).digest("hex").slice(0, 20);
}
function annPath(img) { return path.join(STATE_DIR, `${img.key}.json`); }
export function loadAnnotations(img) {
  let ann = { file: img.file, labels: {}, comments: {}, notes: "" };
  try { ann = { ...ann, ...JSON.parse(fs.readFileSync(annPath(img), "utf8")) }; } catch {}
  img.comments = Object.fromEntries(Object.entries(ann.comments).map(([k, v]) => [Number(k), v]));
  return ann;
}
function saveAnnotations(img, ann) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(annPath(img), JSON.stringify({ ...ann, file: img.file }, null, 2));
}

// ---------- strings / search / structs ----------

export function extractStrings(buf, base, minLen, max, filter) {
  const out = [];
  const re = filter ? new RegExp(filter, "i") : null;
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const c = buf[i];
    if (i < buf.length && ((c >= 0x20 && c < 0x7f) || c === 9)) { if (start < 0) start = i; continue; }
    if (start >= 0 && i - start >= minLen) {
      const text = Buffer.from(buf.subarray(start, i)).toString("latin1");
      if (!re || re.test(text)) { out.push({ addr: base + start, text }); if (out.length >= max) break; }
    }
    start = -1;
  }
  return out;
}

export function parsePattern(p) {
  p = String(p).trim();
  const q = p.match(/^"(.*)"$/s);
  if (q) return [...Buffer.from(q[1], "utf8")];
  const h = p.replace(/\s+/g, "");
  if (/^([0-9a-f?]{2})+$/i.test(h)) return h.match(/../g).map((x) => (x === "??" ? -1 : parseInt(x, 16)));
  return [...Buffer.from(p, "utf8")];
}

export function searchBytes(data, pat, base, max) {
  const out = [];
  const first = pat.findIndex((b) => b >= 0);
  outer: for (let i = 0; i + pat.length <= data.length; i++) {
    if (first >= 0) { i = data.indexOf(pat[first], i + first) - first; if (i < 0 || i + pat.length > data.length) break; }
    for (let j = 0; j < pat.length; j++) if (pat[j] >= 0 && data[i + j] !== pat[j]) continue outer;
    out.push(base + i);
    if (out.length >= max) break;
  }
  return out;
}

const STRUCT_TYPES = { u8: 1, s8: 1, i8: 1, u16: 2, s16: 2, i16: 2, u32: 4, s32: 4, i32: 4, u64: 8, s64: 8, i64: 8, f32: 4, f64: 8, ptr: 8, char: 1, bool: 1 };
export function decodeStruct(data, off, layout, littleDefault = true, count = 1) {
  const fields = layout.split(/[;\n]/).map((f) => f.trim()).filter(Boolean).map((f, idx) => {
    // bare type (optionally with [n]), e.g. "ptr" or "u64[8]" — auto-name it
    let m = f.match(/^(\w+?)(be|le)?(?:\[(\d+)\])?$/i);
    if (m && STRUCT_TYPES[m[1].toLowerCase()]) return { type: m[1].toLowerCase(), le: m[2] ? m[2].toLowerCase() === "le" : littleDefault, name: `f${idx}`, n: m[3] ? +m[3] : 0 };
    m = f.match(/^(\w+?)(be|le)?\s+(\w+)(?:\[(\d+)\])?$/i) || f.match(/^(\w+?)(be|le)?(?:\[(\d+)\])\s+(\w+)$/i);
    if (!m) throw new Error(`bad field: "${f}" (use e.g. "u32 magic; f32 pos[3]; char name[16]; u16be id", or a bare type like "ptr")`);
    const [type, end, name, n] = m[4] !== undefined && /^\d+$/.test(m[3]) ? [m[1], m[2], m[4], m[3]] : [m[1], m[2], m[3], m[4]];
    if (!STRUCT_TYPES[type.toLowerCase()]) throw new Error(`unknown type ${type}`);
    return { type: type.toLowerCase(), le: end ? end.toLowerCase() === "le" : littleDefault, name, n: n ? +n : 0 };
  });
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const read = (t, le, o) => {
    switch (t) {
      case "u8": case "bool": return dv.getUint8(o);
      case "s8": case "i8": return dv.getInt8(o);
      case "u16": return dv.getUint16(o, le); case "s16": case "i16": return dv.getInt16(o, le);
      case "u32": return dv.getUint32(o, le); case "s32": case "i32": return dv.getInt32(o, le);
      case "u64": case "ptr": return dv.getBigUint64(o, le); case "s64": case "i64": return dv.getBigInt64(o, le);
      case "f32": return dv.getFloat32(o, le); case "f64": return dv.getFloat64(o, le);
    }
  };
  const fmt = (t, v) => (t === "ptr" || (typeof v === "bigint" && v > 0xffffn) ? "0x" + v.toString(16) : typeof v === "bigint" ? v.toString() : t.startsWith("u") && v > 9 ? `${v} (0x${v.toString(16)})` : String(v));
  const recs = [];
  for (let r = 0; r < count; r++) {
    const lines = [];
    for (const f of fields) {
      const sz = STRUCT_TYPES[f.type];
      if (off + sz * Math.max(1, f.n) > data.length) { lines.push(`  ${f.name}: <out of range>`); break; }
      if (f.type === "char") { lines.push(`  ${hex(off)} ${f.name}: ${JSON.stringify(readCStr(data, off, f.n || 1))}`); off += f.n || 1; continue; }
      const vals = [];
      for (let i = 0; i < Math.max(1, f.n); i++, off += sz) vals.push(fmt(f.type, read(f.type, f.le, off)));
      lines.push(`  ${f.name}: ${f.n ? "[" + vals.join(", ") + "]" : vals[0]}`);
    }
    recs.push((count > 1 ? `[${r}] ` : "") + "{\n" + lines.join("\n") + "\n}");
  }
  return { text: recs.join("\n"), end: off };
}

// ---------- tool definitions (shared by MCP server and DeepSeek harness) ----------

const P = { type: "string", description: "Absolute path to the file (~ allowed)." };
const ADDR = { type: "string", description: "Virtual address (hex string like \"0x7100012340\" or integer). For NSO/NRO the default base is 0x7100000000." };
const BASE = { type: "string", description: "Override load base address (default 0x7100000000 for NSO/NRO, 0 for raw files)." };

export const TOOLS = [
  { name: "file_info", description: "Identify a file and summarize its structure. For Switch NSO/NRO: segments, build id, module path, symbol counts. For NSP/XCI/PFS0/HFS0: contained files. Start here.",
    inputSchema: { type: "object", properties: { path: P, base: BASE }, required: ["path"] } },
  { name: "read_binary_chunk", description: "Read bytes as a hexdump (or base64). Use `offset` for raw file offsets, or `address` for NSO/NRO virtual addresses (decompressed image). Max 64 KiB.",
    inputSchema: { type: "object", properties: { path: P, offset: { type: "integer", minimum: 0 }, address: ADDR, length: { type: "integer", minimum: 1, maximum: MAX_CHUNK, default: 256 }, format: { type: "string", enum: ["hex", "base64"], default: "hex" }, base: BASE }, required: ["path"] } },
  { name: "binary_strings", description: "List printable strings with addresses (like `strings -t x`). For NSO/NRO scans the decompressed image (default rodata). `filter` is a case-insensitive regex.",
    inputSchema: { type: "object", properties: { path: P, segment: { type: "string", description: "text | rodata | data | file (default: rodata for executables, whole file otherwise)" }, filter: { type: "string" }, min_length: { type: "integer", minimum: 2, default: 4 }, max_results: { type: "integer", minimum: 1, maximum: 5000, default: 200 }, base: BASE }, required: ["path"] } },
  { name: "search_bytes", description: "Search for a byte pattern. Hex with ?? wildcards (\"1f 20 03 d5 ?? ?? 00 94\") or quoted text (\"\\\"Error\\\"\"). Searches the decompressed image for NSO/NRO.",
    inputSchema: { type: "object", properties: { path: P, pattern: { type: "string" }, segment: { type: "string" }, max_results: { type: "integer", minimum: 1, maximum: 1000, default: 50 }, base: BASE }, required: ["path", "pattern"] } },
  { name: "disassemble", description: "Disassemble instructions at an address (AArch64 default; x86-64 available). Output is annotated with symbol/label names for branch targets and resolved ADRP+ADD/LDR data references, including string previews.",
    inputSchema: { type: "object", properties: { path: P, address: ADDR, symbol: { type: "string", description: "Symbol or label name to start at instead of address (substring match)." }, count: { type: "integer", minimum: 1, maximum: 2000, default: 64 }, arch: { type: "string", enum: ["aarch64", "x86-64"] }, base: BASE }, required: ["path"] } },
  { name: "find_xrefs", description: "Find code that references an address: calls (BL), branches, and ADRP-based data loads/stores/address computations. Returns referencing instruction addresses and enclosing function names.",
    inputSchema: { type: "object", properties: { path: P, address: ADDR, max_results: { type: "integer", minimum: 1, maximum: 2000, default: 100 }, base: BASE }, required: ["path", "address"] } },
  { name: "find_string_refs", description: "Find strings matching `text` (case-insensitive substring) in the image, then find the code that references each one. Great for locating functions by their log/error messages.",
    inputSchema: { type: "object", properties: { path: P, text: { type: "string" }, max_strings: { type: "integer", minimum: 1, maximum: 100, default: 10 }, base: BASE }, required: ["path", "text"] } },
  { name: "list_symbols", description: "List symbols (dynsym, demangled) and your saved labels. Filter with a case-insensitive regex.",
    inputSchema: { type: "object", properties: { path: P, filter: { type: "string" }, kind: { type: "string", enum: ["all", "func", "object", "imported", "labels"], default: "all" }, limit: { type: "integer", minimum: 1, maximum: 5000, default: 200 }, base: BASE }, required: ["path"] } },
  { name: "decode_struct", description: "Decode bytes using a C-like layout, e.g. \"u32 magic; u16be version; f32 pos[3]; char name[16]; ptr next\". Types: u8/s8/u16/s16/u32/s32/u64/s64/f32/f64/ptr/char/bool, optional be/le suffix.",
    inputSchema: { type: "object", properties: { path: P, offset: { type: "integer", minimum: 0 }, address: ADDR, layout: { type: "string" }, count: { type: "integer", minimum: 1, maximum: 256, default: 1 }, big_endian: { type: "boolean", default: false }, base: BASE }, required: ["path", "layout"] } },
  { name: "compare_files", description: "Compare two files byte-by-byte and report differing ranges.",
    inputSchema: { type: "object", properties: { path_a: P, path_b: P, offset: { type: "integer", minimum: 0, default: 0 }, length: { type: "integer", minimum: 1 }, max_diffs: { type: "integer", minimum: 1, maximum: 1000, default: 50 } }, required: ["path_a", "path_b"] } },
  { name: "annotate", description: "Save a label (function/variable name) and/or comment at an address. Persisted per build id under ~/.binharness and shown in later disassembly. Use this to build up knowledge as you reverse engineer.",
    inputSchema: { type: "object", properties: { path: P, address: ADDR, label: { type: "string" }, comment: { type: "string" }, notes: { type: "string", description: "Replace the free-form project notes for this binary." }, base: BASE }, required: ["path"] } },
  { name: "get_annotations", description: "Return saved labels, comments and notes for this binary.",
    inputSchema: { type: "object", properties: { path: P, base: BASE }, required: ["path"] } },
  { name: "extract_image", description: "Write the decompressed NSO/NRO memory image to `out` as a flat binary (load it at the base address in Ghidra/IDA), plus a .json sidecar with segments and symbols. Will not overwrite existing files.",
    inputSchema: { type: "object", properties: { path: P, out: { type: "string" }, base: BASE }, required: ["path", "out"] } },
];
TOOLS.push(...RE_TOOLS);
TOOLS.push({
  name: "label_syscalls",
  description: "Auto-name every nn::svc wrapper function (svcSleepThread, svcSendSyncRequest, …) and comment each `svc #n` site with its Horizon syscall name. Saves them as persistent annotations, so the names then appear in disassemble, list_functions and call_graph. Run this once on a fresh module.",
  inputSchema: { type: "object", properties: { path: { type: "string" }, base: { type: "string" }, dry_run: { type: "boolean", description: "Preview without saving." } }, required: ["path"] },
  annotations: { readOnlyHint: false },
});
TOOLS.push({
  name: "export_symbols",
  description: "Export everything recovered (function boundaries + names, RTTI vtables, svc/service labels, saved labels and comments) as Ghidra and/or IDA import scripts, so the names carry into a full disassembler. Runs the RTTI/syscall/service naming passes first by default (set label:false to export only what's already labeled). Pair with extract_image: load the image at the base address, then run the script. format: ghidra | ida | both (default) | json.",
  inputSchema: { type: "object", properties: { path: { type: "string" }, out: { type: "string", description: "Output path prefix (e.g. ./ngc). Suffixes .ghidra.py/.ida.py/.names.json are added." }, format: { type: "string", enum: ["ghidra", "ida", "both", "json"], default: "both" }, label: { type: "boolean", description: "Run RTTI/syscall/service labeling first (default true)." }, base: { type: "string" } }, required: ["path", "out"] },
  annotations: { readOnlyHint: false },
});
TOOLS.push({
  name: "label_rtti",
  description: "Name every recovered vtable (vtable_<Class>) and its virtual-method functions (<Class>::vf<n>) from C++ RTTI, as persistent annotations. One of the biggest name-recovery passes for a stripped C++ module; run after find_rtti looks right.",
  inputSchema: { type: "object", properties: { path: { type: "string" }, base: { type: "string" }, dry_run: { type: "boolean" } }, required: ["path"] },
  annotations: { readOnlyHint: false },
});
TOOLS.push({
  name: "parse_npdm",
  description: "Parse a main.npdm (Switch program metadata): program id, 32/64-bit, and the authoritative Service Access Control — which services the module may HOST (register) vs CONNECT to — plus the kernel syscall allowlist. If a sibling `main` NSO exists, cross-checks the syscalls the code actually issues against the allowlist. This is ground truth, unlike find_services/scan_syscalls.",
  inputSchema: { type: "object", properties: { path: { type: "string", description: "Path to the .npdm file." } }, required: ["path"] },
  annotations: { readOnlyHint: true },
});
TOOLS.push({
  name: "label_services",
  description: "Label the functions that reference each IPC service as use_<service> (e.g. use_fsp_srv) and comment the service-name strings. Saved as persistent annotations so names appear in disassemble, list_functions and call_graph.",
  inputSchema: { type: "object", properties: { path: { type: "string" }, base: { type: "string" }, dry_run: { type: "boolean" } }, required: ["path"] },
  annotations: { readOnlyHint: false },
});
for (const t of TOOLS) t.annotations = { readOnlyHint: !["annotate", "extract_image"].includes(t.name) };

function segData(img, name) {
  if (!name || name === "file" || name === "all") return { data: img.data, start: 0 };
  const s = img.segments.find((x) => x.name === name);
  if (!s) throw new Error(`no segment "${name}" (have: ${img.segments.map((x) => x.name).join(", ")})`);
  return { data: img.data.subarray(s.start, s.start + s.size), start: s.start };
}

function resolveAddr(img, args) {
  if (args.symbol) {
    const q = args.symbol.toLowerCase();
    const hit = img.sortedNamed.find(([, n]) => n.toLowerCase() === q) || img.sortedNamed.find(([, n]) => n.toLowerCase().includes(q));
    if (!hit) throw new Error(`no symbol/label matching "${args.symbol}"`);
    return hit[0];
  }
  const a = parseNum(args.address);
  if (a !== undefined && !Number.isNaN(a)) return a;
  if (args.offset !== undefined) return img.base + args.offset;
  return img.base + seg(img, "text").start;
}

export function callTool(name, args = {}) {
  const text = (t, extra) => ({ content: [{ type: "text", text: t }], structuredContent: extra });
  if (name === "compare_files") {
    const a = resolvePath(args.path_a), b = resolvePath(args.path_b);
    const sa = fs.statSync(a).size, sb = fs.statSync(b).size, off = args.offset || 0;
    const len = Math.min(args.length ?? Infinity, Math.max(sa, sb) - off, 256 << 20);
    const A = readRange(a, off, len).buf, B = readRange(b, off, len).buf;
    const diffs = []; let i = 0;
    const n = Math.max(A.length, B.length);
    while (i < n && diffs.length < (args.max_diffs || 50)) {
      if (A[i] === B[i]) { i++; continue; }
      const s = i; while (i < n && A[i] !== B[i]) i++;
      diffs.push({ offset: off + s, length: i - s });
    }
    const lines = diffs.map((d) => `${hex(d.offset)} +${d.length}:  ${Buffer.from(A.subarray(d.offset - off, d.offset - off + Math.min(d.length, 16))).toString("hex")}  vs  ${Buffer.from(B.subarray(d.offset - off, d.offset - off + Math.min(d.length, 16))).toString("hex")}`);
    return text(`sizes: ${sa} vs ${sb}\n${diffs.length ? lines.join("\n") : "no differences in range"}`, { diffs });
  }

  if (name === "parse_npdm") {
    const npdmFile = resolvePath(args.path);
    const buf = fs.readFileSync(npdmFile);
    const sibling = path.join(path.dirname(npdmFile), "main");
    let img = null; try { if (fs.existsSync(sibling)) img = openImage(sibling); } catch { /* ignore */ }
    return npdmTool(buf, img);
  }

  const file = resolvePath(args.path);
  const head = readRange(file, 0, 0x200);
  const format = detectFormat(head.buf, head.size, file);
  const isExe = /NSO|NRO/.test(format || "");

  if (name === "file_info") {
    const lines = [`${file}`, `${head.size} bytes (${hex(head.size)})${format ? " — " + format : ""}`];
    if (isExe) {
      const img = openImage(file, args);
      lines.push(`base ${hex(img.base)}  build id ${img.buildId || "-"}${img.modulePath ? "  module " + img.modulePath : ""}`);
      for (const s of img.segments) lines.push(`  ${s.name.padEnd(7)} ${hex(img.base + s.start)} - ${hex(img.base + s.start + s.size)}  ${s.perm}  ${hex(s.size)}${s.compressed ? "  (lz4)" : ""}`);
      const f = img.symbols.filter((s) => !s.imported).length;
      lines.push(`symbols: ${img.symbols.length} (${f} defined, ${img.symbols.length - f} imported); labels: ${img.sortedNamed.length - new Set(img.symbols.filter((s) => s.addr).map((s) => s.addr)).size} saved`);
    } else if (/NPDM/.test(format || "")) {
      try { const n = parseNpdm(readRange(file, 0, head.size).buf); lines.push(`${n.name}  ${n.programId}  ${n.is64Bit ? "64-bit" : "32-bit"}`, `hosts: ${n.services.filter((x) => x.host).map((x) => x.name).join(" ") || "—"}`, `connects to: ${n.services.filter((x) => !x.host).map((x) => x.name).join(" ") || "—"}`); } catch (e) { lines.push("(NPDM parse failed: " + e.message + ")"); }
    } else if (/PFS0|HFS0/.test(format || "")) {
      const p = parsePfs0(file);
      lines.push(...p.files.map((f) => `  ${f.name}  @${hex(f.offset)}  ${f.size} bytes`));
    } else if (/XCI/.test(format || "")) {
      const x = parseXci(file);
      for (const p of x.partitions) { lines.push(`  [${p.name}] @${hex(p.offset)} ${p.size} bytes`); for (const f of p.files || []) lines.push(`      ${f.name}  ${f.size} bytes`); }
    } else lines.push("", hexdump(head.buf.subarray(0, 256), 0));
    return text(lines.join("\n"), { path: file, size: head.size, format });
  }

  if (name === "read_binary_chunk") {
    const len = Math.min(args.length || 256, MAX_CHUNK);
    if (args.address !== undefined && isExe) {
      const img = openImage(file, args), a = parseNum(args.address), o = a - img.base;
      if (o < 0 || o >= img.data.length) throw new Error(`address ${hex(a)} outside image`);
      const b = Buffer.from(img.data.subarray(o, o + len));
      return text(args.format === "base64" ? b.toString("base64") : hexdump(b, a), { address: a, length: b.length, data: b.toString("base64") });
    }
    const r = readRange(file, args.offset ?? parseNum(args.address) ?? 0, len);
    const b64 = r.buf.toString("base64");
    return text(args.format === "base64" ? b64 : hexdump(r.buf, r.offset) || "(no bytes in range)", { path: file, size: r.size, offset: r.offset, length: r.buf.length, data: b64 });
  }

  if (name === "binary_strings") {
    let data, base;
    if (isExe) { const img = openImage(file, args); const sd = segData(img, args.segment || "rodata"); data = sd.data; base = img.base + sd.start; }
    else { data = readRange(file, 0, 64 << 20).buf; base = 0; }
    const strs = extractStrings(data, base, args.min_length || 4, args.max_results || 200, args.filter);
    return text(strs.map((x) => `${x.addr.toString(16)}  ${x.text}`).join("\n") || "(no strings found)", { strings: strs });
  }

  if (name === "search_bytes") {
    const pat = parsePattern(args.pattern);
    if (!pat.length) throw new Error("empty pattern");
    let data, base;
    if (isExe) { const img = openImage(file, args); const sd = segData(img, args.segment); data = sd.data; base = img.base + sd.start; }
    else { data = fs.readFileSync(file); base = 0; }
    const hits = searchBytes(data, pat, base, args.max_results || 50);
    return text(hits.length ? hits.map((h) => hex(h)).join("\n") : "no matches", { hits });
  }

  if (name === "extract_image") {
    if (!isExe) throw new Error("extract_image needs an NSO or NRO");
    const img = openImage(file, args), out = resolvePath(args.out);
    if (fs.existsSync(out)) throw new Error(`${out} already exists`);
    fs.writeFileSync(out, img.data);
    fs.writeFileSync(out + ".json", JSON.stringify({ source: file, base: hex(img.base), buildId: img.buildId, segments: img.segments.map((s) => ({ ...s, start: hex(img.base + s.start) })), symbols: img.symbols.filter((s) => s.addr).map((s) => ({ name: s.name, demangled: s.demangled, addr: hex(s.addr), size: s.size, type: s.type })) }, null, 2));
    return text(`wrote ${out} (${img.data.length} bytes, load at ${hex(img.base)}) and ${out}.json`);
  }

  // Remaining tools operate on an executable image (raw files are treated as a flat blob at base).
  const img = openImage(file, args);

  if (name === "disassemble") {
    if (args.arch && args.arch !== img.arch) { img.arch = args.arch; }
    const a = resolveAddr(img, args);
    return text(disassemble(img, a, Math.min(args.count || 64, 2000)), { address: a });
  }

  if (name === "find_xrefs") {
    const a = parseNum(args.address);
    const refs = findXrefs(img, a, args.max_results || 100);
    return text(refs.length ? refs.map((r) => `${r.from.toString(16)}  ${r.kind.padEnd(5)}  ${r.func || ""}`).join("\n") : `no references to ${hex(a)} found`, { refs });
  }

  if (name === "find_string_refs") {
    const pat = String(args.text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const lim = args.max_strings || 10;
    const strs = [];
    for (const sname of ["rodata", "data"]) {
      const s = img.segments.find((x) => x.name === sname);
      if (!s) continue;
      strs.push(...extractStrings(img.data.subarray(s.start, s.start + s.size), img.base + s.start, 3, lim, pat));
    }
    if (img.kind === "raw") strs.push(...extractStrings(img.data, img.base, 3, lim, pat));
    const pick = strs.slice(0, lim);
    if (!pick.length) return text(`no strings containing "${args.text}"`);
    const refs = findXrefs(img, pick.map((s) => s.addr), 5000);
    const out = pick.map((s) => {
      const rs = refs.filter((r) => r.target === s.addr);
      return `${s.addr.toString(16)}  ${JSON.stringify(s.text.slice(0, 120))}\n` + (rs.length ? rs.map((r) => `    <- ${r.from.toString(16)}  ${r.func || ""}`).join("\n") : "    (no direct code refs found)");
    });
    return text(out.join("\n"), { strings: pick, refs });
  }

  if (name === "list_symbols") {
    const re = args.filter ? new RegExp(args.filter, "i") : null;
    let rows;
    if (args.kind === "labels") {
      const ann = loadAnnotations(img);
      rows = Object.entries(ann.labels).map(([a, n]) => ({ addr: Number(a), name: n, type: "label" }));
    } else {
      rows = img.symbols.filter((s) => (args.kind === "func" ? s.type === "func" && !s.imported : args.kind === "object" ? s.type === "object" : args.kind === "imported" ? s.imported : true));
    }
    rows = rows.filter((s) => !re || re.test(s.demangled || s.name)).slice(0, args.limit || 200);
    return text(rows.map((s) => `${s.addr ? s.addr.toString(16).padStart(10) : "  (import)"}  ${(s.type || "").padEnd(6)}  ${s.demangled || s.name}`).join("\n") || "(none)", { count: rows.length });
  }

  if (name === "decode_struct") {
    let data, off, base;
    if (args.address !== undefined) { data = img.data; base = img.base; off = parseNum(args.address) - img.base; }
    else { data = readRange(file, 0, Math.min(head.size, 256 << 20)).buf; base = 0; off = args.offset || 0; }
    const r = decodeStruct(data, off, args.layout, !args.big_endian, args.count || 1);
    return text(`@ ${hex(base + off)}\n${r.text}\n(next: ${hex(base + r.end)})`);
  }

  if (name === "annotate") {
    const ann = loadAnnotations(img);
    const a = args.address !== undefined ? parseNum(args.address) : undefined;
    if (args.label !== undefined) { if (a === undefined) throw new Error("address required for label"); if (args.label) ann.labels[a] = args.label; else delete ann.labels[a]; }
    if (args.comment !== undefined) { if (a === undefined) throw new Error("address required for comment"); if (args.comment) ann.comments[a] = args.comment; else delete ann.comments[a]; }
    if (args.notes !== undefined) ann.notes = args.notes;
    saveAnnotations(img, ann);
    finishSymbols(img);
    return text(`saved${a !== undefined ? " at " + hex(a) : ""} (${Object.keys(ann.labels).length} labels, ${Object.keys(ann.comments).length} comments)`);
  }

  if (name === "get_annotations") {
    const ann = loadAnnotations(img);
    const lines = [`labels (${Object.keys(ann.labels).length}):`, ...Object.entries(ann.labels).map(([a, n]) => `  ${Number(a).toString(16)}  ${n}`),
      `comments (${Object.keys(ann.comments).length}):`, ...Object.entries(ann.comments).map(([a, c]) => `  ${Number(a).toString(16)}  ${c}`),
      `notes:`, ann.notes || "  (none)"];
    return text(lines.join("\n"));
  }

  if (name === "label_syscalls") {
    const ann = loadAnnotations(img);
    const sites = scanSyscalls(img);
    const perFunc = new Map(); // funcOff -> Set(num)
    for (const st of sites) { const f = functionAt(img, st.addr); if (f) (perFunc.get(f.off) || perFunc.set(f.off, new Set()).get(f.off)).add(st.num); }
    let labeled = 0, commented = 0;
    const named = [];
    for (const st of sites) {
      const nm = SVC_NAMES[st.num];
      if (ann.comments[st.addr] === undefined) { ann.comments[st.addr] = `svc #0x${st.num.toString(16)} ${nm || "Unknown"}`; commented++; }
      const f = functionAt(img, st.addr);
      // A wrapper is a small function whose only syscall is this one.
      if (f && nm && perFunc.get(f.off).size === 1 && f.size <= 0x80 && !ann.labels[f.addr]) {
        ann.labels[f.addr] = `svc${nm}`; labeled++; named.push(`${f.addr.toString(16)}  svc${nm}`);
      }
    }
    if (!args.dry_run) { saveAnnotations(img, ann); finishSymbols(img); }
    const text = `${sites.length} svc sites: ${labeled} wrapper functions ${args.dry_run ? "would be " : ""}named, ${commented} sites commented.\n` + named.slice(0, 40).join("\n");
    return { content: [{ type: "text", text }], structuredContent: { labeled, commented } };
  }
  if (name === "find_services") return findServicesTool(img, args);
  if (name === "find_rtti") return findRttiTool(img, args);
  if (name === "export_symbols") {
    // Run the naming passes first so the export is never empty (opt out with label:false).
    const passes = [];
    if (args.label !== false) for (const p of ["label_rtti", "label_syscalls", "label_services"]) {
      try { const r = callTool(p, { path: args.path, base: args.base }); passes.push(`${p}: ${r.content[0].text.split("\n")[0]}`); } catch (e) { passes.push(`${p}: skipped (${e.message})`); }
    }
    const sym = collectSymbols(img, loadAnnotations(img));
    const meta = { name: path.basename(path.dirname(file)) === "." ? path.basename(file) : path.basename(file), base: img.base, buildId: img.buildId };
    const out = resolvePath(args.out), fmt = args.format || "both", written = [];
    const write = (suffix, content) => { const f = out + suffix; if (fs.existsSync(f)) throw new Error(`${f} already exists`); fs.writeFileSync(f, content); written.push(f); };
    if (fmt === "ghidra" || fmt === "both") write(".ghidra.py", emitGhidra(sym, meta));
    if (fmt === "ida" || fmt === "both") write(".ida.py", emitIda(sym, meta));
    if (fmt === "json") write(".names.json", JSON.stringify(sym, null, 1));
    const named = sym.functions.filter((f) => !/^sub_/.test(f.name)).length;
    return { content: [{ type: "text", text: `${passes.length ? passes.join("\n") + "\n" : ""}exported ${sym.functions.length} functions (${named} named), ${sym.labels.length} labels, ${sym.comments.length} comments to:\n${written.join("\n")}` }], structuredContent: { functions: sym.functions.length, named, labels: sym.labels.length, comments: sym.comments.length, files: written } };
  }
  if (name === "label_rtti") {
    const ann = loadAnnotations(img);
    const classes = scanRtti(img), relocs = getRelocations(img);
    let vt = 0, methods = 0;
    for (const c of classes) {
      const base = c.name.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
      for (const v of c.vtables) {
        if (!ann.labels[v.addr]) { ann.labels[v.addr] = `vtable_${base}`; vt++; }
        for (let i = 0; i < v.methods; i++) {
          const fp = relocs.get(v.off + i * 8); if (fp === undefined) continue;
          // Follow call veneers so the name lands on the real implementation, not the thunk.
          const fa = resolveThunk(img, img.base + fp);
          if (!ann.labels[fa] && !img.addrNames.has(fa)) { ann.labels[fa] = `${base}::vf${i}`; methods++; }
        }
      }
    }
    if (!args.dry_run) { saveAnnotations(img, ann); finishSymbols(img); }
    return { content: [{ type: "text", text: `${classes.length} classes: ${vt} vtables and ${methods} virtual methods ${args.dry_run ? "would be " : ""}labeled.` }], structuredContent: { vtables: vt, methods } };
  }
  if (name === "label_services") {
    const ann = loadAnnotations(img);
    const svcs = findServices(img);
    let labeled = 0, commented = 0; const named = [];
    for (const s of svcs) {
      if (ann.comments[s.addr] === undefined) { ann.comments[s.addr] = `service "${s.name}"`; commented++; }
      // Label a referencing function use_<svc> when it refs exactly one service and is unnamed.
      for (const r of s.refs) {
        const f = functionAt(img, r.from); if (!f || ann.labels[f.addr] || img.addrNames.has(f.addr)) continue;
        const others = svcs.filter((o) => o !== s && o.refs.some((x) => { const g = functionAt(img, x.from); return g && g.off === f.off; }));
        if (others.length) continue;
        ann.labels[f.addr] = `use_${s.name.replace(/[^A-Za-z0-9]/g, "_")}`; labeled++; named.push(`${f.addr.toString(16)}  ${ann.labels[f.addr]}`);
      }
    }
    if (!args.dry_run) { saveAnnotations(img, ann); finishSymbols(img); }
    const text = `${svcs.length} services: ${labeled} functions ${args.dry_run ? "would be " : ""}labeled, ${commented} service strings commented.\n` + named.slice(0, 40).join("\n");
    return { content: [{ type: "text", text }], structuredContent: { labeled, commented } };
  }
  if (name === "list_functions") return listFunctions(img, args);
  if (name === "call_graph") return callGraphTool(img, args, resolveAddr);
  if (name === "scan_syscalls") return scanSyscallsTool(img, args);

  throw new Error(`Unknown tool: ${name}`);
}

export function safeCallTool(name, args) {
  try { return callTool(name, args); }
  catch (e) { return { isError: true, content: [{ type: "text", text: String(e.message || e) }] }; }
}
