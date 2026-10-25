// Shared low-level primitives used by both bintools.mjs (the tool layer) and
// re.mjs (the Switch RE layer). Kept dependency-free and importing nothing from
// either, so there is no import cycle — re.mjs and bintools.mjs both depend on
// this, not on each other for these helpers.

const _warned = new Set();
export function warnOnce(key, msg) { if (!_warned.has(key)) { _warned.add(key); try { process.stderr.write(`[binharness] ${msg}\n`); } catch { /* ignore */ } } }

export const hex = (n, w = 0) => "0x" + n.toString(16).padStart(w, "0");
export const sext = (v, bits) => (v << (32 - bits)) >> (32 - bits);
export const page = (a) => a - (a % 4096);

export function segmentAt(img, addr) {
  const off = addr - img.base;
  return img.segments.find((s) => off >= s.start && off < s.start + s.size);
}
export const seg = (img, name) => img.segments.find((s) => s.name === name) || img.segments[0];

export function nearestName(img, addr, maxDist = 0x100000) {
  const a = img.sortedNamed;
  let lo = 0, hi = a.length - 1, best = -1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (a[mid][0] <= addr) { best = mid; lo = mid + 1; } else hi = mid - 1; }
  if (best < 0) return null;
  const [base, name] = a[best];
  if (addr - base >= maxDist || segmentAt(img, addr) !== segmentAt(img, base)) return null;
  return addr === base ? name : `${name}+${hex(addr - base)}`;
}

// Decode one AArch64 instruction for branch/data references; updates `regs`
// for ADRP/ADR/ADD so ADRP+ADD/LDR data refs resolve. Returns {kind, target}.
export function decodeRef(w, pc, regs) {
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

// Scan the executable segment for references to target(s): calls, branches, and
// ADRP-based data loads/stores/address computations.
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
