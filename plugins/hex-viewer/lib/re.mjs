// Reverse-engineering layer for stripped, statically-linked Switch modules:
// MOD0/.dynamic parsing, relocation application (RELR + RELA relative),
// function-boundary recovery, call graph, and syscall scanning.
// Pure analysis over an image produced by bintools.openImage().
import { hex, extractStrings, findXrefs, warnOnce } from "./core.mjs";
import { spawnSync } from "node:child_process";

// Known Horizon service namespaces (part before ':') and bare service names.
// Used to filter rodata strings down to real services with low false positives.
const SVC_NS = new Set("sm lm fsp fsp-srv ldr ro pm set apm appletAE appletOE hid hidbus irs nvdrv time csrng spl pcv pcie psm bpc gpio i2c uart pwm nfc nfp btdrv bt btm bsd sfdnsres nsd nifm ethc ssl nim ns aoc pctl account acc dauth friends notif bcat erpt eupld lp2p ldn caps grc audout audin audrec audren auddev codecctl hwopus es pl psc lbl nvgpu vi dispdrv disp omm cap ovln prepo mm mmnv ndd npns arp wlan usb jit gsv fatal po pj ssml adraw tlm gpu vsync syncpt vi2 ngc ngct vic ro".split(/\s+/));
const SVC_NAMES_SET = new Set("sm: lm fsp-srv fsp-pr fsp-ldr nvdrv csrng apm hid irs pcv pcie psm bpc gpio btdrv bt btm nvgpu nim ssl account es lbl wlan mmnv ndd cap pwm".split(/\s+/));

function isServiceName(s) {
  if (s.length < 2 || s.length > 8) return false;       // Horizon service names are at most 8 bytes
  if (s.includes("::")) return false;                    // C++ namespace, not a service
  if (SVC_NAMES_SET.has(s)) return true;
  const ci = s.indexOf(":");
  if (ci > 0) return SVC_NS.has(s.slice(0, ci));          // "set:sys" -> namespace "set"
  if (s.includes("-")) return SVC_NAMES_SET.has(s);       // "fsp-srv" style, must be known
  return false;
}

const sext = (v, bits) => (v << (32 - bits)) >> (32 - bits);

// Horizon 64-bit SVC table (id -> name). Stable across firmware.
export const SVC_NAMES = {
  0x01: "SetHeapSize", 0x02: "SetMemoryPermission", 0x03: "SetMemoryAttribute", 0x04: "MapMemory", 0x05: "UnmapMemory",
  0x06: "QueryMemory", 0x07: "ExitProcess", 0x08: "CreateThread", 0x09: "StartThread", 0x0a: "ExitThread",
  0x0b: "SleepThread", 0x0c: "GetThreadPriority", 0x0d: "SetThreadPriority", 0x0e: "GetThreadCoreMask", 0x0f: "SetThreadCoreMask",
  0x10: "GetCurrentProcessorNumber", 0x11: "SignalEvent", 0x12: "ClearEvent", 0x13: "MapSharedMemory", 0x14: "UnmapSharedMemory",
  0x15: "CreateTransferMemory", 0x16: "CloseHandle", 0x17: "ResetSignal", 0x18: "WaitSynchronization", 0x19: "CancelSynchronization",
  0x1a: "ArbitrateLock", 0x1b: "ArbitrateUnlock", 0x1c: "WaitProcessWideKeyAtomic", 0x1d: "SignalProcessWideKey", 0x1e: "GetSystemTick",
  0x1f: "ConnectToNamedPort", 0x20: "SendSyncRequestLight", 0x21: "SendSyncRequest", 0x22: "SendSyncRequestWithUserBuffer", 0x23: "SendAsyncRequestWithUserBuffer",
  0x24: "GetProcessId", 0x25: "GetThreadId", 0x26: "Break", 0x27: "OutputDebugString", 0x28: "ReturnFromException",
  0x29: "GetInfo", 0x2a: "FlushEntireDataCache", 0x2b: "FlushDataCache", 0x2c: "MapPhysicalMemory", 0x2d: "UnmapPhysicalMemory",
  0x2e: "GetDebugFutureThreadInfo", 0x2f: "GetLastThreadInfo", 0x30: "GetResourceLimitLimitValue", 0x31: "GetResourceLimitCurrentValue",
  0x32: "SetThreadActivity", 0x33: "GetThreadContext3", 0x34: "WaitForAddress", 0x35: "SignalToAddress", 0x36: "SynchronizePreemptionState",
  0x37: "GetResourceLimitPeakValue", 0x39: "CreateIoPool", 0x3a: "CreateIoRegion", 0x3c: "KernelDebug", 0x3d: "ChangeKernelTraceState",
  0x40: "CreateSession", 0x41: "AcceptSession", 0x42: "ReplyAndReceiveLight", 0x43: "ReplyAndReceive", 0x44: "ReplyAndReceiveWithUserBuffer",
  0x45: "CreateEvent", 0x46: "MapIoRegion", 0x47: "UnmapIoRegion", 0x48: "MapPhysicalMemoryUnsafe", 0x49: "UnmapPhysicalMemoryUnsafe",
  0x4a: "SetUnsafeLimit", 0x4b: "CreateCodeMemory", 0x4c: "ControlCodeMemory", 0x4d: "SleepSystem", 0x4e: "ReadWriteRegister",
  0x4f: "SetProcessActivity", 0x50: "CreateSharedMemory", 0x51: "MapTransferMemory", 0x52: "UnmapTransferMemory", 0x53: "CreateInterruptEvent",
  0x54: "QueryPhysicalAddress", 0x55: "QueryIoMapping", 0x56: "CreateDeviceAddressSpace", 0x57: "AttachDeviceAddressSpace", 0x58: "DetachDeviceAddressSpace",
  0x59: "MapDeviceAddressSpaceByForce", 0x5a: "MapDeviceAddressSpaceAligned", 0x5b: "MapDeviceAddressSpace", 0x5c: "UnmapDeviceAddressSpace",
  0x5d: "InvalidateProcessDataCache", 0x5e: "StoreProcessDataCache", 0x5f: "FlushProcessDataCache", 0x60: "DebugActiveProcess",
  0x61: "BreakDebugProcess", 0x62: "TerminateDebugProcess", 0x63: "GetDebugEvent", 0x64: "ContinueDebugEvent", 0x65: "GetProcessList",
  0x66: "GetThreadList", 0x67: "GetDebugThreadContext", 0x68: "SetDebugThreadContext", 0x69: "QueryDebugProcessMemory", 0x6a: "ReadDebugProcessMemory",
  0x6b: "WriteDebugProcessMemory", 0x6c: "SetHardwareBreakPoint", 0x6d: "GetDebugThreadParam", 0x6f: "GetSystemInfo", 0x70: "CreatePort",
  0x71: "ManageNamedPort", 0x72: "ConnectToPort", 0x73: "SetProcessMemoryPermission", 0x74: "MapProcessMemory", 0x75: "UnmapProcessMemory",
  0x76: "QueryProcessMemory", 0x77: "MapProcessCodeMemory", 0x78: "UnmapProcessCodeMemory", 0x79: "CreateProcess", 0x7a: "StartProcess",
  0x7b: "TerminateProcess", 0x7c: "GetProcessInfo", 0x7d: "CreateResourceLimit", 0x7e: "SetResourceLimitLimitValue", 0x7f: "CallSecureMonitor",
};

// ---------- MOD0 / .dynamic ----------

export function parseDynamic(img) {
  if (img._dyn) return img._dyn;
  const d = img.data, dv = new DataView(d.buffer, d.byteOffset);
  const text = img.segments.find((s) => s.name === "text");
  const out = { tags: {}, text };
  try {
    const mod0 = dv.getUint32(4, true);
    if (d.length < mod0 + 8 || Buffer.from(d.subarray(mod0, mod0 + 4)).toString("latin1") !== "MOD0") return (img._dyn = out);
    out.mod0 = mod0;
    const dyn = mod0 + dv.getInt32(mod0 + 4, true);
    out.dynamic = dyn;
    for (let o = dyn, k = 0; k < 128 && o + 16 <= d.length; k++, o += 16) {
      const tag = Number(dv.getBigInt64(o, true)), val = Number(dv.getBigUint64(o + 8, true));
      if (tag === 0) break;
      out.tags[tag] = val; // last wins; fine for these
    }
  } catch { /* leave empty */ }
  return (img._dyn = out);
}

// Apply relative relocations (RELR packed + RELA R_AARCH64_RELATIVE=1027) over a
// copy-free index: returns Map(location -> absolute target) using image offsets.
export function getRelocations(img) {
  if (img._relocs) return img._relocs;
  const dyn = parseDynamic(img), t = dyn.tags, d = img.data, dv = new DataView(d.buffer, d.byteOffset);
  const relocs = new Map(); // loc(offset) -> targetOffset
  const inImage = (o) => o >= 0 && o < d.length;
  // RELR: DT_RELR=0x24(36) addr, DT_RELRSZ=0x23(35) size
  if (t[36] && t[35]) {
    let base = 0;
    for (let o = t[36], end = t[36] + t[35]; o + 8 <= end && o + 8 <= d.length; o += 8) {
      const entry = dv.getBigUint64(o, true);
      if ((entry & 1n) === 0n) { // address entry
        base = Number(entry);
        if (inImage(base)) { relocs.set(base, Number(dv.getBigUint64(base, true))); base += 8; }
      } else { // bitmap of the next 63 words
        let bits = entry >> 1n, where = base;
        for (let i = 0; i < 63; i++, where += 8, bits >>= 1n) {
          if ((bits & 1n) === 1n && inImage(where)) relocs.set(where, Number(dv.getBigUint64(where, true)));
        }
        base += 63 * 8;
      }
    }
  }
  // RELA: DT_RELA=7 addr, DT_RELASZ=8 size, 24-byte entries. Keep only RELATIVE (type 1027).
  if (t[7] && t[8]) {
    for (let o = t[7], end = t[7] + t[8]; o + 24 <= end && o + 24 <= d.length; o += 24) {
      const where = Number(dv.getBigUint64(o, true)), info = dv.getBigUint64(o + 8, true), addend = Number(dv.getBigInt64(o + 16, true));
      if (Number(info & 0xffffffffn) === 1027 && inImage(where)) relocs.set(where, addend);
    }
  }
  return (img._relocs = relocs);
}

// ---------- function recovery ----------

const isBL = (w) => (w >>> 26) === 0x25; // BL
const isB = (w) => (w >>> 26) === 0x05;  // B
const blTarget = (w, pc) => pc + sext(w & 0x3ffffff, 26) * 4;

// Does the word look like a function prologue?
function isPrologue(w) {
  if (w === 0xd503233f || w === 0xd503237f) return true;           // paciasp / pacibsp
  if ((w & 0xffc003e0) === 0xa9800000 && (w & 31) === 29) return false; // (guard)
  if ((w & 0xffe07fff) === 0xa9807bfd) return true;                // stp x29,x30,[sp,#imm]! (pre-index)
  if ((w & 0xffc07fff) === 0xa9007bfd) return true;                // stp x29,x30,[sp,#imm]
  if ((w & 0xffc003ff) === 0xd10003ff) return true;                // sub sp,sp,#imm
  if ((w & 0xffc07fe0) === 0xa9bf0000 || (w & 0xffe07fe0) === 0xa9bf0000) return true; // stp ..,[sp,#-imm]!
  return false;
}

export function buildFunctions(img) {
  if (img.functions) return img.functions;
  const dyn = parseDynamic(img), text = dyn.text, d = img.data, dv = new DataView(d.buffer, d.byteOffset);
  const base = img.base, tStart = text.start, tEnd = text.start + text.size;
  const inText = (o) => o >= tStart && o < tEnd;
  const seeds = new Set();
  const addOff = (o) => { if (inText(o) && (o & 3) === 0) seeds.add(o); };

  // 1. BL targets + relocated code pointers + any defined symbols.
  const callEdges = []; // [siteOff, targetOff]
  for (let o = tStart; o + 4 <= tEnd; o += 4) {
    const w = dv.getUint32(o, true);
    if (isBL(w)) { const tOff = o + sext(w & 0x3ffffff, 26) * 4; addOff(tOff); callEdges.push([o, tOff]); }
  }
  for (const [loc, tgt] of getRelocations(img)) if (inText(tgt)) addOff(tgt); // vtables, init_array, func ptrs
  for (const s of img.symbols) if (s.addr && inText(s.addr - base)) addOff(s.addr - base);
  // 2. init/fini and entry.
  const t = dyn.tags;
  for (const tag of [12, 13]) if (t[tag]) addOff(t[tag]); // DT_INIT/DT_FINI
  for (const [arr, sz] of [[25, 27], [26, 28]]) { // DT_INIT_ARRAY/sz, DT_FINI_ARRAY/sz
    if (t[arr] && t[sz]) for (let o = t[arr]; o < t[arr] + t[sz] && o + 8 <= d.length; o += 8) addOff(Number(dv.getBigUint64(o, true)) - base);
  }
  addOff(0); // module entry (after the MOD0 trampoline branch)

  // 3. Prologues that directly follow a function end (ret/b + padding) catch
  //    functions that are only reached indirectly.
  let prevEnd = true;
  for (let o = tStart; o + 4 <= tEnd; o += 4) {
    const w = dv.getUint32(o, true);
    if (prevEnd && isPrologue(w)) addOff(o);
    prevEnd = w === 0xd65f03c0 /*ret*/ || w === 0xd503201f /*nop*/ || w === 0 || isB(w);
  }

  const starts = [...seeds].sort((a, b) => a - b);
  const funcs = starts.map((start, i) => {
    const end = i + 1 < starts.length ? starts[i + 1] : tEnd;
    const first = dv.getUint32(start, true);
    return { addr: base + start, off: start, size: end - start, prologue: isPrologue(first) };
  }).filter((f) => f.size > 0);

  img.functions = funcs;
  img._funcStarts = funcs.map((f) => f.off);
  img._callEdges = callEdges;
  return funcs;
}

// Follow single-instruction call veneers/thunks to the real target:
//   b <target>                         (plain tail-branch veneer)
//   adrp x16,#x ; add x16,x16,#y ; br x16   (range-extension thunk)
// Returns the ultimate target address (or the input if it isn't a thunk).
export function resolveThunk(img, addr, maxHops = 4) {
  const d = img.data, dv = new DataView(d.buffer, d.byteOffset);
  const at = (a) => { const o = a - img.base; return o >= 0 && o + 4 <= d.length ? dv.getUint32(o, true) : null; };
  for (let hop = 0; hop < maxHops; hop++) {
    const w = at(addr);
    if (w === null) break;
    if (((w & 0xfc000000) >>> 0) === 0x14000000) { addr = addr + sext(w & 0x3ffffff, 26) * 4; continue; } // b
    // adrp xN ; add xN,xN,#imm ; br xN
    if (((w & 0x9f000000) >>> 0) === 0x90000000) {
      const rd = w & 31, w2 = at(addr + 4), w3 = at(addr + 8);
      if (w2 !== null && w3 !== null && ((w2 & 0xff800000) >>> 0) === 0x91000000 && ((w2 >>> 5) & 31) === rd && (w2 & 31) === rd
          && ((w3 & 0xfffffc1f) >>> 0) === 0xd61f0000 && ((w3 >>> 5) & 31) === rd) {
        const imm = sext((((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3), 21);
        const target = (addr - (addr % 4096)) + imm * 4096 + (((w2 >>> 10) & 0xfff) << (((w2 >>> 22) & 1) ? 12 : 0));
        if (target !== addr) { addr = target; continue; }
      }
    }
    break;
  }
  return addr;
}

export function functionAt(img, addr) {
  buildFunctions(img);
  const off = addr - img.base, a = img._funcStarts;
  let lo = 0, hi = a.length - 1, best = -1;
  while (lo <= hi) { const m = (lo + hi) >> 1; if (a[m] <= off) { best = m; lo = m + 1; } else hi = m - 1; }
  return best < 0 ? null : img.functions[best];
}

// Build function-level call edges once: Map(funcOff -> Set(calleeFuncOff)) and reverse.
export function buildCallGraph(img) {
  if (img._graph) return img._graph;
  buildFunctions(img);
  const fwd = new Map(), rev = new Map();
  const add = (m, k, v) => { (m.get(k) || m.set(k, new Set()).get(k)).add(v); };
  for (const [siteOff, tgtOff] of img._callEdges) {
    const from = functionAt(img, img.base + siteOff), to = functionAt(img, img.base + tgtOff);
    if (!from || !to || from.off === to.off) continue;
    add(fwd, from.off, to.off); add(rev, to.off, from.off);
  }
  return (img._graph = { fwd, rev });
}

// Find Switch IPC service names in rodata (fsp-srv, set:sys, nifm:u, …) and the
// code that references each — the services a module registers or connects to.
export function findServices(img) {
  const segs = ["rodata", "data"].map((n) => img.segments.find((s) => s.name === n)).filter(Boolean);
  const strs = [];
  for (const s of segs) for (const _s of extractStrings(img.data.subarray(s.start, s.start + s.size), img.base + s.start, 2, 2e5)) strs.push(_s);
  const seen = new Map(); // name -> addr (first)
  for (const s of strs) if (isServiceName(s.text) && !seen.has(s.text)) seen.set(s.text, s.addr);
  const addrs = [...seen.values()];
  const refs = addrs.length ? findXrefs(img, addrs, 5000) : [];
  const byAddr = new Map();
  for (const r of refs) (byAddr.get(r.target) || byAddr.set(r.target, []).get(r.target)).push(r);
  return [...seen.entries()].map(([name, addr]) => ({ name, addr, refs: byAddr.get(addr) || [] }))
    .sort((a, b) => b.refs.length - a.refs.length || a.name.localeCompare(b.name));
}

// Parse a main.npdm (program metadata). Returns the program id, the authoritative
// service access list (which services the module may host vs connect to), and the
// kernel-capability syscall allowlist. This is ground truth, unlike reference scans.
export function parseNpdm(buf) {
  if (buf.toString("latin1", 0, 4) !== "META") throw new Error("not an NPDM (no META magic)");
  const flags = buf[0x0c];
  const out = {
    name: buf.toString("latin1", 0x20, 0x30).replace(/\0+$/, ""),
    is64Bit: !!(flags & 1), mainThreadPriority: buf[0x0e], mainThreadCore: buf[0x0f],
    services: [], allowedSyscalls: [],
  };
  const aci = buf.readUInt32LE(0x70);
  if (buf.toString("latin1", aci, aci + 4) !== "ACI0") throw new Error("NPDM missing ACI0");
  out.programId = "0x" + buf.readBigUInt64LE(aci + 0x10).toString(16).padStart(16, "0");
  // ServiceAccessControl: entries of [control byte][name]. bit7 = may host; low 3 bits = len-1.
  let o = aci + buf.readUInt32LE(aci + 0x28), end = o + buf.readUInt32LE(aci + 0x2c);
  while (o < end) {
    const c = buf[o++], len = (c & 7) + 1;
    if (o + len > end) break;
    out.services.push({ name: buf.toString("latin1", o, o + len), host: !!(c & 0x80) });
    o += len;
  }
  // KernelAccessControl: decode SyscallMask descriptors into allowed syscall numbers.
  let k = aci + buf.readUInt32LE(aci + 0x30), kend = k + buf.readUInt32LE(aci + 0x34);
  for (; k + 4 <= kend; k += 4) {
    const desc = buf.readUInt32LE(k);
    if ((desc & 0x1f) === 0x0f) { // SyscallMask: marker 0b01111
      const index = (desc >>> 29) & 7, mask = (desc >>> 5) & 0xffffff;
      for (let i = 0; i < 24; i++) if (mask & (1 << i)) out.allowedSyscalls.push(index * 24 + i);
    }
  }
  out.allowedSyscalls.sort((a, b) => a - b);
  return out;
}

// Name functions from diagnostic strings: trace/assert messages often embed the
// C++ qualified name of the function that logs them, e.g. "RoModule::RelocateRel
// is called". We extract Class::method tokens and, when exactly one unnamed
// function references that string, name it.
function methodLike(qualified) {
  const last = qualified.split("::").pop();
  if (/^k[A-Z]/.test(last)) return false;       // kConstant enum member
  if (/^[A-Z0-9_]{2,}$/.test(last)) return false; // ALL_CAPS enum/macro
  if (last.length < 2 || /\d{3,}/.test(qualified)) return false;
  return true;
}

export function scanNameStrings(img) {
  const segs = ["rodata", "data"].map((n) => img.segments.find((s) => s.name === n)).filter(Boolean);
  const byAddr = new Map(); // string addr -> qualified name
  for (const s of segs) for (const st of extractStrings(img.data.subarray(s.start, s.start + s.size), img.base + s.start, 4, 2e5)) {
    const m = st.text.match(/\b((?:[A-Za-z_]\w*::)+[A-Za-z_]\w*)\b/);
    if (m && !/^(std|__gnu|_GLOBAL)/.test(m[1]) && methodLike(m[1]) && !byAddr.has(st.addr)) byAddr.set(st.addr, m[1]);
  }
  if (!byAddr.size) return [];
  const refs = findXrefs(img, [...byAddr.keys()], 10000);
  // group refs by the function that contains them
  const perString = new Map(); // string addr -> Set(funcOff)
  for (const r of refs) { const f = functionAt(img, r.from); if (!f) continue; (perString.get(r.target) || perString.set(r.target, new Set()).get(r.target)).add(f.off); }
  const out = [];
  for (const [addr, name] of byAddr) {
    const fns = perString.get(addr);
    if (fns && fns.size === 1) out.push({ addr, name, funcOff: [...fns][0] });
  }
  return out;
}

export function scanSyscalls(img) {
  const text = parseDynamic(img).text, d = img.data, dv = new DataView(d.buffer, d.byteOffset);
  const sites = [];
  for (let o = text.start; o + 4 <= text.start + text.size; o += 4) {
    const w = dv.getUint32(o, true);
    if (((w & 0xffe0001f) >>> 0) === 0xd4000001) sites.push({ addr: img.base + o, num: (w >>> 5) & 0xffff });
  }
  return sites;
}

// ---------- C++ RTTI / vtable recovery ----------

// Recover class names from Itanium RTTI: type_info name strings in rodata, their
// type_info objects, and the vtables that point at them (giving virtual methods).
export function scanRtti(img) {
  const d = img.data, dv = new DataView(d.buffer, d.byteOffset);
  const text = parseDynamic(img).text;
  const inText = (o) => o >= text.start && o < text.start + text.size;
  // 1. candidate mangled type names in rodata/data.
  const nameOff = new Map(); // image-offset -> mangled text
  for (const sn of ["rodata", "data"]) {
    const s = img.segments.find((x) => x.name === sn);
    if (!s) continue;
    for (const st of extractStrings(d.subarray(s.start, s.start + s.size), s.start, 2, 2e5)) {
      if (/^(N[0-9]|[0-9]{1,3}[A-Za-z_]|St[0-9]|[PK]+[0-9N])/.test(st.text) && st.text.length < 120) nameOff.set(st.addr, st.text);
    }
  }
  if (!nameOff.size) return [];
  // 2. demangle in one batch (c++filt -t).
  const names = [...nameOff.values()];
  const r = spawnSync("c++filt", ["-t"], { input: names.join("\n"), encoding: "utf8", maxBuffer: 64 << 20 });
  if (r.error?.code === "ENOENT") warnOnce("cxxfilt", "c++filt not found on PATH — RTTI class names will stay mangled. Install binutils/LLVM to demangle.");
  const demangled = new Map();
  if (r.status === 0 && r.stdout) { const out = r.stdout.split("\n"); names.forEach((m, i) => { if (out[i] && out[i] !== m) demangled.set(m, out[i]); }); }
  // 3. relocations: find type_info (a struct whose +8 slot points to a name) and
  //    vtables (whose -8 slot points to a type_info).
  const relocs = getRelocations(img);           // loc -> target (image offsets)
  const typeInfoAt = new Map();                  // typeInfoOff -> nameOff
  for (const [loc, tgt] of relocs) if (nameOff.has(tgt) && loc >= 8) typeInfoAt.set(loc - 8, tgt);
  const classes = new Map(); // nameOff -> {mangled, name, typeInfo, vtables:[]}
  for (const [tiOff, nOff] of typeInfoAt) {
    const mangled = nameOff.get(nOff);
    classes.set(nOff, { mangled, name: demangled.get(mangled) || mangled, typeInfo: img.base + tiOff, vtables: [] });
  }
  const vtableBoundary = new Set([...typeInfoAt.keys()].map((ti) => ti + 8)); // where another vtable's -8 slot sits
  for (const [loc, tgt] of relocs) {
    if (!typeInfoAt.has(tgt)) continue;          // loc's slot points at a type_info -> loc+8 is a vtable
    const vtOff = loc + 8;
    let n = 0;
    for (let o = vtOff; relocs.has(o) && inText(relocs.get(o)) && n < 400; o += 8) {
      if (n > 0 && vtableBoundary.has(o - 8)) break; // next class's type_info slot -> stop
      n++;
    }
    if (n) classes.get(typeInfoAt.get(tgt)).vtables.push({ off: vtOff, addr: img.base + vtOff, methods: n });
  }
  return [...classes.values()].filter((c) => demangled.has(c.mangled) || c.vtables.length)
    .sort((a, b) => (b.vtables[0]?.methods || 0) - (a.vtables[0]?.methods || 0));
}

// Gather everything recovered about a module into addr -> {name, kind, comment}.
// Combines function boundaries, saved labels/comments, and RTTI vtables.
export function collectSymbols(img, annotations) {
  const funcs = buildFunctions(img);
  const out = { functions: [], labels: [], comments: [] };
  const funcStart = new Set(funcs.map((f) => f.addr));
  for (const f of funcs) {
    const name = img.addrNames.get(f.addr) || `sub_${f.addr.toString(16)}`;
    out.functions.push({ addr: f.addr, name });
  }
  // RTTI vtables are data labels (not functions).
  const named = new Set();
  for (const c of scanRtti(img)) {
    const base = c.name.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
    for (const v of c.vtables) if (!named.has(v.addr)) { out.labels.push({ addr: v.addr, name: `vtable_${base}` }); named.add(v.addr); }
  }
  // Saved labels that fall outside functions become data labels too.
  if (annotations) {
    for (const [a, n] of Object.entries(annotations.labels)) { const addr = Number(a); if (!funcStart.has(addr) && !named.has(addr)) { out.labels.push({ addr, name: n }); named.add(addr); } }
    for (const [a, cm] of Object.entries(annotations.comments)) out.comments.push({ addr: Number(a), text: cm });
  }
  return out;
}

const sanitize = (n) => n.replace(/[^A-Za-z0-9_]/g, "_").replace(/^(\d)/, "_$1").slice(0, 200);

export function emitGhidra(sym, meta) {
  const q = (s) => JSON.stringify(s);
  const L = [`# Ghidra import script for ${meta.name} (${meta.programId || meta.buildId || ""})`,
    `# Generated by hex-viewer. Load the extract_image output as a flat binary at base ${hex(meta.base)} (AARCH64:LE:64), then: Script Manager -> run this file.`,
    `from ghidra.program.model.symbol import SourceType`, `fm = currentProgram.getFunctionManager()`,
    `def A(a): return toAddr(a)`, `def mk(a,n):`, `    addr=A(a)`,
    `    f=fm.getFunctionContaining(addr)`, `    if f is None:`,
    `        try: f=fm.createFunction(None, addr, None, SourceType.USER_DEFINED)`, `        except: f=None`,
    `    try:`, `        if f is not None and f.getEntryPoint()==addr: f.setName(n, SourceType.USER_DEFINED)`,
    `        else: createLabel(addr, n, True)`, `    except Exception as e: print('skip',n,e)`,
    `def lbl(a,n):`, `    try: createLabel(A(a), n, True)`, `    except Exception as e: print('skip',n,e)`,
    `def cmt(a,t):`, `    try: setEOLComment(A(a), t)`, `    except: pass`, ``];
  for (const f of sym.functions) L.push(`mk(${f.addr}, ${q(sanitize(f.name))})`);
  for (const l of sym.labels) L.push(`lbl(${l.addr}, ${q(sanitize(l.name))})`);
  for (const c of sym.comments) L.push(`cmt(${c.addr}, ${q(c.text)})`);
  L.push(`print("hex-viewer: ${sym.functions.length} functions, ${sym.labels.length} labels, ${sym.comments.length} comments")`);
  return L.join("\n") + "\n";
}

export function emitIda(sym, meta) {
  const q = (s) => JSON.stringify(s);
  const L = [`# IDAPython import script for ${meta.name} (${meta.programId || meta.buildId || ""})`,
    `# Load the extract_image output as a flat binary (ARM little-endian, 64-bit) at base ${hex(meta.base)}, then File -> Script file -> run this.`,
    `import idc, ida_funcs, idaapi`,
    `def mk(a,n):`, `    if ida_funcs.get_func(a) is None: ida_funcs.add_func(a)`, `    idc.set_name(a, n, idc.SN_NOWARN|idc.SN_FORCE)`,
    `def lbl(a,n): idc.set_name(a, n, idc.SN_NOWARN|idc.SN_FORCE)`,
    `def cmt(a,t): idc.set_cmt(a, t, 0)`, ``];
  for (const f of sym.functions) L.push(`mk(${f.addr}, ${q(sanitize(f.name))})`);
  for (const l of sym.labels) L.push(`lbl(${l.addr}, ${q(sanitize(l.name))})`);
  for (const c of sym.comments) L.push(`cmt(${c.addr}, ${q(c.text)})`);
  L.push(`print("hex-viewer: %d functions, %d labels, %d comments" % (${sym.functions.length}, ${sym.labels.length}, ${sym.comments.length}))`);
  return L.join("\n") + "\n";
}

// ---------- tool handlers (return {text, structuredContent}) ----------

function label(img, f) {
  const n = img.addrNames.get(f.addr);
  return n || `sub_${f.addr.toString(16)}`;
}

export function listFunctions(img, args) {
  const funcs = buildFunctions(img);
  const re = args.filter ? new RegExp(args.filter, "i") : null;
  let rows = funcs;
  if (args.min_size) rows = rows.filter((f) => f.size >= args.min_size);
  if (args.named_only) rows = rows.filter((f) => img.addrNames.has(f.addr));
  if (re) rows = rows.filter((f) => re.test(label(img, f)));
  const total = rows.length;
  rows = rows.slice(0, args.limit || 200);
  const text = `${funcs.length} functions recovered (${funcs.filter((f) => f.prologue).length} with clear prologues)` +
    (total !== funcs.length ? `; ${total} match` : "") + `\n` +
    rows.map((f) => `${f.addr.toString(16)}  ${hex(f.size).padStart(7)}  ${f.prologue ? " " : "~"} ${label(img, f)}`).join("\n");
  return { content: [{ type: "text", text }], structuredContent: { count: funcs.length, shown: rows.length } };
}

export function callGraphTool(img, args, resolveAddr) {
  const g = buildCallGraph(img);
  const start = resolveAddr(img, args);
  const f = functionAt(img, start);
  if (!f) throw new Error(`no function contains ${hex(start)}`);
  const dir = args.direction || "callees";
  const depth = Math.min(args.depth || 2, 6), maxNodes = 400;
  const lines = [];
  let nodes = 0;
  const walk = (off, which, d, prefix, seen) => {
    if (nodes >= maxNodes) return;
    const edges = [...((which === "callers" ? g.rev : g.fwd).get(off) || [])];
    for (let i = 0; i < edges.length; i++) {
      if (nodes >= maxNodes) { lines.push(prefix + "…(truncated)"); return; }
      const child = edges[i], fn = img.functions[img._funcStarts.indexOf(child)];
      const last = i === edges.length - 1, branch = prefix + (last ? "└─ " : "├─ ");
      const cyc = seen.has(child);
      lines.push(branch + label(img, fn) + ` (${hex(fn.addr)})` + (cyc ? " ↺" : ""));
      nodes++;
      if (d > 1 && !cyc) walk(child, which, d - 1, prefix + (last ? "   " : "│  "), new Set(seen).add(child));
    }
  };
  const header = `${label(img, f)} (${hex(f.addr)})  —  ${dir}, depth ${depth}`;
  if (dir === "both") { lines.push("callees:"); walk(f.off, "callees", depth, "  ", new Set([f.off])); lines.push("callers:"); walk(f.off, "callers", depth, "  ", new Set([f.off])); }
  else walk(f.off, dir, depth, "", new Set([f.off]));
  return { content: [{ type: "text", text: header + "\n" + (lines.join("\n") || "(no edges found)") }], structuredContent: { function: f.addr, nodes } };
}

export function npdmTool(buf, img) {
  const n = parseNpdm(buf);
  const hosts = n.services.filter((s) => s.host).map((s) => s.name);
  const uses = n.services.filter((s) => !s.host).map((s) => s.name);
  const lines = [
    `${n.name}  ${n.programId}  ${n.is64Bit ? "64-bit" : "32-bit"}  (main-thread prio ${n.mainThreadPriority}, core ${n.mainThreadCore})`,
    `hosts (${hosts.length}): ${hosts.join(" ") || "—"}`,
    `connects to (${uses.length}): ${uses.join(" ") || "—"}`,
    `allowed syscalls (${n.allowedSyscalls.length}): ${n.allowedSyscalls.map((s) => SVC_NAMES[s] || "0x" + s.toString(16)).join(", ")}`,
  ];
  // If given the matching module image, note how the linked svc wrappers relate to
  // the allowlist. The wrapper scan counts statically-linked wrappers, not calls
  // actually made, so wrappers outside the allowlist are typically just unused.
  if (img) {
    const present = new Set(scanSyscalls(img).map((s) => s.num));
    const allowed = new Set(n.allowedSyscalls);
    const extra = [...present].filter((s) => !allowed.has(s)).sort((a, b) => a - b);
    lines.push(`svc wrappers present: ${present.size} distinct; ${extra.length ? extra.length + " outside the allowlist (likely unused linked wrappers): " + extra.map((s) => SVC_NAMES[s] || "0x" + s.toString(16)).join(", ") : "all within the NPDM allowlist"}`);
  }
  return { content: [{ type: "text", text: lines.join("\n") }], structuredContent: { programId: n.programId, hosts, uses, allowedSyscalls: n.allowedSyscalls } };
}

export function findRttiTool(img, args) {
  const classes = scanRtti(img);
  const re = args.filter ? new RegExp(args.filter, "i") : null;
  const rows = (re ? classes.filter((c) => re.test(c.name)) : classes).slice(0, args.limit || 200);
  const text = classes.length
    ? `${classes.length} RTTI classes (${classes.filter((c) => c.vtables.length).length} with vtables):\n` +
      rows.map((c) => {
        const vt = c.vtables[0];
        return `  ${vt ? vt.addr.toString(16) : "          "}  ${vt ? (vt.methods + " vm").padStart(6) : "      "}  ${c.name}`;
      }).join("\n")
    : "no C++ RTTI found (module may be built without RTTI)";
  return { content: [{ type: "text", text }], structuredContent: { classes: rows.map((c) => ({ name: c.name, vtable: c.vtables[0]?.addr, methods: c.vtables[0]?.methods || 0 })) } };
}

export function findServicesTool(img, args) {
  const svcs = findServices(img);
  const re = args.filter ? new RegExp(args.filter, "i") : null;
  const rows = re ? svcs.filter((s) => re.test(s.name)) : svcs;
  const text = rows.length
    ? `${svcs.length} IPC services referenced:\n` + rows.map((s) =>
        `  ${s.name.padEnd(10)} str@${s.addr.toString(16)}  ${s.refs.length} ref${s.refs.length === 1 ? "" : "s"}` +
        (s.refs.length ? `  e.g. ${s.refs.slice(0, 3).map((r) => r.func || r.from.toString(16)).join(", ")}` : "")).join("\n")
    : "no known IPC service names found in rodata";
  return { content: [{ type: "text", text }], structuredContent: { services: rows.map((s) => ({ name: s.name, addr: s.addr, refs: s.refs.length })) } };
}

export function scanSyscallsTool(img, args) {
  const sites = scanSyscalls(img);
  const byNum = new Map();
  for (const s of sites) (byNum.get(s.num) || byNum.set(s.num, []).get(s.num)).push(s.addr);
  const summary = [...byNum.entries()].sort((a, b) => a[0] - b[0]).map(([n, addrs]) =>
    `  svc 0x${n.toString(16).padStart(2, "0")}  ${(SVC_NAMES[n] || "Unknown").padEnd(28)} ${addrs.length}×  e.g. ${addrs.slice(0, 3).map((a) => a.toString(16)).join(" ")}`);
  const text = sites.length
    ? `${sites.length} svc instructions, ${byNum.size} distinct syscalls:\n${summary.join("\n")}`
    : "no svc instructions found (module may reach the kernel only through shared wrappers)";
  return { content: [{ type: "text", text }], structuredContent: { total: sites.length, distinct: byNum.size } };
}

export const RE_TOOLS = [
  { name: "list_functions", description: "Recover and list function boundaries in a (possibly stripped) module, from call targets, relocated code pointers, init/fini arrays and prologue scanning. Columns: address, size, prologue marker (~ = inferred), name. Essential for navigating stripped Switch sysmodules.",
    inputSchema: { type: "object", properties: { path: { type: "string" }, filter: { type: "string", description: "Regex on the function name/label." }, named_only: { type: "boolean", description: "Only functions with a symbol or saved label." }, min_size: { type: "integer", description: "Minimum size in bytes." }, limit: { type: "integer", default: 200 }, base: { type: "string" } }, required: ["path"] } },
  { name: "call_graph", description: "Show the call graph around a function (by address or symbol/label). direction: callees (what it calls), callers (what calls it), or both. Depth-limited tree; ↺ marks recursion.",
    inputSchema: { type: "object", properties: { path: { type: "string" }, address: { type: "string" }, symbol: { type: "string" }, direction: { type: "string", enum: ["callees", "callers", "both"], default: "callees" }, depth: { type: "integer", default: 2 }, base: { type: "string" } }, required: ["path"] } },
  { name: "scan_syscalls", description: "Find every `svc #n` instruction and decode the Horizon kernel syscall (SendSyncRequest, ConnectToNamedPort, QueryMemory, …), grouped by syscall with example addresses. Reveals what kernel services a module uses.",
    inputSchema: { type: "object", properties: { path: { type: "string" }, base: { type: "string" } }, required: ["path"] } },
  { name: "find_services", description: "Find Switch IPC service names in rodata (fsp-srv, set:sys, nifm:u, ldr:ro, …) and the functions that reference each one, sorted by reference count. Shows which system services a module registers or talks to.",
    inputSchema: { type: "object", properties: { path: { type: "string" }, filter: { type: "string", description: "Regex on the service name." }, base: { type: "string" } }, required: ["path"] } },
  { name: "find_rtti", description: "Recover C++ class names from Itanium RTTI: demangles type_info name strings and locates each class's vtable and its number of virtual methods. The richest source of names in a stripped C++ module (nn::fs::RomFsFileSystem, DisplayPort::Connector, …).",
    inputSchema: { type: "object", properties: { path: { type: "string" }, filter: { type: "string", description: "Regex on the demangled class name." }, limit: { type: "integer", default: 200 }, base: { type: "string" } }, required: ["path"] } },
];
for (const t of RE_TOOLS) t.annotations = { readOnlyHint: true };
