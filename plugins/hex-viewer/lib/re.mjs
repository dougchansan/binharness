// Reverse-engineering layer for stripped, statically-linked Switch modules:
// MOD0/.dynamic parsing, relocation application (RELR + RELA relative),
// function-boundary recovery, call graph, and syscall scanning.
// Pure analysis over an image produced by bintools.openImage().
import { hex, segmentAt } from "./bintools.mjs";

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

export function scanSyscalls(img) {
  const text = parseDynamic(img).text, d = img.data, dv = new DataView(d.buffer, d.byteOffset);
  const sites = [];
  for (let o = text.start; o + 4 <= text.start + text.size; o += 4) {
    const w = dv.getUint32(o, true);
    if (((w & 0xffe0001f) >>> 0) === 0xd4000001) sites.push({ addr: img.base + o, num: (w >>> 5) & 0xffff });
  }
  return sites;
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
];
for (const t of RE_TOOLS) t.annotations = { readOnlyHint: true };
