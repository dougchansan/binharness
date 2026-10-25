// node --test tests/tools.test.mjs   (regenerates the fixture, then checks every tool against it)
import { test, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(here, "fixture.nso");
const home = fs.mkdtempSync(path.join(os.tmpdir(), "binharness-test-"));
process.env.HOME = home; // annotations go to a throwaway ~/.binharness
const { callTool } = await import("../plugins/hex-viewer/lib/bintools.mjs");
const run = (name, args) => callTool(name, { path: fixture, ...args }).content[0].text;

before(() => execFileSync(process.execPath, [path.join(here, "make-fixture.mjs")]));

test("file_info parses NSO header and segments", () => {
  const t = run("file_info");
  assert.match(t, /Switch NSO executable/);
  assert.match(t, /text\s+0x7100000000 - 0x7100001000\s+r-x\s+0x1000\s+\(lz4\)/);
  assert.match(t, /module D:\\home\\fixture\\main\.nss/);
});
test("symbols are read and demangled", () => assert.match(run("list_symbols"), /nn::os::SleepThread\(nn::TimeSpan\)/));
test("disassembly annotates calls and string refs", () => {
  const t = run("disassemble", { symbol: "nnMain", count: 5 });
  assert.match(t, /add x0, x0, #0x100\s+; 0x7100001100 "Hello Switch error %d"/);
  assert.match(t, /bl 0x7100000020\s+; nn::os::SleepThread/);
});
test("find_xrefs finds the BL", () => assert.match(run("find_xrefs", { address: "0x7100000020" }), /710000000c\s+call\s+nnMain\+0xc/));
test("find_string_refs links string to code", () => assert.match(run("find_string_refs", { text: "switch error" }), /<- 7100000008\s+nnMain\+0x8/));
test("search_bytes with wildcards", () => assert.match(run("search_bytes", { pattern: "c0 03 ?? d6", segment: "text" }), /0x7100000024\n0x7100000040/));
test("decode_struct", () => assert.match(run("decode_struct", { address: "0x7100001000", layout: "u32 zero; u32 len" }), /len: 24 \(0x18\)/));
test("annotations persist and show in disassembly", () => {
  run("annotate", { address: "0x7100000040", label: "main_epilogue", comment: "returns" });
  assert.match(run("disassemble", { address: "0x7100000040", count: 1 }), /main_epilogue:\n\s+7100000040:\s+ret\s+\/\/ returns/);
});
test("compare_files", () => {
  const b = path.join(home, "b.nso"); const buf = fs.readFileSync(fixture); buf[5] ^= 0xff; fs.writeFileSync(b, buf);
  assert.match(callTool("compare_files", { path_a: fixture, path_b: b }).content[0].text, /0x5 \+1/);
});
test("harness runs a full tool loop against a mock API", async () => {
  const mock = spawn(process.execPath, [path.join(here, "mock-deepseek.mjs"), fixture]);
  const port = await new Promise((r) => mock.stdout.once("data", (d) => r(String(d).trim())));
  let stderr = ""; mock.stderr.on("data", (d) => (stderr += d));
  const outp = execFileSync(process.execPath, [path.join(here, "../harness/deepseek-bin.mjs"), "--base-url", `http://127.0.0.1:${port}`, "-p", "go", fixture], { env: { ...process.env, DEEPSEEK_API_KEY: "test-key" }, encoding: "utf8" });
  mock.kill("SIGTERM");
  await new Promise((r) => mock.once("exit", r));
  assert.match(outp, /used by nnMain/);
  assert.match(stderr, /MOCK OK \(3 requests\)/);
});

test("list_functions recovers nnMain and SleepThread", () => {
  const t = run("list_functions");
  assert.match(t, /functions recovered/);
  assert.match(t, /7100000000/); // nnMain
  assert.match(t, /7100000020/); // SleepThread (BL target + symbol)
});
test("call_graph shows nnMain -> SleepThread", () => {
  assert.match(run("call_graph", { symbol: "nnMain", direction: "callees" }), /SleepThread|7100000020/);
});
test("scan_syscalls decodes svc", () => {
  assert.match(run("scan_syscalls"), /svc 0x0b\s+SleepThread\s+1×/);
});

test("label_syscalls names svc wrappers and comments sites", () => {
  const t = run("label_syscalls");
  assert.match(t, /svcSleepThread/);
  // the saved label now shows up in disassembly of the wrapper
  assert.match(run("disassemble", { symbol: "svcSleepThread", count: 2 }), /svcSleepThread:/);
});

test("find_services runs (fixture has no service names)", () => {
  assert.match(run("find_services"), /no known IPC service names|IPC services referenced/);
});
test("label_services runs without error", () => {
  assert.match(run("label_services"), /services:/);
});

test("parseNpdm reads program id, SAC and syscall allowlist", async () => {
  const { parseNpdm } = await import("../plugins/hex-viewer/lib/re.mjs");
  const b = Buffer.alloc(0x80 + 0x60);
  b.write("META", 0, "latin1"); b[0x0c] = 1; b.write("testmod", 0x20, "latin1");
  b.writeUInt32LE(0x80, 0x70); b.writeUInt32LE(0x60, 0x74);
  const a = 0x80; b.write("ACI0", a, "latin1"); b.writeBigUInt64LE(0x0100000000000040n, a + 0x10);
  // ACI0 header runs to 0x38; put SAC data at a+0x40, KAC at a+0x50.
  b.writeUInt32LE(0x40, a + 0x28);                                 // sac off (rel to ACI0)
  let o = a + 0x40; b[o++] = 0x82; b.write("sm:", o, "latin1"); o += 3; b[o++] = 0x01; b.write("lm", o, "latin1"); o += 2;
  b.writeUInt32LE(o - (a + 0x40), a + 0x2c);                       // sac size
  b.writeUInt32LE(0x50, a + 0x30);                                 // kac off
  b.writeUInt32LE(0x0f | ((1 << 0x0b) << 5), a + 0x50);            // SyscallMask granting svc 0x0b
  b.writeUInt32LE(4, a + 0x34);                                   // kac size
  const n = parseNpdm(b);
  assert.equal(n.name, "testmod");
  assert.equal(n.programId, "0x0100000000000040");
  assert.deepEqual(n.services.find((s) => s.name === "sm:"), { name: "sm:", host: true });
  assert.equal(n.services.find((s) => s.name === "lm").host, false);
  assert.ok(n.allowedSyscalls.includes(0x0b));
});
test("find_rtti / label_rtti run on a non-RTTI module", () => {
  assert.match(run("find_rtti"), /no C\+\+ RTTI|RTTI classes/);
  assert.match(run("label_rtti"), /classes:/);
});

test("export_symbols writes Ghidra and IDA scripts", () => {
  const out = path.join(home, "export");
  const t = callTool("export_symbols", { path: fixture, out, format: "both" }).content[0].text;
  assert.match(t, /functions,.*labels,.*comments/);
  for (const suf of [".ghidra.py", ".ida.py"]) {
    const src = fs.readFileSync(out + suf, "utf8");
    assert.match(src, /nnMain|sub_7100000000/);
  }
});
