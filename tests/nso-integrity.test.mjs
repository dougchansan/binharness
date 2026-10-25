// Synthetic NSO integrity and optional beetool differential tests.
// No game/firmware files, cryptographic keys, or proprietary SDK input.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { openImage, callTool } from "../plugins/hex-viewer/lib/bintools.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "binharness-nso-test-"));
const file = path.join(dir, "fixture.nso");
before(() => execFileSync(process.execPath, [path.join(here, "make-fixture.mjs"), file]));
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

// Independently construct bytes expected from the test generator, without
// reusing any loader/decompression or hash-verification code.
function oracle() {
  const text = Buffer.alloc(0x1000);
  for (let i = 0; i < text.length; i += 4) text.writeUInt32LE(0xd503201f, i);
  text.writeUInt32LE((0x90000000 | (1 << 29)) >>> 0, 4);
  text.writeUInt32LE((0x91000000 | (0x100 << 10)) >>> 0, 8);
  text.writeUInt32LE((0x94000000 | (0x14 / 4)) >>> 0, 12);
  text.writeUInt32LE((0x94000000 | (0x30 / 4)) >>> 0, 16);
  text.writeUInt32LE((0xd4000001 | (0x0b << 5)) >>> 0, 0x20);
  text.writeUInt32LE(0xd65f03c0, 0x24);
  text.writeUInt32LE(0xd65f03c0, 0x40);
  const ro = Buffer.alloc(0x1000);
  const mod = "D:\\home\\fixture\\main.nss";
  ro.writeUInt32LE(mod.length, 4); ro.write(mod, 8, "latin1");
  ro.write("Hello Switch error %d\0", 0x100, "latin1");
  const names = ["nnMain", "_ZN2nn2os11SleepThreadENS_8TimeSpanE", "_ZN2nn2fs8MountRomEPKcPvm"];
  let off = 1;
  for (const n of names) { ro.write(n + "\0", 0x200 + off, "latin1"); off += n.length + 1; }
  let nm = 1;
  for (let i = 0; i < names.length; i++) {
    const o = 0x300 + 24 * (i + 1);
    ro.writeUInt32LE(nm, o); ro[o + 4] = 0x12;
    ro.writeUInt16LE(i === 2 ? 0 : 1, o + 6);
    ro.writeBigUInt64LE(BigInt(i === 1 ? 0x20 : 0), o + 8);
    ro.writeBigUInt64LE(4n, o + 16);
    nm += names[i].length + 1;
  }
  return [text, ro, Buffer.alloc(0x100, 0xab)];
}

test("independent byte oracle, enabled header digests, and verifier agree", () => {
  const header = fs.readFileSync(file);
  const img = openImage(file);
  assert.equal(header.readUInt32LE(0x0c) & 0x38, 0x38);
  const segments = oracle();
  for (let i = 0; i < 3; i++) {
    const mem = header.readUInt32LE(0x14 + i * 0x10), size = header.readUInt32LE(0x18 + i * 0x10);
    assert.ok(Buffer.from(img.data.subarray(mem, mem + size)).equals(segments[i]), "decoded segment " + i);
    assert.equal(header.subarray(0xa0 + i * 32, 0xc0 + i * 32).toString("hex"), sha(segments[i]));
  }
  const report = callTool("verify_nso", { path: file });
  assert.equal(report.structuredContent.valid, true);
  assert.equal(report.structuredContent.checked, 3);
  assert.match(report.content[0].text, /text: valid/);
});

test("hash mismatch warns and prevents default extraction; missing flag stays unverified", () => {
  const altered = Buffer.from(fs.readFileSync(file));
  altered[0xa0] ^= 0x40;
  const badFile = path.join(dir, "bad-digest.nso");
  fs.writeFileSync(badFile, altered);
  const report = callTool("verify_nso", { path: badFile });
  assert.equal(report.structuredContent.valid, false);
  assert.equal(report.structuredContent.mismatches, 1);
  assert.match(callTool("file_info", { path: badFile }).content[0].text, /text=mismatch/);
  const out = path.join(dir, "blocked.bin");
  assert.throws(() => callTool("extract_image", { path: badFile, out }), /hash mismatch/i);
  assert.equal(fs.existsSync(out), false);
  callTool("extract_image", { path: badFile, out, ignore_hash_mismatch: true });
  assert.equal(fs.existsSync(out), true);

  altered.writeUInt32LE(altered.readUInt32LE(0x0c) & ~0x08, 0x0c);
  const noHashFile = path.join(dir, "text-unflagged.nso");
  fs.writeFileSync(noHashFile, altered);
  const absent = callTool("verify_nso", { path: noHashFile });
  assert.equal(absent.structuredContent.checked, 2);
  assert.equal(absent.structuredContent.segments[0].status, "not-present");
});

test("ZBIC flag rejects without configured helper, rather than attempting LZ4", () => {
  const bytes = Buffer.from(fs.readFileSync(file));
  bytes.writeUInt32LE(bytes.readUInt32LE(0x0c) | 0x80, 0x0c);
  const input = path.join(dir, "zbic-flagged.nso");
  fs.writeFileSync(input, bytes);
  const old = process.env.BINHARNESS_BEETOOL;
  delete process.env.BINHARNESS_BEETOOL;
  try { assert.throws(() => openImage(input), /BINHARNESS_BEETOOL/); }
  finally { if (old === undefined) delete process.env.BINHARNESS_BEETOOL; else process.env.BINHARNESS_BEETOOL = old; }
});

test("mocked ZBIC helper integration enforces output metadata and hash matching", { skip: process.platform === "win32" }, () => {
  const bytes = Buffer.from(fs.readFileSync(file));
  bytes.writeUInt32LE(bytes.readUInt32LE(0x0c) | 0x80, 0x0c);
  const input = path.join(dir, "zbic-mock.nso");
  fs.writeFileSync(input, bytes);
  const header = Buffer.from(bytes.subarray(0, 0x100)), segments = oracle();
  header.writeUInt32LE(header.readUInt32LE(0x0c) & 0x78, 0x0c);
  let offset = 0x100;
  for (let i = 0; i < 3; i++) {
    header.writeUInt32LE(offset, 0x10 + i * 0x10);
    header.writeUInt32LE(segments[i].length, 0x60 + i * 4);
    offset += segments[i].length;
  }
  const decoded = path.join(dir, "decoded-oracle.nso");
  fs.writeFileSync(decoded, Buffer.concat([header, ...segments]));
  const helper = path.join(dir, "fake-hactool");
  fs.writeFileSync(helper, "#!" + process.execPath + "\n" +
    "const fs=require('fs');const a=process.argv.find(v=>v.startsWith('--uncompressed='));" +
    "if(!a||!process.argv.includes('nso0'))process.exit(2);" +
    "fs.copyFileSync(process.env.BINHARNESS_ORACLE,a.slice('--uncompressed='.length));\n", { mode: 0o755 });
  const oldHelper = process.env.BINHARNESS_BEETOOL, oldOracle = process.env.BINHARNESS_ORACLE;
  process.env.BINHARNESS_BEETOOL = helper;
  process.env.BINHARNESS_ORACLE = decoded;
  try {
    const img = openImage(input);
    assert.equal(img.compression, "zbic (external beetool)");
    assert.equal(img.hashes.every((h) => h.status === "valid"), true);
    const wrong = Buffer.from(fs.readFileSync(decoded));
    wrong.writeUInt32LE(wrong.readUInt32LE(0x14) + 1, 0x14);
    const wrongFile = path.join(dir, "bad-decoder-output.nso");
    fs.writeFileSync(wrongFile, wrong);
    process.env.BINHARNESS_ORACLE = wrongFile;
    const input2 = path.join(dir, "zbic-mock2.nso");
    fs.copyFileSync(input, input2);
    assert.throws(() => openImage(input2), /changed NSO metadata/);
  } finally {
    if (oldHelper === undefined) delete process.env.BINHARNESS_BEETOOL; else process.env.BINHARNESS_BEETOOL = oldHelper;
    if (oldOracle === undefined) delete process.env.BINHARNESS_ORACLE; else process.env.BINHARNESS_ORACLE = oldOracle;
  }
});

test("optional independent beetool differential on the synthetic LZ4 fixture", { skip: !process.env.BINHARNESS_BEETOOL || process.platform === "win32" }, () => {
  const out = path.join(dir, "beetool-independent.nso");
  const env = { ...process.env, HOME: dir, USERPROFILE: dir, XDG_CONFIG_HOME: dir };
  const r = spawnSync(process.env.BINHARNESS_BEETOOL, ["-t", "nso0", "--uncompressed=" + out, file], { env, encoding: "utf8", timeout: 120000 });
  assert.equal(r.status, 0, r.error?.message || r.stderr?.slice(0, 500));
  const output = fs.readFileSync(out), img = openImage(file);
  for (let i = 0; i < 3; i++) {
    const fileOff = output.readUInt32LE(0x10 + i * 0x10);
    const memOff = output.readUInt32LE(0x14 + i * 0x10), size = output.readUInt32LE(0x18 + i * 0x10);
    assert.ok(output.subarray(fileOff, fileOff + size).equals(Buffer.from(img.data.subarray(memOff, memOff + size))));
  }
});
