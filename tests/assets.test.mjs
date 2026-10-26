// node --test tests/assets.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import zlib from "node:zlib";
import { decompress, parseByml } from "../plugins/hex-viewer/lib/assets.mjs";

function bymlFixture() { // {a: 42}, little-endian
  const b = Buffer.alloc(0x2c);
  b.write("YB", 0, "latin1"); b.writeUInt16LE(3, 2); b.writeUInt32LE(0x10, 4); b.writeUInt32LE(0, 8); b.writeUInt32LE(0x20, 12);
  b.writeUInt32LE((0xc2 | (1 << 8)) >>> 0, 0x10); b.writeUInt32LE(0x0c, 0x14); b.writeUInt32LE(0x0e, 0x18); b.write("a\0", 0x1c, "latin1");
  b.writeUInt32LE((0xc1 | (1 << 8)) >>> 0, 0x20); b.writeUInt32LE((0 | (0xd1 << 24)) >>> 0, 0x24); b.writeUInt32LE(42, 0x28);
  return b;
}

test("decompress zstd / gzip / zlib round-trip", () => {
  const src = Buffer.from("binharness asset payload ".repeat(40));
  for (const [name, c] of [["Zstandard", zlib.zstdCompressSync(src)], ["gzip", zlib.gzipSync(src)], ["zlib", zlib.deflateSync(src)]]) {
    const r = decompress(c);
    assert.equal(r.format, name);
    assert.ok(r.data.equals(src));
  }
});

test("decompress Yaz0 (all-literal)", () => {
  const payload = Buffer.from("YAZ0TEST");
  const y = Buffer.concat([Buffer.from("Yaz0"), (() => { const h = Buffer.alloc(12); h.writeUInt32BE(payload.length, 0); return h; })(), Buffer.from([0xff]), payload]);
  assert.ok(decompress(y).data.equals(payload));
});

test("parseByml -> JSON", () => {
  const r = parseByml(bymlFixture());
  assert.equal(r.version, 3);
  assert.deepEqual(r.root, { a: 42 });
});

test("decompress rejects unknown input", () => {
  assert.throws(() => decompress(Buffer.from("not compressed at all")));
});
