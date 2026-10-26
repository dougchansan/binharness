// NSO0 hashing and opt-in ZBIC interoperability; no Nintendo keys or third-party codec bundled.
// Layout: https://switchbrew.org/wiki/NSO0
// External decoder: https://github.com/alula/beetool (hactool-derived, ISC).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";

const MAX_OUTPUT = 512 * 1024 * 1024;
const INVARIANT_WORDS = [0x14, 0x18, 0x24, 0x28, 0x34, 0x38, 0x3c, 0x90, 0x94, 0x98, 0x9c];

export function verifyNsoHashes(header, image, segments) {
  const flags = header.readUInt32LE(0x0c);
  return segments.map((s, i) => {
    const expected = header.subarray(0xa0 + i * 32, 0xc0 + i * 32).toString("hex");
    const actual = crypto.createHash("sha256").update(
      Buffer.from(image.buffer, image.byteOffset + s.memOffset, s.size)
    ).digest("hex");
    const enabled = !!(flags & (1 << (i + 3)));
    return { name: s.name, bytes: s.size, enabled,
      status: !enabled ? "not-present" : expected === actual ? "valid" : "mismatch",
      expected: enabled ? expected : null, actual };
  });
}

export function expandZbicNso(original) {
  const helper = process.env.BINHARNESS_BEETOOL;
  if (!helper || !path.isAbsolute(helper)) {
    throw new Error("ZBIC-compressed NSO requires an absolute BINHARNESS_BEETOOL executable path; LZ4 remains built-in. See README.");
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "binharness-zbic-"));
  try {
    const input = path.join(dir, "input.nso");
    const output = path.join(dir, "uncompressed.nso");
    fs.writeFileSync(input, original, { mode: 0o600 });
    // Beetool's hactool inheritance may otherwise inspect ~/.switch/prod.keys.
    // Constrain its home/config search to a temporary empty directory.
    const env = { ...process.env, HOME: dir, USERPROFILE: dir, XDG_CONFIG_HOME: dir };
    const result = spawnSync(helper, ["-t", "nso0", "--uncompressed=" + output, input], {
      cwd: dir, env, timeout: 120000, encoding: "utf8", maxBuffer: 1024 * 1024,
    });
    if (result.error || result.status !== 0) {
      throw new Error("ZBIC beetool helper failed (" + (result.error?.code || "exit " + result.status) + ").");
    }
    const stat = fs.statSync(output);
    if (!stat.isFile() || stat.size < 0x100 || stat.size > MAX_OUTPUT) {
      throw new Error("ZBIC helper output is missing, invalid, or oversized.");
    }
    const decoded = fs.readFileSync(output);
    if (decoded.toString("latin1", 0, 4) !== "NSO0") throw new Error("ZBIC helper output is not NSO0.");
    const originalFlags = original.readUInt32LE(0x0c), flags = decoded.readUInt32LE(0x0c);
    if ((flags & 0x87) !== 0 || (flags & 0x78) !== (originalFlags & 0x78)) {
      throw new Error("ZBIC helper did not return an uncompressed NSO.");
    }
    for (const off of INVARIANT_WORDS) {
      if (decoded.readUInt32LE(off) !== original.readUInt32LE(off)) {
        throw new Error("ZBIC helper changed NSO metadata.");
      }
    }
    if (!decoded.subarray(0x40, 0x60).equals(original.subarray(0x40, 0x60)) ||
        !decoded.subarray(0xa0, 0x100).equals(original.subarray(0xa0, 0x100))) {
      throw new Error("ZBIC helper changed module ID or declared SHA-256 hashes.");
    }
    for (let i = 0; i < 3; i++) {
      const h = 0x10 + i * 0x10;
      const offset = decoded.readUInt32LE(h), size = decoded.readUInt32LE(h + 8);
      if (offset < 0x100 || offset + size > decoded.length ||
          decoded.readUInt32LE(0x60 + i * 4) !== size) {
        throw new Error("ZBIC helper returned an incomplete NSO segment.");
      }
    }
    return decoded;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
