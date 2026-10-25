import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { auditEntry, auditArchive, auditPackage, auditTracked, auditHistory, parseTar, validatePolicy } from "../scripts/audit-dist.mjs";

const policy = (files = ["package.json", "harness/demo.mjs"]) => ({
  version: 1, maxTextBytes: 1024 * 1024, maxArchiveBytes: 4 * 1024 * 1024, maxArchiveEntries: 64,
  gitFiles: [...files], retiredGitFiles: [], packageFiles: [...files], binaryAssets: {},
});

function tar(entries) {
  const parts = [];
  for (const { name, data = Buffer.from("sample\n"), type = "0" } of entries) {
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, "utf8");
    header.write("0000644\0", 100, 8, "ascii");
    header.write(data.length.toString(8).padStart(11, "0") + "\0", 124, 12, "ascii");
    header.fill(32, 148, 156);
    header.write(type, 156, 1, "ascii");
    header.write("ustar\0", 257, 6, "ascii");
    header.write(header.reduce((a, b) => a + b, 0).toString(8).padStart(6, "0") + "\0 ", 148, 8, "ascii");
    parts.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

function temp(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "binharness-audit-test-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function git(dir, args) {
  const result = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
  assert.equal(result.status, 0, `git ${args[0]} failed: ${result.error?.code || result.stderr}`);
  return result.stdout;
}

function packageRoot(t) {
  const dir = temp(t);
  fs.mkdirSync(path.join(dir, "harness"));
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "binharness-audit-synthetic", version: "1.0.0", files: ["harness"], scripts: { prepack: "node -e \"process.exit(99)\"" } }));
  fs.writeFileSync(path.join(dir, "harness/demo.mjs"), "export const synthetic = true;\n");
  return dir;
}

test("source inventory accepts ordinary UTF-8 and rejects embedded binary or literal key material", () => {
  const p = validatePolicy(policy());
  assert.equal(auditEntry("harness/demo.mjs", Buffer.from("// synthetic source\n"), p), null);
  assert.match(auditEntry("harness/demo.mjs", Buffer.from("NSO0sample"), p), /signature/);
  assert.match(auditEntry("harness/demo.mjs", Buffer.from([0xc0, 0xff]), p), /UTF-8/);
  assert.match(auditEntry("harness/demo.mjs", Buffer.from("text\0bytes"), p), /control/);
  const key = Buffer.from("master_key_00 = " + "ab".repeat(16));
  const finding = auditEntry("harness/demo.mjs", key, p);
  assert.match(finding, /key material/);
  assert.ok(!finding.includes("ab".repeat(16)));
  assert.match(auditEntry("harness/unreviewed.mjs", Buffer.from("// new\n"), p), /inventory/);
  assert.match(auditEntry("../harness/demo.mjs", Buffer.from("// new\n"), p), /unsafe/);
});

test("binary exception pins the exact Git asset and never licenses a package copy", () => {
  const image = Buffer.from([0xff, 0xd8, 0xff, 0xd9]);
  const p = policy();
  p.gitFiles.push("docs/screenshot.jpg");
  p.binaryAssets["docs/screenshot.jpg"] = { sha256: createHash("sha256").update(image).digest("hex") };
  validatePolicy(p);
  assert.equal(auditEntry("docs/screenshot.jpg", image, p), null);
  assert.match(auditEntry("docs/screenshot.jpg", Buffer.concat([image, Buffer.from([0])]), p), /digest/);
  assert.match(auditEntry("docs/screenshot.jpg", image, p, "package"), /inventory/);
  p.gitFiles = p.gitFiles.filter((name) => name !== "docs/screenshot.jpg");
  p.retiredGitFiles.push("docs/screenshot.jpg");
  validatePolicy(p);
  assert.equal(auditEntry("docs/screenshot.jpg", image, p, "history"), null);
  assert.match(auditEntry("docs/screenshot.jpg", image, p), /inventory/);
  assert.match(auditEntry("docs/screenshot.jpg", Buffer.concat([image, Buffer.from([0])]), p, "history"), /digest/);
});

test("actual archive contents must exactly match the package inventory", () => {
  const p = policy(["README.md"]);
  const result = auditArchive(gzipSync(tar([{ name: "package/README.md" }])), p);
  assert.equal(result.files, 1);
  assert.deepEqual(result.failures, []);
  const missing = auditArchive(gzipSync(tar([{ name: "package/unreviewed.txt" }])), p);
  assert.equal(missing.failures.length, 2);
});

test("tar rejects traversal, duplicates, links, special headers, corruption and truncation", () => {
  const p = policy();
  for (const name of ["package/../escape", "/package/file", "package/./file", "package//file", "package\\file"]) {
    assert.throws(() => parseTar(tar([{ name }]), p), /unsafe/);
  }
  assert.throws(() => parseTar(tar([{ name: "package/a" }, { name: "package/a" }]), p), /duplicate/);
  for (const type of ["1", "2", "5", "x", "g", "L"]) assert.throws(() => parseTar(tar([{ name: "package/a", type }]), p), /nonregular/);
  const bad = tar([{ name: "package/a" }]); bad[0] ^= 1;
  assert.throws(() => parseTar(bad, p), /checksum/);
  assert.throws(() => parseTar(tar([{ name: "package/a" }]).subarray(0, 1024), p), /end markers/);
  assert.throws(() => parseTar(tar([{ name: "package/a" }]).subarray(0, 700), p), /truncated/);
  const trail = tar([{ name: "package/a" }]); trail[trail.length - 1] = 1;
  assert.throws(() => parseTar(trail, p), /trailing/);
  assert.throws(() => auditArchive(gzipSync(tar([{ name: "package/a" }])).subarray(0, 20), p), /gzip/);
});

test("npm pack integration ignores lifecycle scripts and catches included untracked inputs", (t) => {
  const dir = packageRoot(t), p = policy();
  assert.deepEqual(auditPackage(dir, p).failures, []);
  fs.writeFileSync(path.join(dir, "harness/accidental.nso"), "NSO0synthetic");
  const result = auditPackage(dir, p);
  assert.ok(result.failures.some((f) => f.path === "harness/accidental.nso"));
});

test("internal packing produces an actual tarball despite an inherited npm dry-run", (t) => {
  const dir = packageRoot(t), p = policy();
  const previous = process.env.npm_config_dry_run;
  try {
    process.env.npm_config_dry_run = "true";
    const result = auditPackage(dir, p);
    assert.equal(result.files, 2);
    assert.match(result.sha256, /^[0-9a-f]{64}$/);
    assert.deepEqual(result.failures, []);
  } finally {
    if (previous === undefined) delete process.env.npm_config_dry_run;
    else process.env.npm_config_dry_run = previous;
  }
});

test("package source symlinks fail before npm can silently omit them", (t) => {
  const dir = packageRoot(t);
  fs.renameSync(path.join(dir, "harness/demo.mjs"), path.join(dir, "harness/target.mjs"));
  fs.symlinkSync("target.mjs", path.join(dir, "harness/demo.mjs"));
  assert.ok(auditPackage(dir, policy()).failures.some((f) => /symlink/.test(f.rule)));
});

test("Git audit checks staged bytes even when worktree bytes are subsequently cleaned", (t) => {
  const dir = temp(t), p = policy(["README.md"]);
  git(dir, ["init", "--quiet"]);
  fs.writeFileSync(path.join(dir, "README.md"), "NSO0synthetic");
  git(dir, ["add", "README.md"]);
  fs.writeFileSync(path.join(dir, "README.md"), "# Clean working tree text\n");
  const result = auditTracked(dir, p);
  assert.ok(result.failures.some((f) => f.scope === "index" && /signature/.test(f.rule)));
  assert.ok(!result.failures.some((f) => f.scope === "worktree"));
});

test("reviewed retired paths allow source renames and deletions only in history", (t) => {
  const dir = temp(t), p = policy(["README.md"]);
  git(dir, ["init", "--quiet"]);
  fs.writeFileSync(path.join(dir, "old.md"), "# Synthetic document\n");
  fs.writeFileSync(path.join(dir, "deleted.md"), "Retired synthetic example.\n");
  git(dir, ["add", "old.md", "deleted.md"]);
  const commit = ["-c", "user.name=Audit Test", "-c", "user.email=audit@example.invalid", "commit", "--quiet", "-m"];
  git(dir, [...commit, "synthetic source"]);
  git(dir, ["mv", "old.md", "README.md"]);
  git(dir, ["rm", "deleted.md"]);
  git(dir, [...commit, "rename and retire synthetic source"]);
  assert.deepEqual(auditTracked(dir, p).failures, []);
  assert.deepEqual(new Set(auditHistory(dir, p).failures.map((f) => f.path)), new Set(["old.md", "deleted.md"]));
  p.retiredGitFiles = ["old.md", "deleted.md"];
  validatePolicy(p);
  assert.deepEqual(auditTracked(dir, p).failures, []);
  assert.deepEqual(auditHistory(dir, p).failures, []);
  assert.match(auditEntry("old.md", Buffer.from("# Synthetic source\n"), p), /inventory/);
  assert.match(auditEntry("old.md", Buffer.from("NSO0synthetic"), p, "history"), /signature/);
  assert.match(auditEntry("old.md", Buffer.from("master_key_00 = " + "ab".repeat(16)), p, "history"), /key material/);
  p.retiredGitFiles.push("sample.nso");
  assert.match(auditEntry("sample.nso", Buffer.from("synthetic"), p, "history"), /filename/);
  p.retiredGitFiles.push("README.md");
  assert.throws(() => validatePolicy(p), /disjoint/);
});

test("history detects a removed binary and refuses shallow coverage", (t) => {
  const dir = temp(t), p = policy(["README.md"]);
  git(dir, ["init", "--quiet"]);
  fs.writeFileSync(path.join(dir, "README.md"), "NSO0synthetic");
  git(dir, ["add", "README.md"]);
  const commit = ["-c", "user.name=Audit Test", "-c", "user.email=audit@example.invalid", "commit", "--quiet", "-m"];
  git(dir, [...commit, "synthetic bad input"]);
  fs.writeFileSync(path.join(dir, "README.md"), "# Synthetic source\n");
  git(dir, ["add", "README.md"]);
  git(dir, [...commit, "remove synthetic input"]);
  const result = auditHistory(dir, p);
  assert.equal(result.commits, 2);
  assert.ok(result.failures.some((f) => /signature/.test(f.rule)));
  fs.writeFileSync(path.join(dir, ".git/shallow"), git(dir, ["rev-parse", "HEAD"]));
  assert.throws(() => auditHistory(dir, p), /full clone/);
});
