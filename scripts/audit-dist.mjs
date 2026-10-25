#!/usr/bin/env node
// Mechanical distribution guard. It cannot establish authorship, permission, or
// the provenance of source text / encoded data. See PROVENANCE.md for that scope.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { gunzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const utf8 = new TextDecoder("utf-8", { fatal: true });
const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const fail = (message) => { throw new Error(message); };

export function safePath(name) {
  return typeof name === "string" && name.length > 0 &&
    !/[\\\x00-\x1f\x7f]/.test(name) && !/^[A-Za-z]:/.test(name) &&
    name.split("/").every((part) => part && part !== "." && part !== "..");
}

export function validatePolicy(policy) {
  if (policy?.version !== 1) fail("unsupported distribution policy version");
  for (const key of ["gitFiles", "retiredGitFiles", "packageFiles"]) {
    if (!Array.isArray(policy[key]) || (key !== "retiredGitFiles" && !policy[key].length) ||
        policy[key].some((p) => !safePath(p)) || new Set(policy[key]).size !== policy[key].length) {
      fail(`invalid ${key} inventory`);
    }
  }
  if (policy.retiredGitFiles.some((p) => policy.gitFiles.includes(p))) fail("current and retired Git inventories must be disjoint");
  if (policy.packageFiles.some((p) => !policy.gitFiles.includes(p))) fail("package inventory must be a subset of Git inventory");
  for (const key of ["maxTextBytes", "maxArchiveBytes", "maxArchiveEntries"]) {
    if (!Number.isSafeInteger(policy[key]) || policy[key] < 1) fail(`invalid ${key} limit`);
  }
  for (const [name, asset] of Object.entries(policy.binaryAssets || {})) {
    if ((!policy.gitFiles.includes(name) && !policy.retiredGitFiles.includes(name)) || policy.packageFiles.includes(name) ||
        !/^[a-f0-9]{64}$/.test(asset.sha256 || "")) fail("invalid Git-only binary asset exception");
  }
  return policy;
}

const forbiddenName = /(?:^|\/)(?:\.env(?:\..*)?|prod\.keys|title\.keys|console\.keys|fw-index\.json|FIRMWARE-(?:INDEX|SERVICES)\.md)$|\.(?:keys|nso|nro|nca|npdm|nsp|xci|rom|iso|gcm|dol|rel|bin|elf|zip|gz|tgz|7z|rar|zst|pem|p12)$/i;
const keyAssignment = /(?:["']?(?:master_key_[0-9a-f]{2}|titlekek_[0-9a-f]{2}|key_area_key_(?:application|ocean|system)_[0-9a-f]{2}|header_key|device_key|bis_key_[0-9a-f]{2}|title_key)["']?\s*[:=]\s*["']?[0-9a-f]{32,})|(?:^\s*[0-9a-f]{32}\s*=\s*[0-9a-f]{32}\s*$)|\bsk-[A-Za-z0-9]{24,}\b/im;

function binarySignature(data) {
  const has = (offset, value) => data.subarray(offset, offset + value.length).equals(Buffer.from(value, "latin1"));
  return [[0, "NSO0"], [0, "NRO0"], [0x10, "NRO0"], [0, "META"],
    [0, "PFS0"], [0, "HFS0"], [0x200, "NCA2"], [0x200, "NCA3"],
    [0, "\x7fELF"], [0, "MZ"], [0, "PK\x03\x04"], [0, "\x1f\x8b"],
    [0, "7z\xbc\xaf\x27\x1c"], [0, "Rar!"], [0, "\x28\xb5\x2f\xfd"],
    [0x18, "\x5d\x1c\x9e\xa3"], [0x1c, "\xc2\x33\x9f\x3d"]].some(([o, v]) => has(o, v));
}

export function auditEntry(name, data, policy, scope = "git") {
  if (!safePath(name)) return "unsafe path";
  if (forbiddenName.test(name)) return "dump, archive, credential, or generated-output filename";
  const inventory = scope === "package" ? policy.packageFiles :
    scope === "history" ? [...policy.gitFiles, ...policy.retiredGitFiles] : policy.gitFiles;
  if (!inventory.includes(name)) return "path absent from reviewed inventory";
  const asset = policy.binaryAssets?.[name];
  if (asset) {
    return !["git", "history"].includes(scope) || sha256(data) !== asset.sha256 ? "binary asset digest differs from inventory exception" : null;
  }
  if (data.length > policy.maxTextBytes) return "source file exceeds size limit";
  if (binarySignature(data)) return "executable, firmware, or archive signature in source file";
  let text;
  try { text = utf8.decode(data); } catch { return "source file is not valid UTF-8"; }
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text)) return "binary control bytes in source file";
  if (keyAssignment.test(text)) return "possible literal key material (value redacted)";
  return null;
}

function command(executable, args, cwd, binary = false) {
  const result = spawnSync(executable, args, { cwd, encoding: binary ? null : "utf8", maxBuffer: 32 * 1024 * 1024 });
  if (result.error || result.status !== 0) fail(`${path.basename(executable)} ${args[0]} failed (${result.error?.code || result.status}); command output withheld`);
  return result.stdout;
}

function requireRepo(root) {
  const top = command("git", ["rev-parse", "--show-toplevel"], root).trim();
  if (fs.realpathSync(top) !== fs.realpathSync(root)) fail("audit root is not the Git repository root");
}

function readRegular(root, name, maxBytes) {
  if (!safePath(name)) fail("unsafe source path");
  const parts = name.split("/");
  let current = root;
  for (let i = 0; i < parts.length; i++) {
    current = path.join(current, parts[i]);
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) fail("symlink in source path");
    if (i === parts.length - 1) {
      if (!stat.isFile()) fail("nonregular source file");
      if (stat.size > maxBytes) fail("source file exceeds read limit");
    } else if (!stat.isDirectory()) fail("non-directory source ancestor");
  }
  return fs.readFileSync(current);
}

function readBlob(root, oid, limit, cache) {
  if (!cache.has(oid)) {
    const size = Number(command("git", ["cat-file", "-s", oid], root).trim());
    if (!Number.isSafeInteger(size) || size < 0 || size > limit) fail("Git blob exceeds read limit");
    cache.set(oid, command("git", ["cat-file", "blob", oid], root, true));
  }
  return cache.get(oid);
}

function check(failures, scope, name, fn) {
  try {
    const problem = fn();
    if (problem) failures.push({ scope, path: name, rule: problem });
  } catch (error) {
    // Filesystem errors may include paths, but never print file contents or the
    // child command's stderr, which could repeat a credential in malformed JSON.
    failures.push({ scope, path: name, rule: error.code ? `file operation failed (${error.code})` : error.message });
  }
}

export function auditTracked(root, policy) {
  requireRepo(root);
  const failures = [], cache = new Map(), seen = new Set();
  const rows = command("git", ["ls-files", "--stage", "-z"], root).split("\0").filter(Boolean);
  for (const row of rows) {
    const tab = row.indexOf("\t"), name = row.slice(tab + 1);
    const [mode, oid, stage] = row.slice(0, tab).split(" ");
    seen.add(name);
    if (tab < 0 || stage !== "0" || !["100644", "100755"].includes(mode)) {
      failures.push({ scope: "index", path: name, rule: "unmerged or nonregular Git entry" });
      continue;
    }
    check(failures, "index", name, () => auditEntry(name, readBlob(root, oid, policy.maxArchiveBytes, cache), policy));
    check(failures, "worktree", name, () => auditEntry(name, readRegular(root, name, policy.maxArchiveBytes), policy));
  }
  for (const name of policy.gitFiles) if (!seen.has(name)) failures.push({ scope: "index", path: name, rule: "reviewed source file is not tracked" });
  return { files: seen.size, indexBlobs: cache.size, failures };
}

export function auditHistory(root, policy) {
  requireRepo(root);
  if (command("git", ["rev-parse", "--is-shallow-repository"], root).trim() !== "false") fail("history audit requires a full clone; fetch complete history first");
  const commits = command("git", ["rev-list", "--all", "HEAD"], root).trim().split("\n").filter(Boolean);
  const refs = command("git", ["for-each-ref", "--format=%(refname)"], root).trim().split("\n").filter(Boolean);
  const seen = new Set(), cache = new Map(), failures = [];
  for (const commit of commits) {
    const rows = command("git", ["ls-tree", "-r", "-z", commit], root).split("\0").filter(Boolean);
    for (const row of rows) {
      const tab = row.indexOf("\t"), name = row.slice(tab + 1);
      const [mode, type, oid] = row.slice(0, tab).split(" ");
      const id = `${mode}:${oid}:${name}`;
      if (seen.has(id)) continue;
      seen.add(id);
      if (tab < 0 || type !== "blob" || !["100644", "100755"].includes(mode)) {
        failures.push({ scope: "history", path: name, rule: "nonregular Git entry", commit });
        continue;
      }
      check(failures, "history", name, () => auditEntry(name, readBlob(root, oid, policy.maxArchiveBytes, cache), policy, "history"));
    }
  }
  return { commits: commits.length, refs: [...refs, "HEAD"], pathBlobPairs: seen.size, uniqueBlobs: cache.size, failures };
}

function tarString(bytes) {
  const zero = bytes.indexOf(0);
  const text = zero < 0 ? bytes : bytes.subarray(0, zero);
  if (zero >= 0 && bytes.subarray(zero).some((b) => b !== 0)) fail("nonzero bytes after tar string terminator");
  try { return utf8.decode(text); } catch { fail("invalid UTF-8 tar header"); }
}

function tarNumber(bytes) {
  // npm's ordinary USTAR output uses octal fields. Base-256 and special header
  // types are deliberately unsupported and rejected, rather than guessed at.
  const value = bytes.toString("ascii").replace(/\0.*$/, "").trim();
  if (!/^[0-7]+$/.test(value)) fail("invalid or unsupported tar numeric field");
  const n = Number.parseInt(value, 8);
  if (!Number.isSafeInteger(n)) fail("tar number exceeds safe range");
  return n;
}

export function parseTar(data, limits) {
  if (!data.length || data.length % 512 || data.length > limits.maxArchiveBytes) fail("truncated or oversized tar archive");
  const entries = [], seen = new Set();
  let offset = 0;
  while (offset + 512 <= data.length) {
    const header = data.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) {
      if (offset + 1024 > data.length || data.subarray(offset).some((b) => b !== 0)) fail("invalid tar end markers or trailing payload");
      return entries;
    }
    let checksum = 0;
    for (let i = 0; i < 512; i++) checksum += i >= 148 && i < 156 ? 32 : header[i];
    if (checksum !== tarNumber(header.subarray(148, 156))) fail("tar header checksum mismatch");
    const type = header[156];
    if (type !== 0 && type !== 48) fail("unsupported nonregular tar entry (links, directories, PAX and GNU extensions are rejected)");
    const magic = header.subarray(257, 263).toString("latin1");
    if (magic !== "ustar\0" && magic !== "ustar " && magic !== "\0".repeat(6)) fail("unsupported tar header format");
    const prefix = magic.startsWith("ustar") ? tarString(header.subarray(345, 500)) : "";
    const shortName = tarString(header.subarray(0, 100));
    const name = prefix ? `${prefix}/${shortName}` : shortName;
    if (!safePath(name) || !name.startsWith("package/")) fail("unsafe tar path or missing package/ prefix");
    if (seen.has(name)) fail("duplicate tar path");
    seen.add(name);
    if (entries.length >= limits.maxArchiveEntries) fail("too many archive entries");
    const size = tarNumber(header.subarray(124, 136));
    const start = offset + 512, padded = Math.ceil(size / 512) * 512;
    if (size > limits.maxArchiveBytes || start + padded > data.length) fail("truncated or oversized tar entry");
    if (data.subarray(start + size, start + padded).some((b) => b !== 0)) fail("nonzero tar padding");
    entries.push({ path: name.slice(8), data: data.subarray(start, start + size) });
    offset = start + padded;
  }
  fail("missing tar end markers");
}

export function auditArchive(archive, policy) {
  if (archive.length > policy.maxArchiveBytes) fail("compressed archive exceeds size limit");
  let raw;
  try { raw = gunzipSync(archive, { maxOutputLength: policy.maxArchiveBytes }); }
  catch { fail("invalid, truncated, or oversized gzip stream"); }
  const entries = parseTar(raw, policy), failures = [];
  for (const entry of entries) check(failures, "package", entry.path, () => auditEntry(entry.path, entry.data, policy, "package"));
  const names = new Set(entries.map((e) => e.path));
  for (const name of policy.packageFiles) if (!names.has(name)) failures.push({ scope: "package", path: name, rule: "required package file missing" });
  return { files: entries.length, bytes: entries.reduce((n, e) => n + e.data.length, 0), sha256: sha256(archive), failures };
}

export function auditPackage(root, policy) {
  const failures = [];
  // Check known package sources too: npm may silently omit a symlink.
  for (const name of policy.packageFiles) check(failures, "package-source", name, () => auditEntry(name, readRegular(root, name, policy.maxArchiveBytes), policy, "package"));
  if (failures.length) return { files: 0, failures };
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "binharness-audit-"));
  try {
    // Always inspect real bytes, even inside an outer npm pack/publish --dry-run
    // lifecycle that exports npm_config_dry_run=true to this process.
    const args = ["pack", "--ignore-scripts", "--dry-run=false", "--json", "--cache", path.join(temp, "cache"), "--pack-destination", temp];
    const npmCli = process.env.npm_execpath;
    // npm.cmd cannot be spawned directly on Windows without a shell. npm run /
    // lifecycle invocations supply npm_execpath, so invoke that JS entry with
    // Node and keep shell interpolation out of every audit command.
    let output;
    if (npmCli && path.basename(npmCli) === "npm-cli.js") output = command(process.execPath, [npmCli, ...args], root);
    else if (process.platform !== "win32") output = command("npm", args, root);
    else fail("on Windows, run this guard through npm run audit:dist so npm_execpath is available");
    let packed;
    try { packed = JSON.parse(output); } catch { fail("npm pack did not return valid JSON"); }
    const filename = packed?.[0]?.filename;
    if (!Array.isArray(packed) || packed.length !== 1 || typeof filename !== "string" || !safePath(filename) || filename.includes("/")) fail("unexpected npm pack result");
    return auditArchive(readRegular(temp, filename, policy.maxArchiveBytes), policy);
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
}

export function main(args = process.argv.slice(2)) {
  const json = args.includes("--json"), history = args.includes("--history"), packageOnly = args.includes("--package-only");
  const mode = history ? "history" : packageOnly ? "package" : "distribution";
  let result;
  try {
    if (args.some((a) => !["--json", "--history", "--package-only"].includes(a)) || (history && packageOnly)) fail("usage: node scripts/audit-dist.mjs [--history | --package-only] [--json]");
    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(path.join(ROOT, "scripts/dist-policy.json"), "utf8")); }
    catch { fail("distribution policy is unreadable or invalid JSON"); }
    const policy = validatePolicy(parsed);
    result = { ok: true, mode };
    if (history) result.history = auditHistory(ROOT, policy);
    else {
      if (!packageOnly) result.git = auditTracked(ROOT, policy);
      result.package = auditPackage(ROOT, policy);
    }
    result.failures = [result.git, result.package, result.history].filter(Boolean).flatMap((s) => s.failures);
    for (const section of [result.git, result.package, result.history].filter(Boolean)) delete section.failures;
    result.ok = result.failures.length === 0;
  } catch (error) {
    result = { ok: false, mode, failures: [{ scope: mode, rule: error.code ? `operation failed (${error.code})` : error.message }] };
  }
  if (json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log(`Distribution audit: ${result.ok ? "PASS" : "FAIL"} (${mode})`);
    if (result.git) console.log(`Git index/worktree: ${result.git.files} paths, ${result.git.indexBlobs} index blobs`);
    if (result.package) console.log(`Actual npm tarball: ${result.package.files} files${result.package.sha256 ? `; SHA-256 ${result.package.sha256}` : ""}`);
    if (result.history) console.log(`Fetched history: ${result.history.commits} commits, ${result.history.pathBlobPairs} path/blob pairs, ${result.history.uniqueBlobs} unique blobs`);
    for (const finding of result.failures) console.error(`${finding.scope}${finding.path ? ` ${JSON.stringify(finding.path)}` : ""}: ${finding.rule}`);
    console.log("Checks cover inventory and recognizable content patterns, not authorship or permission. See PROVENANCE.md.");
  }
  return result.ok ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main();
