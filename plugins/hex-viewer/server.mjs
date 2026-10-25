#!/usr/bin/env node
// Hex Viewer MCP server: zero-dependency stdio JSON-RPC server exposing
// binary-file tools plus an MCP App UI (ui://hex-viewer/app).
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import readline from "node:readline";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP_URI = "ui://hex-viewer/app";
const APP_MIME = "text/html;profile=mcp-app";
const INITIAL_CHUNK = 16 * 1024;
const MAX_CHUNK = 64 * 1024;

// ---------- helpers ----------

function resolvePath(p) {
  if (typeof p !== "string" || !p) throw new Error("path is required");
  if (p.startsWith("~")) p = path.join(os.homedir(), p.slice(1));
  return path.resolve(p);
}

function readRange(file, offset, length) {
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

function hexdump(buf, base, maxLines = Infinity) {
  const lines = [];
  for (let i = 0; i < buf.length && lines.length < maxLines; i += 16) {
    const row = buf.subarray(i, i + 16);
    const hex = [...row].map((b) => b.toString(16).padStart(2, "0"));
    const left = hex.slice(0, 8).join(" ").padEnd(23);
    const right = hex.slice(8).join(" ").padEnd(23);
    const ascii = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${(base + i).toString(16).padStart(8, "0")}  ${left}  ${right}  |${ascii}|`);
  }
  return lines.join("\n");
}

function detectFormat(b, size, name) {
  const s = (o, n) => b.subarray(o, o + n).toString("latin1");
  const u32be = (o) => (b.length >= o + 4 ? b.readUInt32BE(o) : -1);
  const ext = path.extname(name).toLowerCase();
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
  if (s(0, 4) === "\x28\xb5\x2f\xfd") return "Zstandard";
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

function extractStrings(buf, base, minLen, max) {
  const out = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const c = buf[i];
    const printable = i < buf.length && ((c >= 0x20 && c < 0x7f) || c === 9);
    if (printable) { if (start < 0) start = i; continue; }
    if (start >= 0 && i - start >= minLen) {
      out.push({ offset: base + start, text: buf.subarray(start, i).toString("latin1") });
      if (out.length >= max) break;
    }
    start = -1;
  }
  return out;
}

// ---------- tools ----------

const TOOLS = [
  {
    name: "view_binary",
    title: "Open in Hex Viewer",
    description: "Open a binary file in an interactive hex viewer UI. Use for any file whose preview isn't supported (executables, object files, ROMs, archives, images, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the file (~ allowed)." },
        offset: { type: "integer", minimum: 0, description: "Byte offset to scroll to initially." },
      },
      required: ["path"],
    },
    annotations: { readOnlyHint: true },
    _meta: { ui: { resourceUri: APP_URI }, "openai/outputTemplate": APP_URI },
  },
  {
    name: "read_binary_chunk",
    title: "Read bytes",
    description: "Read a range of bytes from a file. Returns a text hexdump (format=hex) or base64 (format=base64). Max 64 KiB per call.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        offset: { type: "integer", minimum: 0, default: 0 },
        length: { type: "integer", minimum: 1, maximum: MAX_CHUNK, default: 512 },
        format: { type: "string", enum: ["hex", "base64"], default: "hex" },
      },
      required: ["path"],
    },
    annotations: { readOnlyHint: true },
  },
  {
    name: "binary_strings",
    title: "Extract strings",
    description: "List printable ASCII strings in a file (like `strings -t x`).",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        min_length: { type: "integer", minimum: 2, default: 4 },
        offset: { type: "integer", minimum: 0, default: 0 },
        length: { type: "integer", minimum: 1, description: "Bytes to scan (default 8 MiB)." },
        max_results: { type: "integer", minimum: 1, maximum: 5000, default: 500 },
      },
      required: ["path"],
    },
    annotations: { readOnlyHint: true },
  },
];

function callTool(name, args = {}) {
  const file = resolvePath(args.path);
  if (name === "view_binary") {
    const want = Math.max(0, Math.floor(args.offset || 0));
    const chunkStart = Math.floor(want / INITIAL_CHUNK) * INITIAL_CHUNK;
    const head = readRange(file, 0, 4096);
    const chunk = chunkStart === 0 ? readRange(file, 0, INITIAL_CHUNK) : readRange(file, chunkStart, INITIAL_CHUNK);
    const format = detectFormat(head.buf, head.size, file);
    const summary = `${file}\n${head.size} bytes (0x${head.size.toString(16)})${format ? ` — ${format}` : ""}`;
    return {
      content: [{ type: "text", text: `${summary}\n\n${hexdump(head.buf, 0, 16)}${head.size > 256 ? "\n…" : ""}` }],
      structuredContent: {
        path: file, name: path.basename(file), size: head.size, mtime: head.mtime, format,
        initialOffset: Math.min(want, head.size), chunkOffset: chunk.offset, data: chunk.buf.toString("base64"),
      },
    };
  }
  if (name === "read_binary_chunk") {
    const len = Math.min(args.length || 512, MAX_CHUNK);
    const r = readRange(file, args.offset || 0, len);
    const b64 = r.buf.toString("base64");
    const text = args.format === "base64" ? b64 : hexdump(r.buf, r.offset);
    return {
      content: [{ type: "text", text: text || "(no bytes in range)" }],
      structuredContent: { path: file, size: r.size, offset: r.offset, length: r.buf.length, data: b64 },
    };
  }
  if (name === "binary_strings") {
    const r = readRange(file, args.offset || 0, args.length || 8 * 1024 * 1024);
    const strs = extractStrings(r.buf, r.offset, args.min_length || 4, args.max_results || 500);
    const text = strs.map((x) => `${x.offset.toString(16).padStart(8, "0")}  ${x.text}`).join("\n");
    return { content: [{ type: "text", text: text || "(no strings found)" }], structuredContent: { strings: strs } };
  }
  throw new Error(`Unknown tool: ${name}`);
}

// ---------- JSON-RPC over stdio ----------

function send(msg) { process.stdout.write(JSON.stringify(msg) + "\n"); }

function handle(req) {
  const { id, method, params = {} } = req;
  switch (method) {
    case "initialize":
      return {
        protocolVersion: params.protocolVersion || "2025-06-18",
        capabilities: { tools: { listChanged: false }, resources: { listChanged: false } },
        serverInfo: { name: "hex-viewer", version: "0.1.0" },
      };
    case "ping": return {};
    case "tools/list": return { tools: TOOLS };
    case "tools/call":
      try { return callTool(params.name, params.arguments); }
      catch (e) { return { isError: true, content: [{ type: "text", text: String(e.message || e) }] }; }
    case "resources/list":
      return { resources: [{ uri: APP_URI, name: "Hex Viewer", mimeType: APP_MIME }] };
    case "resources/templates/list": return { resourceTemplates: [] };
    case "resources/read":
      if (params.uri !== APP_URI) throw Object.assign(new Error("Unknown resource"), { code: -32002 });
      return {
        contents: [{
          uri: APP_URI, mimeType: APP_MIME,
          text: fs.readFileSync(path.join(HERE, "assets", "app.html"), "utf8"),
          _meta: { ui: { prefersBorder: true } },
        }],
      };
    default:
      if (id === undefined) return undefined; // notification
      throw Object.assign(new Error(`Method not found: ${method}`), { code: -32601 });
  }
}

readline.createInterface({ input: process.stdin }).on("line", (line) => {
  if (!line.trim()) return;
  let req;
  try { req = JSON.parse(line); } catch { return send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }); }
  if (req.id === undefined) { try { handle(req); } catch {} return; }
  try { send({ jsonrpc: "2.0", id: req.id, result: handle(req) }); }
  catch (e) { send({ jsonrpc: "2.0", id: req.id, error: { code: e.code || -32603, message: String(e.message || e) } }); }
});
