#!/usr/bin/env node
// Hex Viewer MCP server: zero-dependency stdio JSON-RPC server exposing
// binary-file tools plus an MCP App UI (ui://hex-viewer/app).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import readline from "node:readline";
import { TOOLS as BIN_TOOLS, callTool as binCallTool, resolvePath, readRange, hexdump, detectFormat } from "./lib/bintools.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP_URI = "ui://hex-viewer/app";
const APP_MIME = "text/html;profile=mcp-app";
const INITIAL_CHUNK = 16 * 1024;

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
  ...BIN_TOOLS,
];

function callTool(name, args = {}) {
  if (name === "view_binary") {
    const file = resolvePath(args.path);
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
  return binCallTool(name, args);
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
        serverInfo: { name: "hex-viewer", version: "0.4.0" },
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
