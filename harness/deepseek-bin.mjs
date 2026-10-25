#!/usr/bin/env node
// deepseek-bin: a DeepSeek-powered reverse-engineering agent for binaries
// (Nintendo Switch NSO/NRO/NSP/XCI first, any file second). Uses the same
// toolkit as the Hex Viewer MCP server. Zero npm dependencies; Node 18+.
//
//   DEEPSEEK_API_KEY=... node harness/deepseek-bin.mjs main.nso
//   node harness/deepseek-bin.mjs -p "find the save-file loader" main.nso
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import readline from "node:readline";
import { TOOLS, safeCallTool, resolvePath } from "../plugins/hex-viewer/lib/bintools.mjs";

const STATE_DIR = path.join(os.homedir(), ".binharness");
const TOOL_RESULT_LIMIT = 16000;
// USD per 1M tokens at peak rates (off-peak is half): [cache hit, cache miss, output]
const PRICES = { "deepseek-flash": [0.006, 0.3, 1.2], "deepseek-v4-pro": [0.044, 1.32, 3.96] };
const WRITE_TOOLS = new Set(["extract_image"]);

// ---------- CLI args ----------

function usage() {
  console.log(`usage: deepseek-bin [options] [files...]

  -p, --prompt <text>    run one task non-interactively and exit
  -m, --model <name>     deepseek-flash (default) | deepseek-v4-pro
      --pro              shorthand for --model deepseek-v4-pro
  -e, --effort <level>   none | low | high (default) | max   (none = no thinking)
      --max-steps <n>    tool-call rounds per task (default 60)
      --base-url <url>   API base (default https://api.deepseek.com)
  -y, --yes              allow file-writing tools without asking
      --show-thinking    print the model's reasoning as it streams
      --recon            run the naming passes (RTTI/syscalls/services) up front
  -h, --help

env: DEEPSEEK_API_KEY (required), DEEPSEEK_BASE_URL, DEEPSEEK_MODEL
REPL: /help /recon [file] /model /effort /files /add <file> /cost /save <file.md> /reset /exit`);
}

const opts = { model: process.env.DEEPSEEK_MODEL || "deepseek-flash", effort: "high", maxSteps: 60, baseUrl: process.env.DEEPSEEK_BASE_URL || "https://api.deepseek.com", yes: false, showThinking: false, recon: false, prompt: null, files: [] };
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  const a = argv[i], next = () => argv[++i];
  if (a === "-h" || a === "--help") { usage(); process.exit(0); }
  else if (a === "-p" || a === "--prompt") opts.prompt = next();
  else if (a === "-m" || a === "--model") opts.model = next();
  else if (a === "--pro") opts.model = "deepseek-v4-pro";
  else if (a === "-e" || a === "--effort") opts.effort = next();
  else if (a === "--max-steps") opts.maxSteps = +next();
  else if (a === "--base-url") opts.baseUrl = next();
  else if (a === "-y" || a === "--yes") opts.yes = true;
  else if (a === "--show-thinking") opts.showThinking = true;
  else if (a === "--recon") opts.recon = true;
  else if (a.startsWith("-")) { console.error(`unknown option ${a}`); usage(); process.exit(2); }
  else opts.files.push(resolvePath(a));
}
const API_KEY = process.env.DEEPSEEK_API_KEY;
if (!API_KEY) { console.error("DEEPSEEK_API_KEY is not set. Get a key at https://platform.deepseek.com and export it."); process.exit(2); }

// ---------- terminal helpers ----------

const tty = process.stdout.isTTY;
const c = (code) => (s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const dim = c(2), cyan = c(36), yellow = c(33), red = c(31), bold = c(1);
const out = (s) => process.stdout.write(s);

// ---------- conversation state ----------

const SYSTEM = `You are deepseek-bin, an expert reverse engineer working inside a binary-analysis harness.
Primary target: Nintendo Switch executables (NSO/NRO; AArch64, little-endian, default base 0x7100000000) and containers (NSP/PFS0, XCI/HFS0). These sysmodules are STRIPPED and statically linked (no symbol table), so you recover structure yourself. You can also analyze any other file.

RECON FIRST — on a fresh module, before answering anything, establish structure and names in this order (unless the harness already ran /recon, in which case names exist and you can skip straight to the question):
1. file_info — segments, build id, size.
2. parse_npdm — if a sibling main.npdm exists: program id, which services the module HOSTS vs connects to, syscall allowlist. This is the module's identity and job in one call.
3. label_rtti — demangle C++ class names and name every vtable + virtual method. This is the biggest win; do it early so disassembly and the function list come back named.
4. label_syscalls and label_services — name the svc wrappers and service-using functions.
5. Now list_functions / find_rtti / scan_syscalls / find_services show real names. Use find_string_refs (log/assert/error strings) to reach specific logic.

Then investigate:
- disassemble by address or symbol; it annotates call targets, labels, ADRP+ADD/LDR data refs with string previews. Follow callers/callees with call_graph and find_xrefs.
- decode_struct for data, search_bytes for signatures (?? wildcards), read_binary_chunk for raw bytes.
- annotate anything you figure out (labels/comments/notes). Annotations persist per build id and appear in later disassembly, so name as you go.

Rules:
- Prefer many small, targeted calls over huge dumps. Ask for 32-200 instructions at a time.
- Addresses are virtual-address hex strings ("0x7100012340"). Cite addresses in answers.
- Reconstruct code as clear C/C++ with typed structs; flag uncertain parts.
- NCA files are encrypted; you cannot decrypt them. Ask for extracted NSO/NRO instead.
Be concise in prose; be precise about addresses, types and evidence.`;

const tools = TOOLS.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.inputSchema } }));
let messages = [{ role: "system", content: SYSTEM }];
const totals = { hit: 0, miss: 0, out: 0, cost: 0 };
fs.mkdirSync(path.join(STATE_DIR, "sessions"), { recursive: true });
const logFile = path.join(STATE_DIR, "sessions", `${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`);
const log = (rec) => fs.appendFileSync(logFile, JSON.stringify({ t: Date.now(), ...rec }) + "\n");

function filesNote(files) {
  return files.length ? `\n\nFiles in this session:\n${files.map((f) => `- ${f}`).join("\n")}` : "";
}

// ---------- DeepSeek streaming call ----------

let currentAbort = null;

async function chat() {
  const body = {
    model: opts.model, messages, tools, stream: true, stream_options: { include_usage: true },
    ...(opts.effort === "none" ? { thinking: { type: "disabled" } } : { thinking: { type: "enabled" }, reasoning_effort: opts.effort }),
  };
  currentAbort = new AbortController();
  const res = await fetch(`${opts.baseUrl.replace(/\/$/, "")}/chat/completions`, {
    method: "POST", signal: currentAbort.signal,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}` },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`DeepSeek API ${res.status}: ${(await res.text()).slice(0, 500)}`);

  const msg = { role: "assistant", content: "", reasoning_content: "" };
  const calls = [];
  let usage = null, buf = "", thinkingShown = false, contentStarted = false;
  const decoder = new TextDecoder();
  for await (const chunk of res.body) {
    buf += decoder.decode(chunk, { stream: true });
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
      if (!line.startsWith("data:")) continue;
      const data = line.slice(5).trim();
      if (data === "[DONE]") continue;
      const ev = JSON.parse(data);
      if (ev.usage) usage = ev.usage;
      const d = ev.choices?.[0]?.delta;
      if (!d) continue;
      if (d.reasoning_content) {
        msg.reasoning_content += d.reasoning_content;
        if (opts.showThinking) { if (!thinkingShown) { out(dim("thinking: ")); thinkingShown = true; } out(dim(d.reasoning_content)); }
        else if (!thinkingShown && tty) { out(dim("thinking…")); thinkingShown = true; }
      }
      if (d.content) {
        if (!contentStarted) { if (thinkingShown) out(tty && !opts.showThinking ? "\r\x1b[K" : "\n\n"); contentStarted = true; }
        msg.content += d.content; out(d.content);
      }
      for (const tc of d.tool_calls || []) {
        const slot = (calls[tc.index] ||= { id: "", type: "function", function: { name: "", arguments: "" } });
        if (tc.id) slot.id = tc.id;
        if (tc.function?.name) slot.function.name += tc.function.name;
        if (tc.function?.arguments) slot.function.arguments += tc.function.arguments;
      }
    }
  }
  if (thinkingShown && !contentStarted) out(tty && !opts.showThinking ? "\r\x1b[K" : "\n");
  if (contentStarted) out("\n");
  currentAbort = null;
  if (calls.length) msg.tool_calls = calls.filter(Boolean);
  if (!msg.reasoning_content) delete msg.reasoning_content;
  if (usage) {
    const hit = usage.prompt_cache_hit_tokens ?? 0, miss = usage.prompt_cache_miss_tokens ?? (usage.prompt_tokens - hit);
    const p = PRICES[opts.model] || PRICES["deepseek-flash"];
    totals.hit += hit; totals.miss += miss; totals.out += usage.completion_tokens;
    totals.cost += (hit * p[0] + miss * p[1] + usage.completion_tokens * p[2]) / 1e6;
  }
  return msg;
}

// ---------- tool execution ----------

async function confirm(q) {
  if (opts.yes) return true;
  if (!process.stdin.isTTY || opts.prompt) return false;
  const ans = await ask(yellow(`${q} [y/N] `));
  return /^y/i.test(ans.trim());
}

function summarizeArgs(a) {
  return Object.entries(a).filter(([k]) => k !== "path").map(([k, v]) => `${k}=${typeof v === "string" && v.length > 40 ? v.slice(0, 40) + "…" : JSON.stringify(v)}`).join(" ");
}

async function runTool(call) {
  let args;
  try { args = JSON.parse(call.function.arguments || "{}"); }
  catch { return `error: arguments were not valid JSON: ${call.function.arguments.slice(0, 200)}`; }
  const name = call.function.name;
  out(cyan(`  ⏺ ${name}`) + dim(` ${args.path ? path.basename(args.path) + " " : ""}${summarizeArgs(args)}`) + "\n");
  if (WRITE_TOOLS.has(name) && !(await confirm(`  allow ${name} to write ${args.out}?`))) return "error: the user declined this file write";
  const t0 = Date.now();
  const r = safeCallTool(name, args);
  let text = r.content.map((x) => x.text).join("\n");
  if (r.isError) out(red(`    ✗ ${text.split("\n")[0]}`) + "\n");
  else out(dim(`    ✓ ${text.split("\n").length} lines, ${Date.now() - t0} ms`) + "\n");
  if (text.length > TOOL_RESULT_LIMIT) text = text.slice(0, TOOL_RESULT_LIMIT) + `\n…[truncated ${text.length - TOOL_RESULT_LIMIT} chars; request a narrower range or add a filter]`;
  return r.isError ? `error: ${text}` : text;
}

// ---------- agent loop ----------

async function runTask(userText) {
  messages.push({ role: "user", content: userText });
  log({ role: "user", content: userText });
  for (let step = 0; step < opts.maxSteps; step++) {
    const msg = await chat();
    messages.push(msg);
    log({ role: "assistant", content: msg.content, tool_calls: msg.tool_calls });
    if (!msg.tool_calls?.length) return msg.content;
    for (const call of msg.tool_calls) {
      const result = await runTool(call);
      messages.push({ role: "tool", tool_call_id: call.id, content: result });
      log({ role: "tool", name: call.function.name, args: call.function.arguments, chars: result.length });
    }
  }
  out(yellow(`\n(stopped after ${opts.maxSteps} tool rounds; say "continue" to keep going)\n`));
}

// Deterministic recon: run the structure + naming passes on a module directly
// (no model tokens), then inject a summary so the agent starts already oriented.
function recon(file) {
  file = resolvePath(file);
  out(bold(`\nrecon ${path.basename(file)}\n`));
  const summary = [];
  const step = (title, name, args) => {
    const r = safeCallTool(name, { path: file, ...args });
    const text = r.content.map((x) => x.text).join("\n");
    const first = text.split("\n").find((l) => l.trim()) || "";
    out(cyan(`  ${title}`) + dim(`  ${r.isError ? "✗ " + first : first.slice(0, 90)}`) + "\n");
    if (!r.isError) summary.push(`### ${title}\n${text.length > 1500 ? text.slice(0, 1500) + "\n…" : text}`);
    return r;
  };
  step("file_info", "file_info", {});
  const npdm = file.replace(/\/main$/, "/main.npdm");
  if (npdm !== file && fs.existsSync(npdm)) step("parse_npdm", "parse_npdm", { path: npdm });
  step("label_rtti", "label_rtti", {});
  step("label_syscalls", "label_syscalls", {});
  step("label_services", "label_services", {});
  step("list_functions", "list_functions", { named_only: true, limit: 40 });
  messages.push(
    { role: "user", content: `I ran recon on ${file}. Structure and names are already established (RTTI classes, svc wrappers and service users are labeled and persist). Here is the summary; use it instead of re-running these passes:\n\n${summary.join("\n\n")}` },
    { role: "assistant", content: "Recon received — the module is oriented and named. What would you like me to investigate?" },
  );
  out(dim(`  (${summary.length} passes; names saved and shared with the model)\n`));
}

function costLine() {
  const total = totals.hit + totals.miss;
  return dim(`[${opts.model} · in ${total.toLocaleString()} (${total ? Math.round((100 * totals.hit) / total) : 0}% cached) · out ${totals.out.toLocaleString()} · ≤$${totals.cost.toFixed(4)}]`);
}

function toMarkdown() {
  return messages.filter((m) => m.role !== "system").map((m) => {
    if (m.role === "user") return `## User\n\n${m.content}`;
    if (m.role === "tool") return `<details><summary>tool result</summary>\n\n\`\`\`\n${m.content}\n\`\`\`\n</details>`;
    const calls = (m.tool_calls || []).map((t) => `- \`${t.function.name}(${t.function.arguments})\``).join("\n");
    return `## deepseek-bin\n\n${m.content || ""}${calls ? "\n\n" + calls : ""}`;
  }).join("\n\n");
}

// ---------- REPL ----------

// Line queue instead of rl.question so piped input isn't dropped.
let rl = null, closed = false;
const lineQueue = [], lineWaiters = [];
function ask(q) {
  out(q);
  if (lineQueue.length) return Promise.resolve(lineQueue.shift());
  if (closed) return Promise.resolve(null);
  return new Promise((res) => lineWaiters.push(res));
}

function looksLikeModule(f) {
  try { const b = Buffer.alloc(4); const fd = fs.openSync(f, "r"); fs.readSync(fd, b, 0, 4, 0); fs.closeSync(fd);
    return b.toString("latin1") === "NSO0" || b.toString("latin1", 0, 4) === "\x7fELF"; } catch { return false; }
}

async function main() {
  const intro = opts.files.length ? `I'm working with these files:${filesNote(opts.files).replace(/^\n\nFiles in this session:/, "")}\nStart by getting your bearings (file_info), then wait for my questions.` : null;

  // --recon (or auto, when a single module is given): run the naming passes up front.
  const reconTargets = opts.recon ? opts.files.filter(looksLikeModule) : [];
  if (opts.recon && !reconTargets.length) out(yellow("(--recon: no NSO/ELF module among the files)\n"));

  if (opts.prompt) {
    try { for (const f of reconTargets) recon(f); await runTask(opts.prompt + (reconTargets.length ? "" : filesNote(opts.files))); }
    catch (e) { console.error(red(e.message)); process.exitCode = 1; }
    console.error(costLine());
    return;
  }

  rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: tty });
  rl.on("line", (l) => (lineWaiters.length ? lineWaiters.shift()(l) : lineQueue.push(l)));
  rl.on("close", () => { closed = true; while (lineWaiters.length) lineWaiters.shift()(null); });
  rl.on("SIGINT", () => { if (currentAbort) { currentAbort.abort(); out(yellow("\n(interrupted)\n")); } else rl.close(); });
  console.log(bold("deepseek-bin") + dim(` · ${opts.model} · effort ${opts.effort} · /help for commands · log ${logFile}`));
  for (const f of reconTargets) recon(f);
  if (intro && !reconTargets.length) await safeTask(intro);

  for (;;) {
    const raw = await ask(bold("\n› "));
    if (raw === null) break;
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith("/")) { if (await command(line) === "exit") break; continue; }
    await safeTask(line);
    console.log(costLine());
  }
  rl.close();
  console.log("\n" + costLine());
}

async function safeTask(text) {
  try { await runTask(text); }
  catch (e) {
    if (e.name === "AbortError") { messages.push({ role: "user", content: "(I interrupted you. Stop and wait for my next message.)" }); return; }
    console.error(red(e.message));
    // Keep history valid: drop a dangling user turn so the next request isn't malformed.
    while (messages.length > 1 && messages[messages.length - 1].role !== "assistant") messages.pop();
  }
}

async function command(line) {
  const [cmd, ...rest] = line.split(/\s+/);
  const arg = rest.join(" ");
  switch (cmd) {
    case "/exit": case "/quit": return "exit";
    case "/help": usage(); break;
    case "/model": if (arg) opts.model = arg; console.log(`model: ${opts.model}`); break;
    case "/effort": if (arg) opts.effort = arg; console.log(`effort: ${opts.effort}`); break;
    case "/files": console.log(opts.files.join("\n") || "(none)"); break;
    case "/add": {
      const f = resolvePath(arg); opts.files.push(f);
      messages.push({ role: "user", content: `Added file: ${f}` }, { role: "assistant", content: "Noted." });
      console.log(`added ${f}`); break;
    }
    case "/recon": { const f = arg ? resolvePath(arg) : opts.files[0]; if (!f) { console.log("usage: /recon <file> (or load a file first)"); break; } recon(f); break; }
    case "/cost": console.log(costLine()); break;
    case "/reset": messages = [{ role: "system", content: SYSTEM }]; console.log("conversation cleared (annotations are kept)"); break;
    case "/save": { const f = resolvePath(arg || "deepseek-bin-session.md"); fs.writeFileSync(f, toMarkdown()); console.log(`saved ${f}`); break; }
    default: console.log(`unknown command ${cmd} (try /help)`);
  }
}

main();
