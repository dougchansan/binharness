#!/usr/bin/env node
// fw-index: build and query a firmware-wide index of Switch system modules.
// Scans every CodeFS `main` NSO under a dump directory, records build id,
// sizes, segment layout and all printable strings, and lets you grep across
// the whole firmware (string -> which title(s) and addresses).
//
//   node harness/fw-index.mjs build <dumps-dir> [index.json]
//   node harness/fw-index.mjs search <index.json> <regex>   # which modules contain a string
//   node harness/fw-index.mjs report <index.json>           # markdown overview
import fs from "node:fs";
import path from "node:path";
import { openImage, extractStrings, hex } from "../plugins/hex-viewer/lib/bintools.mjs";
import { findServices } from "../plugins/hex-viewer/lib/re.mjs";

function buildIndex(dir) {
  dir = path.resolve(dir);
  const modules = [];
  for (const name of fs.readdirSync(dir).sort()) {
    const main = path.join(dir, name, "main");
    if (!fs.existsSync(main)) continue;
    let img;
    try { img = openImage(main); } catch (e) { modules.push({ title: name, error: e.message }); continue; }
    const strings = [];
    for (const sname of ["rodata", "data"]) {
      const s = img.segments.find((x) => x.name === sname);
      if (s) strings.push(...extractStrings(img.data.subarray(s.start, s.start + s.size), img.base + s.start, 5, 1e6));
    }
    let services = [];
    try { services = findServices(img).map((s) => ({ name: s.name, refs: s.refs.length })); } catch { /* skip */ }
    modules.push({
      title: name,
      buildId: img.buildId,
      fileSize: fs.statSync(main).size,
      memSize: img.data.length,
      segments: img.segments.map((s) => ({ name: s.name, size: s.size })),
      symbols: img.symbols.length,
      services,
      strings: strings.map((s) => [s.addr, s.text]),
    });
  }
  return { dir, created: new Date().toISOString(), moduleCount: modules.filter((m) => !m.error).length, modules };
}

function search(index, pattern) {
  const re = new RegExp(pattern, "i");
  const hits = [];
  for (const m of index.modules) {
    if (m.error) continue;
    const found = m.strings.filter(([, t]) => re.test(t)).slice(0, 8);
    if (found.length) hits.push({ title: m.title, count: m.strings.filter(([, t]) => re.test(t)).length, sample: found });
  }
  return hits;
}

function report(index) {
  const ok = index.modules.filter((m) => !m.error);
  const bySize = [...ok].sort((a, b) => b.memSize - a.memSize);
  const totalStr = ok.reduce((n, m) => n + m.strings.length, 0);
  const lines = [
    `# Switch firmware index`, ``,
    `- Source: \`${index.dir}\``, `- Built: ${index.created}`,
    `- Modules indexed: **${ok.length}**${index.modules.length > ok.length ? ` (${index.modules.length - ok.length} failed)` : ""}`,
    `- Total strings: **${totalStr.toLocaleString()}**`, ``,
    `## Largest modules (decompressed)`, ``,
    `| Title ID | Build ID | File | Memory | .text | strings |`, `| --- | --- | --- | --- | --- | --- |`,
    ...bySize.slice(0, 20).map((m) => `| ${m.title} | \`${(m.buildId || "").slice(0, 12)}\` | ${(m.fileSize / 1024 / 1024).toFixed(1)} MB | ${(m.memSize / 1024 / 1024).toFixed(1)} MB | ${hex(m.segments.find((s) => s.name === "text").size)} | ${m.strings.length.toLocaleString()} |`),
  ];
  if (index.modules.some((m) => m.error)) {
    lines.push(``, `## Failed`, ``, ...index.modules.filter((m) => m.error).map((m) => `- ${m.title}: ${m.error}`));
  }
  return lines.join("\n");
}

// Invert services -> which modules reference them. This is reference-based:
// a module referencing a service name either registers (serves) or connects to
// (consumes) it, and the two look the same from the name string alone. So this
// is a "who touches this service" map, not a proven provider/consumer split.
// For a service only one module references, that module is almost certainly its
// server; widely-referenced services (sm:, fsp-srv) are owned elsewhere and the
// counts just reflect how heavily each caller uses them.
function servicesReport(index) {
  const ok = index.modules.filter((m) => !m.error && m.services);
  const map = new Map(); // service -> [{title, refs}]
  for (const m of ok) for (const s of m.services) (map.get(s.name) || map.set(s.name, []).get(s.name)).push({ title: m.title, refs: s.refs });
  const rows = [...map.entries()].map(([name, users]) => ({ name, users: users.sort((a, b) => b.refs - a.refs) }))
    .sort((a, b) => b.users.length - a.users.length || a.name.localeCompare(b.name));
  const sole = rows.filter((r) => r.users.length === 1);
  const lines = [`# Switch firmware IPC service map`, ``, `- Source: \`${index.dir}\``, `- Modules with services: **${ok.length}**  ·  distinct services: **${map.size}**`, ``,
    `Reference-based: each module listed *references* that service name, whether it serves or connects to it — the name string alone can't tell which. Counts are how many modules touch the service and how many times the top module references it.`, ``,
    `## Shared services (most widely referenced)`, ``, `| Service | Modules | Heaviest user (refs) |`, `| --- | --- | --- |`];
  for (const r of rows.filter((x) => x.users.length > 1).slice(0, 40)) lines.push(`| \`${r.name}\` | ${r.users.length} | ${r.users[0].title.slice(-8)} (${r.users[0].refs}) |`);
  lines.push(``, `## Single-module services (likely that module's own)`, ``, `| Service | Module |`, `| --- | --- |`,
    ...sole.slice(0, 60).map((r) => `| \`${r.name}\` | ${r.users[0].title.slice(-8)} |`));
  return lines.join("\n");
}

const [cmd, arg1, arg2] = process.argv.slice(2);
if (cmd === "build") {
  const out = arg2 || "fw-index.json";
  const idx = buildIndex(arg1);
  fs.writeFileSync(out, JSON.stringify(idx));
  console.error(`indexed ${idx.moduleCount} modules -> ${out} (${(fs.statSync(out).size / 1024 / 1024).toFixed(1)} MB)`);
} else if (cmd === "search") {
  const idx = JSON.parse(fs.readFileSync(arg1, "utf8"));
  const hits = search(idx, arg2);
  if (!hits.length) { console.log(`no module strings match /${arg2}/i`); }
  for (const h of hits.sort((a, b) => b.count - a.count)) {
    console.log(`\n${h.title}  (${h.count} match${h.count > 1 ? "es" : ""})`);
    for (const [addr, text] of h.sample) console.log(`  ${addr.toString(16)}  ${JSON.stringify(text).slice(0, 100)}`);
  }
} else if (cmd === "report") {
  console.log(report(JSON.parse(fs.readFileSync(arg1, "utf8"))));
} else if (cmd === "services") {
  console.log(servicesReport(JSON.parse(fs.readFileSync(arg1, "utf8"))));
} else {
  console.log("usage: fw-index build <dumps-dir> [out.json] | search <index.json> <regex> | report <index.json> | services <index.json>");
  process.exit(2);
}
