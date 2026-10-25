#!/usr/bin/env node
// fw-index: build and query a firmware-wide index of Switch system modules.
// Scans immediate child directories containing a `main` image, recording build
// id, sizes, segments and bounded rodata/data strings. Search covers this local
// index, not necessarily every module or string in a firmware installation.
//
//   node harness/fw-index.mjs build <dumps-dir> [index.json]
//   node harness/fw-index.mjs search <index.json> <regex>   # which modules contain a string
//   node harness/fw-index.mjs report <index.json>           # markdown overview
import fs from "node:fs";
import path from "node:path";
import { openImage, extractStrings, hex } from "../plugins/hex-viewer/lib/bintools.mjs";
import { findServices, parseNpdm } from "../plugins/hex-viewer/lib/re.mjs";

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
    let npdm = null;
    const npdmPath = path.join(dir, name, "main.npdm");
    try { if (fs.existsSync(npdmPath)) { const n = parseNpdm(fs.readFileSync(npdmPath)); npdm = { name: n.name, programId: n.programId, services: n.services }; } } catch { /* skip */ }
    modules.push({
      title: name,
      buildId: img.buildId,
      fileSize: fs.statSync(main).size,
      memSize: img.data.length,
      segments: img.segments.map((s) => ({ name: s.name, size: s.size })),
      symbols: img.symbols.length,
      services, npdm,
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

// Group literal NPDM ACI0 service entries by declared host/connect permission.
// These declarations are not a runtime dependency map. The parser does not
// verify ACID signatures, establish effective authorization or expand wildcards.
function servicesReport(index) {
  const withNpdm = index.modules.filter((m) => m.npdm && m.npdm.services);
  // Keep the existing index field names; host/client sets represent declarations.
  const map = new Map(); // service -> {hosts:Set, clients:Set}
  const label = (m) => (m.npdm && m.npdm.name) || m.title.slice(-8);
  for (const m of withNpdm) for (const s of m.npdm.services) {
    const e = map.get(s.name) || map.set(s.name, { hosts: new Set(), clients: new Set() }).get(s.name);
    (s.host ? e.hosts : e.clients).add(label(m));
  }
  const rows = [...map.entries()].map(([name, e]) => ({ name, hosts: [...e.hosts], clients: [...e.clients] }))
    .sort((a, b) => b.clients.length - a.clients.length || a.name.localeCompare(b.name));
  const lines = [`# Switch firmware IPC service declarations`, ``, `- Source: \`${index.dir}\``,
    `- Modules with parsed NPDM: **${withNpdm.length}**  ·  distinct service entries: **${map.size}**`, ``,
    `Entries come from NPDM ACI0 service declarations: **host** and **connect** describe requested permissions. They do not establish actual registration, use or effective authorization. ACID signatures are not verified, wildcard entries are not expanded, and absent modules can leave this index incomplete.`, ``,
    `## Entries with the most declared connecting modules`, ``, `| Service entry | Modules declaring host permission | Modules declaring connect permission |`, `| --- | --- | --- |`];
  for (const r of rows.slice(0, 50)) lines.push(`| \`${r.name}\` | ${r.hosts.join(", ") || "**?** (no matching host declaration in index)"} | ${r.clients.length} |`);
  const orphanHosts = rows.filter((r) => r.hosts.length === 0);
  if (orphanHosts.length) lines.push(``, `## Connect entries without a matching host declaration in this index (${orphanHosts.length})`, ``,
    orphanHosts.map((r) => `\`${r.name}\``).join(" "));
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
