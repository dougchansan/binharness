# Binharness — Kimi plugin

Install into the Kimi desktop app as a **local plugin**:

1. Kimi → Settings → Plugins → **Install local plugin** → choose "from directory".
2. Select this folder (`integrations/kimi/binharness`).

The plugin registers the `binharness` MCP server (run locally via Node) and a skill
with the recon-first workflow. Its tools then appear to Kimi as `mcp__binharness__*`
— `view_binary` (hex viewer), `file_info`, `disassemble`, `list_functions`,
`find_rtti`, `label_rtti`, `scan_syscalls`, `find_services`, `parse_npdm`,
`export_symbols`, and more.

The server runs from `/Users/douglaswhittingham/codex-hex-viewer/plugins/hex-viewer/server.mjs`
(set in `kimi.plugin.json` → `mcpServers`). If you move the repo or publish to npm,
update that path (or switch it to `npx -y binharness binharness-mcp`).
