# binharness

A reverse-engineering toolkit for stripped Nintendo Switch modules (and any binary), packaged three ways:

- **Codex plugin** (`hex-viewer`): an interactive hex viewer that renders inline in Codex (for when the file pane says *"Binary file previews aren't supported yet"*), plus 24 RE tools Codex can call.
- **MCP server**: the same tools for any MCP client (`npx -y binharness binharness-mcp`).
- **`deepseek-bin`**: a DeepSeek CLI agent that drives the tools to reverse a module on its own.
- **`deepseek-bin`**: a standalone CLI agent that uses the same tools with DeepSeek models.

![Hex Viewer showing a file with a search hit and the byte inspector](docs/screenshot.jpg)

## What it can do

| Tool | What it does |
| --- | --- |
| `view_binary` | Interactive hex + ASCII viewer (Codex UI): go to offset, hex/text search, byte inspector |
| `file_info` | Identify the file and its structure. NSO/NRO: segments, build id, module path, symbols. NSP/XCI: contained files |
| `disassemble` | AArch64 (or x86-64) disassembly by address or symbol, annotated with call targets, labels and resolved `ADRP`+`ADD`/`LDR` data refs with string previews |
| `list_functions` | Recover function boundaries in stripped code (call targets + relocations + init arrays + prologue scan) — the missing symbol table |
| `call_graph` | Callees/callers of a function as a depth-limited tree (recursion marked) |
| `scan_syscalls` | Decode every `svc #n` into its Horizon kernel call (`SendSyncRequest`, `QueryMemory`, …), grouped |
| `label_syscalls` | Auto-name every `nn::svc` wrapper (`svcSleepThread`, …) and comment each site; names then flow into disassembly, `list_functions` and `call_graph` |
| `find_services` | Find Switch IPC service names in rodata (`fsp-srv`, `set:sys`, `nifm:u`, …) and the functions that use each, by reference count |
| `label_services` | Label referencing functions `use_<service>` and comment the service strings, as persistent annotations |
| `parse_npdm` | Parse `main.npdm`: program id, and the authoritative Service Access Control (which services a module **hosts** vs **connects to**) + kernel syscall allowlist |
| `find_rtti` | Recover C++ class names from Itanium RTTI — demangled `type_info` names, each class's vtable and virtual-method count |
| `label_rtti` | Name every vtable (`vtable_<Class>`) and virtual method (`<Class>::vf<n>`) from RTTI, as persistent annotations — a large name-recovery pass |
| `export_symbols` | Export all recovered names (functions, RTTI vtables, syscall/service labels, comments) as **Ghidra** and **IDA** import scripts; pair with `extract_image` to carry the whole analysis into a disassembler |
| `find_xrefs` | Calls, branches and data refs to an address, with the enclosing function |
| `find_string_refs` | Strings matching text → the code that uses them (fastest way into unknown code) |
| `list_symbols` | Demangled dynsym symbols and your saved labels |
| `search_bytes` | Hex patterns with `??` wildcards, or `"text"` |
| `decode_struct` | Decode memory with a C-like layout: `u32 magic; f32 pos[3]; char name[16]; ptr next` |
| `read_binary_chunk` | Hexdump by file offset or virtual address |
| `binary_strings` | `strings -t x` on a segment, with regex filter |
| `compare_files` | Byte-level diff of two files |
| `annotate` / `get_annotations` | Labels, comments and notes, saved per build id in `~/.binharness/` and shown in later disassembly |
| `extract_image` | Write the decompressed NSO/NRO image + JSON symbol map for Ghidra/IDA |

**Hand-off to Ghidra/IDA.** `extract_image main out.bin` writes the decompressed image; `export_symbols main --out out` writes `out.ghidra.py` / `out.ida.py`. Load `out.bin` as a flat AArch64 binary at base `0x7100000000`, run the script, and every recovered function, vtable, syscall wrapper and service label is applied.

Stripped Switch sysmodules (no symbol table, statically-linked SDK) are the main target: `list_functions` reconstructs the function layout, `scan_syscalls` shows the kernel interface, and `find_string_refs` gets you from an error message to the code. `extract_image` hands the rest off to Ghidra/IDA.

**Formats.** Switch: NSO (LZ4 segments), NRO, NSP/PFS0, XCI/HFS0, NPDM, SARC, BNTX, BFRES, BFSTM, MSBT, BYML, AAMP. Also ELF, Mach-O, PE, PNG/JPEG/GIF, ZIP/gzip/7z/zstd, SQLite, wasm, GameCube/Wii (DOL, REL, Yaz0, RARC, disc images). NSO/NRO addresses use base `0x7100000000` by default (override with `base`).

NCA files are encrypted. This toolkit does not decrypt them or handle console keys, so give it NSO/NRO files you've already extracted (for example `exefs/main`).

## Codex plugin

```bash
codex plugin marketplace add dougchansan/binharness
codex plugin add hex-viewer@dougchansan
```

Restart Codex, then try *"Show `exefs/main` in the hex viewer"* or *"Find the function that prints the save-data error in main.nso"*.

## deepseek-bin (DeepSeek CLI agent)

```bash
git clone https://github.com/dougchansan/binharness && cd binharness
export DEEPSEEK_API_KEY=sk-...        # https://platform.deepseek.com
node harness/deepseek-bin.mjs exefs/main
```

Interactive session with streaming output, tool-call trace and a running cost line. One-shot mode:

```bash
node harness/deepseek-bin.mjs -p "Find where the game loads its save file and reconstruct that function in C" exefs/main
```

**Recon.** On a stripped module, run the naming passes up front so the agent starts from a named module instead of raw `sub_…`:

```bash
node harness/deepseek-bin.mjs --recon -p "what does this module do?" exefs/main
```

`--recon` (or `/recon <file>` in the REPL) runs `parse_npdm`, `label_rtti`, `label_syscalls` and `label_services` directly — no model tokens — then hands the agent the summary. RTTI alone typically names hundreds to >1000 functions, and the labels persist, so later sessions start oriented too.

| Option | |
| --- | --- |
| `-m deepseek-flash` / `--pro` | Model: `deepseek-flash` (default, cheapest) or `deepseek-v4-pro` |
| `-e none\|low\|high\|max` | Thinking effort (`none` disables thinking) |
| `--show-thinking` | Stream the model's reasoning |
| `--max-steps N` | Tool rounds per task (default 60) |
| `-y` | Allow `extract_image` to write files without asking |

REPL commands: `/model`, `/effort`, `/add <file>`, `/files`, `/cost`, `/save notes.md`, `/reset`, `/exit`. Ctrl-C interrupts the current turn.

**Why it's cheap:** the conversation is append-only, so DeepSeek's prompt cache covers almost every request (cache hits cost ~2% of misses). Tool outputs are capped, and the agent is told to make small, targeted calls. Annotations persist, so the next session starts from what earlier ones learned instead of re-deriving it. Session transcripts are written to `~/.binharness/sessions/`.

### Using the tools from other agents

The MCP server works with any MCP client. For [opencode](https://opencode.ai) with DeepSeek:

```json
{
  "model": "deepseek/deepseek-flash",
  "mcp": {
    "binharness": { "type": "local", "command": ["node", "/path/to/binharness/plugins/hex-viewer/server.mjs"] }
  }
}
```

## Layout

```
.agents/plugins/marketplace.json     Codex marketplace "dougchansan"
plugins/hex-viewer/
  .codex-plugin/plugin.json          plugin manifest
  .mcp.json, server.mjs              stdio MCP server + view_binary UI wiring
  lib/bintools.mjs                   the toolkit (formats, LZ4, AArch64 xrefs, objdump wrapper)
  assets/app.html                    hex viewer UI (MCP App)
  skills/hex-viewer/SKILL.md         tells Codex when/how to use the tools
harness/deepseek-bin.mjs             DeepSeek agent
tests/                               synthetic NSO fixture, mock DeepSeek API, test suite
```

Requires Node 18+ and `objdump` (bundled with macOS Command Line Tools; on Linux install `llvm` for `llvm-objdump` and symlink or alias it as `objdump`). No npm dependencies. Run `npm test` to check your setup.

## License

MIT
