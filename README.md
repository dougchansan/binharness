# Hex Viewer for Codex

View binary files as an interactive hex dump right inside Codex — for when the file pane says *"Binary file previews aren't supported yet."*

![Hex Viewer showing a GameCube DOL with a search hit and the byte inspector](docs/screenshot.jpg)

## Install

```bash
codex plugin marketplace add dougchansan/codex-hex-viewer
codex plugin add hex-viewer@dougchansan
```

Restart the Codex app, then ask something like:

> Show `build/main.dol` in the hex viewer

## Features

- **Hex + ASCII grid** that pages through files of any size on demand (16 KiB chunks)
- **Go to offset** (`0x2a000` or decimal) and **find** hex bytes (`de ad be ef`) or `"text"`
- **Byte inspector**: u8/s8/binary, u16/s16/u32/s32/hex32/f32/f64 in big- and little-endian
- **Format detection**: ELF, Mach-O, PE, PNG, JPEG, GIF, RIFF, ZIP, gzip, 7z, PDF, SQLite, zstd, wasm, ar, plus GameCube/Wii formats (DOL, REL, Yaz0/Yay0, RARC, U8, GCM/Wii disc images, J3D, BRRES)
- Keyboard navigation (arrows, PageUp/PageDown, Home/End), light and dark themes

## Tools

| Tool | What it does |
| --- | --- |
| `view_binary` | Opens a file in the interactive viewer (MCP App). Also returns a text summary + first 256 bytes for the model. |
| `read_binary_chunk` | Returns up to 64 KiB of a file as a text hexdump or base64. |
| `binary_strings` | Lists printable strings with offsets, like `strings -t x`. |

## How it works

Codex plugins can't extend the built-in file preview, so this ships as an [MCP App](https://modelcontextprotocol.io/): a dependency-free Node MCP server (`server.mjs`) plus a single-file HTML viewer (`assets/app.html`) that Codex renders inline in the conversation. The viewer fetches more bytes through the host as you scroll. All reads are local and read-only.

```
.agents/plugins/marketplace.json     marketplace "dougchansan"
plugins/hex-viewer/
  .codex-plugin/plugin.json          plugin manifest
  .mcp.json                          MCP server launch config
  server.mjs                         stdio MCP server (no npm deps)
  assets/app.html                    viewer UI
  skills/hex-viewer/SKILL.md         tells Codex when to use it
```

Requires Node 18+ (Codex supplies its own Node when available).

## License

MIT
