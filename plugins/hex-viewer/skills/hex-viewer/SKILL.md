---
name: hex-viewer
description: Use when the user wants to view, inspect, or look inside a binary file (executables, object files, images, archives, ROM/ISO data, .dol/.rel/.bin, etc.) or when a file preview says binary files aren't supported.
---

Call the `view_binary` tool with the file's absolute path (and optional `offset`) to open it in the interactive hex viewer. The viewer pages through the rest of the file itself, so don't re-call the tool just to scroll.

Use `binary_strings` to pull printable strings, and `read_binary_chunk` when you need specific bytes for your own reasoning (it returns a text hexdump).
