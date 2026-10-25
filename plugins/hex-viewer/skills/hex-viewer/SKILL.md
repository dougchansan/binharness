---
name: hex-viewer
description: Use when the user wants to view, inspect, or reverse engineer a binary file (Switch NSO/NRO/NSP/XCI, executables, object files, ROM/ISO data, game assets, .bin/.dol/.rel) or when a file preview says binary files aren't supported.
---

- **Show the user a file**: `view_binary` opens the interactive hex viewer (it pages through the file itself; don't re-call it to scroll).
- **Get your bearings**: `file_info` first. For NSO/NRO it reports segments, build id, module path and symbol counts; for NSP/XCI it lists contained files. NCA files are encrypted and unsupported; ask for extracted NSO/NRO.
- **Find code**: `find_string_refs` (log/error strings → the functions that use them), `list_symbols` (demangled dynsym + saved labels), `search_bytes` (hex with `??` wildcards).
- **Map the code** (stripped modules): `list_functions` reconstructs function boundaries, `call_graph` shows callers/callees, `scan_syscalls` decodes `svc #n` into Horizon kernel calls, `find_services` lists the IPC services (fsp-srv, set:sys, …) a module uses.
- **Name things automatically**: `label_syscalls` names the `svc` wrappers; `label_services` labels the functions that use each service. Both save annotations that then show everywhere.
- **Read code**: `disassemble` by address or symbol name; output annotates call targets and ADRP+ADD/LDR data refs with string previews. Follow callers with `find_xrefs`.
- **Data**: `decode_struct` with a C-like layout, `read_binary_chunk` for raw bytes (`address` for NSO/NRO virtual addresses, `offset` for file offsets).
- **Remember**: `annotate` labels/comments/notes as soon as you understand something; they persist per build id and show up in later disassembly. `get_annotations` to review.
- `extract_image` writes a flat decompressed image + JSON symbols for Ghidra/IDA (never overwrites).

Addresses are hex strings; NSO/NRO default base is 0x7100000000.
