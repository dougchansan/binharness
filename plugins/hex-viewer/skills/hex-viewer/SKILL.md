---
name: hex-viewer
description: Use when the user wants to view, inspect, or reverse engineer a binary file (Switch NSO/NRO/NSP/XCI, executables, object files, ROM/ISO data, game assets, .bin/.dol/.rel) or when a file preview says binary files aren't supported.
---

- **Show a file**: Call `view_binary` in a client supporting MCP Apps. Let the viewer page through the file; do not re-call it to scroll.
- **Get your bearings**: Start with `file_info`. Use NSO/NRO segments and available symbols, NSP/XCI container listings, or NPDM declarations. Treat other recognized formats as raw bytes unless a structured reader is documented. For encrypted NCA analysis, request an NSO/NRO the user is authorized to analyze; this toolkit provides no decryption or console keys.
- **Check NSO integrity**: Call `verify_nso` for enabled SHA-256 checks, mismatches, and absent flags. `extract_image` blocks declared mismatches by default. ZBIC requires a user-installed `BINHARNESS_BEETOOL` executable; neither a decoder nor console keys are bundled.
- **Find code**: Use `find_string_refs` for matching strings and detected AArch64 references, `list_symbols` for dynsym/saved labels, and `search_bytes` for hex patterns with `??` wildcards.
- **Map stripped modules**: Use `list_functions` for estimated boundaries and `call_graph` for detected direct AArch64 calls. Treat `scan_syscalls` as instruction presence and `find_services` as service-string references, not evidence of runtime activity or service ownership.
- **Infer names**: Inspect `find_rtti` before saving candidate RTTI labels with `label_rtti`. Use `label_syscalls` for candidate wrappers, `label_services` for eligible service-reference labels, and `label_from_strings` for diagnostic-name candidates. These tools save inferred annotations; verify their evidence and do not describe them as complete original symbols.
- **Read declarations**: Use `parse_npdm` on `main.npdm` to read ACI0 program/service/kernel declarations. State that ACID signatures are not verified, declared permissions are not proof of effective authorization, and allowed services/syscalls need not be used.
- **Read code**: Use `disassemble` by address or symbol; follow supported AArch64 branch/data references with `find_xrefs`. Use `arch: "x86-64"` for x86-64 instruction disassembly only; the reference/function heuristics remain AArch64-specific.
- **Read data**: Use `decode_struct` with a C-like layout and `read_binary_chunk` for bytes (`address` for NSO/NRO virtual addresses, `offset` for file offsets).
- **Record findings**: Save evidence and uncertainty with `annotate`, then review with `get_annotations`. Labels persist under `~/.binharness/` and appear in later analysis.
- **Export analysis**: Call `extract_image` with `path` and `out`; call `export_symbols` with `path`, an `out` prefix and `format`. These are MCP tools, not shell commands. Ghidra export writes a Java GhidraScript named from the sanitized output basename plus `_ghidra.java`, and a `.ghidra.py` alternative; `both` also writes `.ida.py`. Prefer the Java route for Ghidra; the Python alternative needs a compatible Python integration. Load the image at its recorded base, run the script, and review labels/import warnings.
- **Preserve provenance**: Treat decompressed images and reconstructed C/C++ as derived from their inputs. Check provenance and rights before publishing outputs. Account for the connected client's handling of tool results; the standalone agent sends extracts to its configured model API.

Addresses are hex strings; NSO/NRO default base is 0x7100000000.
