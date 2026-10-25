# Provenance and distribution

This document records what is visible in the repository and public technical
references checked on 2026-10-24. The initial review used v0.6.5, commit
`4cf7675b4dfd78099c2b81565dfb1978f01f948a`. References added during this review are
**cross-checks, not a record of the original implementation sources**. They do
not establish clean-room development or certify the origin of every constant.

See [the distribution audit](docs/distribution-audit.md) for the inspected scope,
packaging checks, results, and remaining limitations.

## Fixtures and other repository material

| Material | Evidence and limits |
| --- | --- |
| [`tests/make-fixture.mjs`](tests/make-fixture.mjs) | Builds `tests/fixture.nso` from allocated buffers, explicit instruction words, chosen strings and symbols, pattern bytes, and constructed NSO metadata. The generator reads no game, firmware, SDK, or downloaded file. Its small LZ4 encoder compresses those constructed segments. |
| [`tests/tools.test.mjs`](tests/tools.test.mjs) | Regenerates the NSO above; also constructs NPDM metadata and a branch-veneer image in memory. The modified-file comparison changes a byte of the generated NSO. The API loop uses the local [`mock-deepseek.mjs`](tests/mock-deepseek.mjs) server. |
| Instruction words and example names | The fixture uses ordinary AArch64 instructions and selected identifiers such as `nnMain` and `SleepThread` to exercise decoding and demangling. These names are test labels; they do not mean the generator supplies the corresponding Nintendo implementation. The history does not record the origin of every identifier. |
| Format layouts, syscall names, and service-name tables | Present as code and constants in [`bintools.mjs`](plugins/hex-viewer/lib/bintools.mjs), [`core.mjs`](plugins/hex-viewer/lib/core.mjs), and [`re.mjs`](plugins/hex-viewer/lib/re.mjs). The checked history does not provide a complete source-by-source attribution record for these tables. The references below make future verification easier without inventing that history. |
| [`docs/screenshot.jpg`](docs/screenshot.jpg) | Legacy hex-viewer UI capture showing a file named `test.dol`, a `GameCube` search hit, and the text `Hello GameCube!`. No input generator or capture procedure is recorded. Its displayed bytes cannot be certified as synthetic from the repository evidence alone. |

The reviewed screenshot has SHA-256
`daefe83721cb6f05334f1c319dac8a5aa0800cdf77008e84adf978160473ef48`.
The distribution guard permits that exact asset in Git as an inventory exception;
the npm package excludes it. This exception records an existing reviewed asset,
not copyright clearance. A replacement image needs a new review and documented
input provenance. The NSO fixture generator does not establish provenance for
this older DOL screenshot.

### Reproduce the test data

From the repository root:

```sh
node tests/make-fixture.mjs
npm test
```

The first command writes the synthetic NSO; the test suite regenerates it too.
The fixture's instructions, symbols, string references, and metadata are chosen
to exercise parser behavior. It is a minimal test input, not a signed title or
evidence of compatibility with every real NSO/NPDM variant. Retain the generator
as the reviewable source; do not replace it with a copied retail binary.

## Public technical cross-checks

These links were checked for the subjects listed, not used to assert complete
implementation conformance. Switchbrew is community reverse-engineering
documentation, **not Nintendo's official specification or permission to use a
Nintendo SDK**. Linked documents retain their own terms and licenses.

| Area in this repository | Public reference and relevant detail |
| --- | --- |
| AArch64 instruction handling in `core.mjs` and the fixture generator | Arm's [A64 Instruction Set Architecture Guide, 1.2](https://documentation-service.arm.com/static/674d8b61c7fc0d1f211dc776), an official overview of A64 registers, addressing, branches, and subroutine calls. Exact decoder masks require instruction-specific verification; this link is not an audit of every encoding. |
| NSO/NRO parsing in `bintools.mjs` | Switchbrew's [NSO0](https://switchbrew.org/wiki/NSO0) and [NRO0](https://switchbrew.org/wiki/NRO0) layout documentation. NSO0 describes separate text/rodata/data segments and optional LZ4 compression; NRO0 documents its header at offset `0x10`. |
| NPDM parsing and synthetic metadata | Switchbrew's [NPDM](https://switchbrew.org/wiki/NPDM), especially ACI0, Service Access Control, and KernelCapability. The service server bit describes permission to register a service; it does not prove a module actually registers or implements it at runtime. |
| Horizon syscall-name lookup | Switchbrew's [SVC table](https://switchbrew.org/wiki/SVC), including `0x0B` / `SleepThread`, the fixture's test case. Firmware annotations in that reference matter; a lookup table is not a version-aware behavioral specification. |
| LZ4 block encoder/decoder | The LZ4 project's [Block Format Description](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md): token fields, literals, match offsets, length extensions, and block-ending conditions. This specifies the format rather than this repository's implementation provenance. |
| RTTI and symbol-name handling | The [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html), sections 2.5 (virtual tables), 2.9 (RTTI), and 5.1 (name mangling). Recovering candidate structures from bytes remains heuristic and does not certify reconstructed classes or function names. |

## Inputs, outputs, and model services

The [MIT license](LICENSE) covers the software and documentation to which the
repository's contributors can grant rights. It does not grant rights to
third-party input files, their contents, or material reproduced from them in an
output. An exported decompressed image contains input bytes. Hex dumps,
disassembly, strings, symbol scripts, reports, and screenshots can also expose
material from the input; generating them does not automatically make that
material MIT-licensed.

The toolkit analyzes supplied files. It does not implement NCA decryption or
console-key handling. That functionality boundary does not certify how an input
was obtained or whether it may be redistributed.

The analysis tools run locally, but `deepseek-bin` sends conversation content
and tool results to its configured API endpoint (DeepSeek by default). Results
can contain file paths, strings, symbols, disassembly, or byte dumps. Recon runs
the tools locally and includes their summaries in model messages. An MCP
client may likewise forward tool results to its model provider. Choose inputs
and endpoint settings accordingly; local file processing does not mean the
result stays on the device. Saved conversations and annotations also need
review before publication.

## Contributions

- For new constants or format knowledge, record the public reference, revision
  or access date, and relevant section near the change. State whether it is a
  factual cross-check or an actual implementation source.
- For reused code, tables, or assets, record the upstream path and revision,
  retain required notices, and check license compatibility. A public URL alone
  is not a license to copy its contents.
- Prefer small fixtures generated from reviewable source. Document every input
  to a generator; for compiler-built examples, include source and build steps.
  Do not add retail binaries, console keys, leaked SDK files, or unexplained
  byte arrays as test shortcuts.
- Record the input and capture procedure for screenshots. Review release
  archives, package contents, reports, and generated scripts as well as source
  files before distributing them. Follow the distribution audit's checks;
  passing a pattern scan is not proof of ownership or permission.
