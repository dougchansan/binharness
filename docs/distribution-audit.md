# Distribution audit

## Scope and initial observations

Reviewed on **2026-10-24**, starting from v0.6.5, commit
`4cf7675b4dfd78099c2b81565dfb1978f01f948a`. This is a distribution-content and
documentation review. It does not establish authorship of every source line,
license compliance for an unknown upstream source, or permission to redistribute
third-party inputs or outputs. See [PROVENANCE.md](../PROVENANCE.md).

The PR subsequently integrated v0.6.6 commit
`7e45146a7bc2faa853c7d3822673cbe52f15f5a4`, preserving its Java GhidraScript
exporter and version updates. Export documentation and generated-file exclusions
cover the Java, Python, and JSON outputs. The starting observations below remain
tied to the original v0.6.5 snapshot rather than silently changing their scope.

| Surface | Observed scope |
| --- | --- |
| Starting Git tree | 22 tracked files. The only non-text file is `docs/screenshot.jpg`. |
| Fetched Git history at the starting commit | 18 commits, 108 distinct path/blob entries, and 22 distinct file paths across the fetched branches and tags. No symlink or submodule entries. |
| Locally built starting npm archive | 10 regular text files. Each archive member was byte-compared with its file at the starting Git commit and matched. No test binary, screenshot, firmware dump, key file, or generated analysis export was included. |
| GitHub releases | The repository's releases endpoint returned an empty list. No release assets were available to inspect. |
| Public npm registry | `npm view binharness versions dist-tags --json` returned E404. No publicly retrievable registry package was available for comparison. This does not establish whether a package was published previously, removed, or distributed elsewhere. |

The locally generated **starting** `binharness-0.6.5.tgz` had SHA-256
`19d8bc3a9d8a6b313669346c7ba5033db0fd1abca79d1beea0eb4bdef51ccecc`.
This hash identifies the archive built during the review; it is not a published
npm artifact or the archive produced after this change.

The screenshot's input/capture provenance remains unverified. Its exact digest
is recorded in PROVENANCE.md and the audit policy. Keeping that digest in the
inventory is an explicit exception for an existing documentation asset, not a
finding that its displayed bytes are independently authored. It is excluded
from the npm package.

## Repeatable checks

Run these commands from a Git checkout:

```sh
npm test
npm run audit:dist
npm run audit:history
npm pack
```

The tests construct synthetic inputs and use a localhost mock model API. The
disassembly tests require LLVM's `objdump` command and a compatible `c++filt` on
PATH; see the [README](../README.md). The distribution checks require Node, npm,
and Git, but no disassembler, console files, credentials, or model API calls.

### Tracked source and npm archive

`npm run audit:dist` checks both the Git index and the working copies of tracked
files, then builds and reads a real npm tarball. It does not rely only on
`.gitignore`, `.npmignore`, a directory listing, or `npm pack --dry-run`.

The archive is created in a temporary directory with lifecycle scripts disabled
for that internal pack operation. The internal command forces a real temporary
archive even when the outer npm command is a dry-run; it never publishes. Its
entries are read without extracting them or executing their contents. Temporary
packaging files are removed afterward.

The policy in [`scripts/dist-policy.json`](../scripts/dist-policy.json) records
the permitted Git and npm paths separately. The guard checks:

- Unreviewed file paths, forbidden dump/key/archive names, and invalid paths.
- Symlinks, submodules, and unsupported archive entry types.
- Strict UTF-8 text, control bytes, file-size limits, and selected executable,
  firmware, and container signatures even when a file has been renamed.
- Selected literal console-key assignment patterns, without printing the
  suspected value.
- The exact digest of the one permitted binary documentation asset.
- Tar entry integrity, duplicate names, unsafe paths, and truncated archives.

The package inventory includes the runtime files, license, README, provenance
note, this audit document, and the audit script/policy. Tests, fixtures, the
screenshot, local environment files, and analysis outputs are not package
contents. Untracked local inputs that do not enter the package are outside this
check's scope; an untracked file that enters the npm archive is still checked.

`npm pack` and normal `npm publish` run the `prepack` gate, which audits a fresh
package archive without requiring a Git checkout. This also supports repacking
an extracted source package. The internal `--ignore-scripts` prevents recursive
prepack execution. Explicitly disabling npm lifecycle scripts bypasses this
hook; CI provides the separate source/history checks.

For machine-readable summaries, append `--json` directly to the script or pass
it through npm, for example `npm run audit:dist -- --json`. The report includes
counts and findings, not suspected key contents. `--package-only` runs just the
archive check.

### Git history

`npm run audit:history` applies the current policy to each distinct path/blob
entry reachable from the locally fetched refs and HEAD. It refuses shallow
history so an incomplete clone is not reported as a complete history check.
Fetch the branches and tags you intend to cover before running it. The workflow
uses a full-depth checkout.

`retiredGitFiles` records reviewed source paths that were legitimately removed or
renamed. Those paths are permitted only in historical trees; they are not
required in the current checkout or allowed into the package. Historical files
still receive the same content checks and binary-digest restrictions.

This does not inspect deleted remote refs, unreachable objects, other people's
forks, private releases, external download mirrors, or a previously removed npm
package. A current-tree pass is not a substitute for this history check.

### CI and policy changes

The [Distribution audit workflow](../.github/workflows/distribution-audit.yml)
runs the synthetic tests, audit regression tests, source/package audit, history
audit, and prepack hook on Node 18 and 24. It has read-only repository
permissions and does not publish or upload packages. Adding the workflow does
not itself configure branch-protection requirements.

When adding a source file, review its provenance and distribution purpose, then
update the appropriate inventory in `scripts/dist-policy.json`. A new npm entry
must also be intentionally included by `package.json`. When removing or renaming
a reviewed source file, move its old path from `gitFiles` to `retiredGitFiles`
so retained history can still be checked. Do not add a broad path exception to
make an unexplained dump pass. New binary documentation assets need a documented
source and capture/generation procedure plus an exact digest.

## Validation recorded for this change

Local validation used Node 24.22.1, npm 11.9.0, and LLVM `objdump` reporting
20.1.2. No real game/firmware input or live model API was used.

| Check | Result |
| --- | --- |
| Synthetic tool and audit regression suite | 32 tests passed, none skipped. |
| Staged/working source and real npm archive | Passed: 28 source paths, 14 package files. |
| Starting fetched history | Passed: 18 commits and 108 distinct path/blob entries. |
| Prepack from the checkout and an extracted package without Git | Passed; the archive round trip produced identical bytes in that check. |
| `npm pack --dry-run` with prepack enabled | Passed; the inner temporary archive was inspected and no outer archive was created. |
| Bundled skill validation and whitespace checks | Passed. |

Regressions cover included untracked inputs, renamed binaries, literal key
patterns, changed asset digests, source symlinks, unsafe/duplicate/truncated tar
entries, staged content differing from cleaned working files, removed historical
binaries, shallow clones, inherited dry-run settings, and legitimate source
renames/deletions. The Node 18/24 workflow provides continuing CI coverage; the
local results above do not assert an unobserved hosted CI result.

## Accuracy corrections in this change

- Separate format recognition from implemented NSO/NRO loaders, container
  listings, raw-byte inspection, and architecture-specific analysis.
- Describe function recovery, RTTI, service references, diagnostic names, and
  syscall scanning as bounded static analysis rather than complete recovery.
- Describe NPDM ACI0 service lists as declarations of permissions. They do not
  prove runtime service use, an implementation's identity, verified ACID
  signatures, or effective authorization.
- Explain which tools write annotations or exports, and correct their MCP
  read-only hints.
- Document model API transmission of analysis results, heuristic reconstruction,
  local annotation/session files, and the CLI's limited write-confirmation scope.
- Replace guaranteed pricing/cache claims with identified hardcoded estimates;
  distinguish local recon work from the subsequent model request.
- Use verified checkout/local-node instructions. Registry manifests remain
  publication metadata, not evidence of a live registry listing.

## Subsequent additions (2026-10-25)

The Kimi integration added three tracked text files, now included in the reviewed Git inventory. The NSO hashing and ZBIC interoperability work adds a text-only runtime module and a new synthetic/optional independent comparison suite. The runtime module is included in npm; the tests, helper executable, ZBIC frames, keys, and generated outputs are not. Distribution checks cover the updated inventory. This does not retroactively alter the initial v0.6.5 snapshot.

## What a pass means

A pass means that the inspected source/archive fits this reviewed inventory and
the implemented byte, name, and structure checks. It is not a copyright detector,
a comprehensive secret scanner, or an exhaustive file-format validator. Textual
code copied from an unknown source, encoded data inside source files, and
unrecognized sensitive formats can evade these mechanical checks. Review
provenance and generated outputs separately. Changing the policy or disabling
the checks can also change the result; the guard is intended to catch mistakes
and make distribution changes reviewable.
