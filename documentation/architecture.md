# OpenCTF architecture

OpenCTF is one inspection kernel with several surfaces. The kernel owns every
fact; the command line, the TypeScript session and the Studio only render what
it returns. The product framing is a CTF toolbox, so the modules are grouped by
challenge action — identify, triage packing, recover text, unpack a container,
decode code, patch a copy — while each module stays one orthogonal decode.

Three Rust crates split the kernel by ownership: `ctf-domain` (challenge model,
evidence, candidates, report, workflows), `ctf-solvers` (algorithms) and
`ctf-formats` (format projections). The binding (`ctf-napi`) forwards JSON and
owns nothing else.

## Components

| Layer     | Crate or package                                                  | Responsibility                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|-----------|-------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Domain    | `../projects/crates/ctf-domain` (`open-ctf-domain`)               | The product: `Challenge`, `Candidate`/`CandidateSet`, `Evidence`/`EvidenceKind`, `ChallengeReport`, the stable `CtfError`, the `OpenCtf`/`BinaryView` session facade, and the workflow orchestration in `workflow/{identify,triage,solve,verify}.rs`. Product-side byte operations (`text`, `find`, `dump`, `carve`, `diff`, `entropy`) keep only the projection; their observation calls the pinned `data-binary-inspect`. |
| Solvers   | `../projects/crates/ctf-solvers` (`open-ctf-solvers`)             | CTF algorithms: Caesar, single-byte XOR, de Bruijn cyclic patterns, text/byte decoders, digests, JWT decoding and URL decomposition. No format parsing, no report assembly. |
| Formats   | `../projects/crates/ctf-formats` (`open-ctf-formats`)             | Format projections. `src/owners.rs` opens the session, calls the pinned owner and projects the owner type onto the existing report shape for PE, ELF, Mach-O and the pyc/PyInstaller/NSIS/asar/Tauri containers; it contains no parser. The product-local modules that remain are `pcap`, `png`, `packer`, `overlay`, `unpack`, `gadgets`, `disasm`, `probe` and `inflate`, each with its reason in `duplication.md`. |
| Upstream  | `data-binary-inspect`, `data-binary-pe`, `data-binary-mach-o`, `data-binary-container`, `data-binary-x64`, `data-compression` | Container detection, headers, sections, imports, exports, symbols, search, hex dumps, byte ranges, diff, entropy, encoded strings, address mapping, atomic patching, PE/ELF fact readers, Mach-O headers/segments/sections/exports/fixups/signatures, Python bytecode and PyInstaller/NSIS/asar/Tauri containers, x86/x64 instruction decoding, the bounded DEFLATE/zlib/gzip envelopes, and the Brotli (RFC 7932) decoder. Pinned at `3e865d5c`; `data-compression` is consumed with the `deflate` and `brotli` features and `data-binary-x64` with `decode`. |
| Binding   | `../projects/crates/ctf-napi` (`open-ctf-napi`)                   | JSON-in / JSON-out Node-API exports plus the WebView host. `commands/{binary,challenge,solver}.rs` forward only; `error.rs` owns the envelope; `lib.rs` owns the handle table. No inspection policy. |
| SDK       | `projects/packages/open-ctf/src`                                  | `OpenCTF` session, report types, stable error translation, addon discovery. |
| CLI       | `projects/packages/open-ctf/src/cli.ts`                           | Argument parsing and rendering only. |
| Studio    | `projects/packages/open-ctf-ui`                                   | VMZ static shell; empty when no host is connected. |
| Skill     | `projects/packages/open-ctf-skills`                               | Agent instructions; no code. |

## Ownership and directory rules

| Path                                        | Owns                                                                 | Must not contain                              |
|---------------------------------------------|----------------------------------------------------------------------|-----------------------------------------------|
| `ctf-domain/src/{challenge,candidates,evidence,report,error}.rs` | Product model, ranking, evidence log, report, stable failure | A second parser, a format decode, a solver    |
| `ctf-domain/src/workflow/`                  | Identify, triage, solve, verify orchestration                        | Format facts, byte parsing                    |
| `ctf-domain/src/{text,find,diff,entropy,dump,carve}.rs` | Product projection over the pinned `data-binary-inspect` byte observation (options, paging, report shape) | Format-specific decoding, a second byte scanner |
| `ctf-solvers/src/`                          | One algorithm per file; behavior-identical to the old kernel         | Format parsing, report assembly               |
| `ctf-formats/src/`                          | One container/image/capture/archive per file                         | Workflow policy, ranking, reporting           |
| `ctf-napi/src/lib.rs`                       | `#[function]` entry points and the live handle table                 | Business logic, byte parsing, scoring         |
| `ctf-napi/src/error.rs`                     | Argument extraction and the `code: message` envelope                 | Domain policy                                 |
| `ctf-napi/src/commands/`                    | One forwarding body per operation                                    | Anything that reads bytes itself              |
| `*/tests/`                                  | Assertions, grouped by the crate that owns the fact                  | `#[cfg(test)]` modules inside `src/`          |

Rules:

- A module belongs to the crate that owns its fact, not to the crate that calls
  it. `ctf-domain` calls `ctf-formats` and `ctf-solvers`; the reverse never
  happens.
- `ctf-domain/src/lib.rs` declares modules and re-exports public types only.
- `ctf-formats` and `ctf-solvers` do not depend on each other. They surface the
  upstream `InspectError` re-exported as `CtfError`, and `ctf-domain::error`
  converts it losslessly at the boundary.

## Call path

```text
open-ctf <command>
  -> src/cli.ts parses flags
  -> new OpenCTF({ path })
  -> src/native.ts requires @wae/open-ctf-<platform>-<arch>
  -> open-ctf-napi maps JSON onto open-ctf-domain / open-ctf-formats / open-ctf-solvers
  -> JSON report
  -> CLI renders text, or the SDK returns typed data
```


The SDK and CLI never read the file themselves. A missing addon is a declarative
state: `capabilities()` and every constructor answer
`capability/not-implemented` instead of returning an empty report.

## Determinism and bounds

- Every report is a pure function of the opened bytes and the request options.
- Hash values come from one upstream digest implementation; `diff` reuses the
  hashes already reported by `info` instead of growing a second convention.
- Listings are bounded by constants in the owning modules (the session defaults
  live on `OpenCtfOptions`):
  string scans default to 100 hits and cap at 10,000, disassembly defaults to 64
  instructions and caps at 4,096, and diff keeps at most 64 differing ranges.
  Reports carry `total` and `truncated` so a caller can tell a complete answer
  from a cut one.
- `diff.comparedBytes` is the shorter of the two file sizes. Two files of
  different lengths are never reported as identical.

## Address model

- A file offset is the byte position inside the file.
- An RVA is a PE image-relative address; a VA is an absolute virtual address.
- `rva <file> <address>` accepts a PE RVA or an ELF virtual address and maps it
  to a file offset.
- `offset <file> <offset>` always reports a VA and additionally reports an RVA
  when the format has one. ELF has no PE RVA, so the CLI reports `rva: null`.

## Patching

Patching is delegated to the upstream session, which writes atomically and
reports the whole-file hash before and after. OpenCTF adds no second writer:

- A range that does not fit the file is rejected with `binary/range` and the
  file is unchanged.
- `patch(offset, data)` without an output path patches the source in place.
- `patch(offset, data, output)` writes a patched copy and leaves the source
  untouched. The CLI exposes the same choice through `--out`.

## Error contract

`ctf-domain/src/error.rs` owns the product failure: `CtfError` carries a stable
`code` and a message, and `Result<T>` is its alias. `ctf-formats` and
`ctf-solvers` surface the upstream `InspectError` re-exported under the same
`CtfError` name, so a format or solver failure crosses the domain boundary
through `From<InspectError>` without a second code set. The shared
`data-binary-inspect::InspectError` re-export path stays stable: the migrated
byte-observation modules return the same owner errors (`binary/parse`,
`binary/range`, `binary/unsupported`, `binary/io`) and the domain converts them
once. `src/errors.ts` on the TypeScript side defines the complete code set;
`translateNativeError` splits the prefix, keeps the code and drops it from the
message.

| Code                         | Meaning                                                       |
|------------------------------|---------------------------------------------------------------|
| `binary/parse`               | The file is not a decodable container.                        |
| `binary/range`               | An offset or length is outside the file.                      |
| `binary/unsupported`         | The format or architecture is recognised but not implemented. |
| `binary/io`                  | Reading, writing or an unexpected failure.                    |
| `handle/invalid`             | The session handle is closed or unknown.                      |
| `capability/not-implemented` | The addon is absent or the route is declared unsupported.     |

Codes are contract. Callers branch on `code`, never on message text.

## Capability status

`capabilities()` is the only support claim; it is assembled in
`ctf-domain/src/report.rs`. The ownership status of each capability is separate
from its support status:

| Status          | Meaning                                                                 | Where it is recorded |
|-----------------|-------------------------------------------------------------------------|----------------------|
| migrated        | The fact is read from the pinned Boost owner, with no copy in this repo | Upstream table above and `duplication.md` |
| product-local   | No owner today; the byte logic is product-side until a later pass       | `documentation/duplication.md` |

The six byte-observation modules (`diff`, `find`, `text`, `dump`, `entropy`,
`carve`) are **migrated** at the pinned revision above. `find` keeps a regex
matcher for patterns the owner cannot express as literals; `text` keeps the
`ascii`/`utf16le`/`both` switch and paging. The DEFLATE call in `inflate` and
`png` is **migrated** to `data-compression` (`Envelope::Raw` /
`Envelope::Zlib`); `miniz_oxide` was deleted from the workspace. The Brotli and
DEFLATE decoders of NSIS, PyInstaller and Tauri now live inside
`data-binary-container`, and the third-party `brotli` crate was deleted, so no
third-party Brotli implementation remains in the dependency graph.

The PE, ELF, Mach-O and container format modules are now **migrated** as well.
The 23 module paths (33 files) whose parsers moved upstream were deleted;
`ctf-formats/src/owners.rs` calls `data-binary-pe::pe`, `data-binary-pe::elf`,
`data-binary-mach-o::mach_o` and `data-binary-container` and projects the owner
types onto the existing reports without renaming a field. `disasm` calls
`data-binary-x64::decode` and `probe` calls `data-binary-probe`. `iced-x86` was
deleted from both manifests and `Cargo.lock`; `cargo tree -e normal,build,dev -i
iced-x86` matches no package. The remaining `ctf-formats` modules are
**product-local**: `pcap`, `png`, `packer`, `overlay`, `unpack`, `gadgets`,
`disasm`, `probe` and `inflate` keep only CTF policy and report shape, with the
reason recorded in `duplication.md`.

Standard hex/base64 text conversions now call `boost_crypto::encoding`, the
existing boundary that delegates base64 to `data-encoding`. `data-encoding` is
still transitive, so no direct dependency was added; `inflate`/`overlay` keep
their space-separated display format, and `png` stays product-side until a
`data-binary-png` owner wiring pass.

A format may be classified and still unsupported, and a suffix is never treated
as a support claim. Mach-O is `partial`: headers, load commands, segments, sections, dylibs, build versions,
the `LC_SYMTAB` symbol table, the `LC_FUNCTION_STARTS` delta table, the dyld
export trie, the `LC_ENCRYPTION_INFO(_64)` crypt range and the
`LC_DYLD_CHAINED_FIXUPS` imports/starts table and the classic dyld bind,
weak-bind and lazy-bind opcode streams (`macho-bindings`) are decoded, but the
rebase stream and chained-pointer decoding are not; fat
containers expose their architecture table through `macho-slices`, and
`macho-extract` writes one slice that the thin-image reports can reopen. Decompilation and debugging are
explicitly `not-implemented`; Mach-O import bindings are `partial` because the
bind opcode streams are decoded while nothing is bound at runtime. ARM and ARM64 disassembly
returns `binary/unsupported` instead of decoding with a guessed mode.

## Test strategy

Tests are grouped by the crate that owns the assertion, never by the surface
that renders it:

| Suite                                    | Covers                                                                    |
|------------------------------------------|---------------------------------------------------------------------------|
| `ctf-formats/tests/projections.rs`       | Format facts: headers, sections, directories, Mach-O load commands, PE resources, unpacking, Python bytecode, pcap/png, opcode tables, and Tauri assets against fixed Node.js Brotli vectors |
| `ctf-solvers/tests/algorithms.rs`        | Solver ranking, previews and failure codes                                |
| `ctf-solvers/tests/fixtures.rs`          | Fixture corpus identity (recorded SHA-256) and NIST digest vectors        |
| `ctf-domain/tests/challenge.rs`          | `Challenge` classification, identify evidence, missing-file failure       |
| `ctf-domain/tests/candidate.rs`          | Candidate ranking, deduplication and report conversion                    |
| `ctf-domain/tests/workflow.rs`           | Session defaults, capability matrix, patch, strings, search, find, dump, carve, diff, entropy, triage/solve/verify |

No test module lives inside `src/`; `#[cfg(test)]` is not used. Format tests may
reach the session facade through a dev-dependency on `open-ctf-domain` — that
edge exists only for tests and never for the library build.
