# OpenCTF agent reference

How an agent discovers capabilities, drives the `open-ctf` CLI and interprets
the stable error surface. The CLI is the automation surface; the SDK (`@wae/open-ctf`) exposes the same calls with typed
reports.

OpenCTF is the binary and container half of a CTF toolbox. Work a challenge in
cost order: `info` and `entropy`, then `overlay`, then `strings --encoding both`,
then `unpack` for an embedded container, then `disasm` (machine code or
`--format pyc`), then `find` / `carve` / `dump` once a region is suspected.
Crypto, steganography and web exploitation are out of scope, and the matrix is
the only support claim that counts.

## Repository map

| Crate                       | Owns                                                                | Tests |
|-----------------------------|---------------------------------------------------------------------|-------|
| `ctf-domain` (`open-ctf-domain`) | `Challenge`, `Candidate`/`CandidateSet`, `Evidence`, `ChallengeReport`, `CtfError`, the `OpenCtf`/`BinaryView` session, the byte-observation projections over the pinned `data-binary-inspect`, and `workflow/{identify,triage,solve,verify}` | `tests/{challenge,candidate,workflow}.rs` |
| `ctf-solvers` (`open-ctf-solvers`) | Caesar, XOR, cyclic, decoders, digests, JWT, URL                | `tests/{algorithms,fixtures}.rs` |
| `ctf-formats` (`open-ctf-formats`) | pcap, png, packer, `archive` (ASAR) and the pending copies of Boost format owners | `tests/projections.rs` |
| `ctf-napi` (`open-ctf-napi`) | JSON-in/JSON-out exports, the handle table, the WebView host       | no tests; the surface is asserted through the CLI/SDK |

Rules an agent must not break:

- A fact belongs to the crate that owns it: format facts in `ctf-formats`,
  algorithm behavior in `ctf-solvers`, product workflow and ranking in
  `ctf-domain`. Do not add a parser to `ctf-domain` or a workflow to
  `ctf-formats`.
- `ctf-formats` and `ctf-solvers` never depend on each other or on
  `ctf-domain`; they surface the upstream `InspectError` re-exported as
  `CtfError`.
- Assertions live in `tests/`, never in a `#[cfg(test)]` module under `src/`.
  A format-fact assertion goes to `projections.rs`, an algorithm assertion to
  `algorithms.rs`, a product-workflow assertion to `workflow.rs`.
- `documentation/duplication.md` is the ledger of modules that still copy a
  Boost owner. If you fix or extend one, keep its `TODO(boost): owner migration`
  marker and update the table.
- The six byte-observation projections in `ctf-domain` (`diff`, `find`, `text`,
  `dump`, `entropy`, `carve`) must not grow a local scanner again. Call the
  pinned `data-binary-inspect` revision recorded in `duplication.md`; only
  product policy (options, paging, evidence, report shape) belongs there.
- Standard hex/base64 text conversions go through `boost_crypto::encoding`,
  which is the data-encoding-backed boundary. Do not hand-roll another hex loop
  and do not add `data-encoding` as a new external crate; `inflate`/`overlay`
  space-separated windows are display policy and stay as-is.

## Capability status

The matrix in `capabilities()` is the support claim; ownership is separate:

- **migrated** — read from the pinned Boost owner, no copy here. `diff`, `find`,
  `text`, `dump`, `entropy` and `carve` are here: their options, paging and
  report shape stay product-side, but the byte observation calls
  `data-binary-inspect` and the compression decoders call `data-compression`,
  both pinned at `f191fdc4134a5be749f289315dfcacc7c4ad9200`. The DEFLATE family
  in `inflate`, `nsis`, `pyinstaller` and `png` is migrated the same way to
  `data-compression`; the Brotli decode of `tauri` is `Brotli::decode_bounded`.
  `miniz_oxide` and the third-party `brotli` crate are no longer dependencies.
  In `ctf-formats`, `disasm` calls `data-binary-x64::decode` (behind the
  `decode` feature), `elf_symbols` calls `data-binary-pe::elf`, and
  `macho/symbols` calls `data-binary-mach-o`; `probe` uses
  `data-binary-probe`. `iced-x86` was deleted from the manifests and
  `Cargo.lock`, so `cargo tree -e normal,build,dev -i iced-x86` is empty.
- **duplicated** — a copy of an owner that exists; marked
  `TODO(boost): owner migration` and listed in `documentation/duplication.md`
  together with the missing field that keeps it product-side. The remaining 29
  `ctf-formats` modules are here.
- **product-local** — no owner today; it moves upstream in a later wiring pass.

A duplicated or product-local capability is still a truthful answer: never call
it unsupported, and never claim it is migrated.

The shared `data-binary-inspect::InspectError` re-export path is part of the
contract: migrated modules and format projections return that error unchanged,
and `ctf-domain/src/error.rs` converts it once into `CtfError`. `find` keeps a
byte-regex matcher for patterns the owner cannot express as literals; plain
literal patterns call `find::find`.


## Capability discovery

Start every task with the matrix, not with a file extension:

```bash
open-ctf capabilities
```

The matrix reports `formats`, `features`, `unsupported` and `architectures`.
`partial` is not full support, and `unsupported` is a truthful answer rather than
a failure. A classified container can still be unsupported: fat Mach-O
containers are rejected, and unknown containers are rejected.

## Routes

| Route                       | Command                                                             | Evidence                                                                     |
|-----------------------------|---------------------------------------------------------------------|------------------------------------------------------------------------------|
| Identify                    | `open-ctf info <file>`                                              | Format, architecture, entry, image base, hash                                |
| Map sections                | `open-ctf sections <file>`                                          | Address, file range and r/w/x per section                                    |
| Find text                   | `open-ctf strings <file> --encoding both`                           | Offset and length per run                                                    |
| Read bytes                  | `open-ctf hexdump <file> --offset <n> --length <n>`                 | Canonical hex dump                                                           |
| Resolve addresses           | `open-ctf rva <file> <address>` / `open-ctf offset <file> <offset>` | Offset, RVA and VA                                                           |
| Inspect linkage             | `open-ctf imports\|exports\|symbols <file>`                         | Module, symbol, ordinal, address                                             |
| Recover PDB path            | `open-ctf debug <file>`                                             | CodeView signature, GUID or NB10 record, path                                |
| Read product metadata       | `open-ctf version <file>`                                           | File/product version and `StringFileInfo` pairs                              |
| Profile Mach-O              | `open-ctf macho <file>`                                             | UUID, platform, min OS/SDK, dylibs, segments, sections, entry                |
| Check PE hardening          | `open-ctf mitigations <file>`                                       | ASLR, DEP, CFG, GS, W+X, relocations, certificate presence                   |
| List PE resources           | `open-ctf resources <file>`                                         | Type, name, language, RVA and size per leaf                                  |
| List PE relocations         | `open-ctf relocations <file>`                                       | Page RVA, entry count and fixup types per block                              |
| List PE runtime functions   | `open-ctf exception <file>`                                         | Begin/end RVA, unwind info and decoded x64 unwind header                     |
| List PE delay imports       | `open-ctf pe-delay-imports <file>`                                  | Module name, timestamp and per-thunk INT/IAT RVAs with name, hint or ordinal |
| List PE bound imports       | `open-ctf pe-bound-imports <file>`                                  | Descriptor timestamp, module name and inline forwarder refs                  |
| Decode PE Rich header       | `open-ctf pe-rich-header <file>`                                    | XOR key, DanS/Rich offsets and compid/build/count entries                    |
| Read ELF dependencies       | `open-ctf dynamic <file>`                                           | Interpreter, SONAME, needed libraries, rpath/runpath                         |
| List ELF static symbols     | `open-ctf elf-symbols <file>`                                       | `.symtab` name, value, size, type, binding, visibility and section           |
| List ELF program headers    | `open-ctf segments <file>`                                          | Segment type, offset, addresses, sizes, permissions and alignment            |
| Read ELF notes              | `open-ctf notes <file>`                                             | GNU build id, ABI tag, GNU properties                                        |
| List PE certificates        | `open-ctf certificates <file>`                                      | Attribute certificate table headers, `PKCS#7` shape (not verified)           |
| Read PE TLS                 | `open-ctf tls <file>`                                               | Raw range, index slot, zero fill and mapped callback addresses               |
| Read PE load config         | `open-ctf load-config <file>`                                       | Security cookie, SEH table, CFG metadata and decoded guard flags             |
| Read Mach-O code signature  | `open-ctf code-signature <file>`                                    | Blob table and CodeDirectory fields (not verified)                           |
| List fat slices             | `open-ctf macho-slices <file>`                                      | CPU, architecture, offset, size and alignment per slice                      |
| Extract a fat slice         | `open-ctf macho-extract <file> --index <n> --out <file>`            | Writes one slice; the source is never overwritten                            |
| List Mach-O symbols         | `open-ctf macho-symbols <file> --limit <n>`                         | Name, address, kind, section and flags per `LC_SYMTAB` entry                 |
| List Mach-O function starts | `open-ctf macho-function-starts <file> --limit <n>`                 | Absolute addresses decoded from `LC_FUNCTION_STARTS`                         |
| List Mach-O exports         | `open-ctf macho-exports <file>`                                     | Dyld export trie names, flags, addresses and ordinals                        |
| Read Mach-O encryption      | `open-ctf macho-encryption <file>`                                  | `LC_ENCRYPTION_INFO` crypt offset, size and cryptid                          |
| Read Mach-O chained fixups  | `open-ctf macho-chained-fixups <file>`                              | `LC_DYLD_CHAINED_FIXUPS` imports, header and starts table                    |
| Decode Mach-O bind opcodes  | `open-ctf macho-bindings <file>`                                    | Classic dyld bind, weak-bind and lazy-bind opcode streams                    |
| Decode code                 | `open-ctf disasm <file> [--format auto\|x86\|pyc]`                    | Address, offset, bytes, mnemonic; bytecode code objects and instructions     |
| Triage packing              | `open-ctf entropy <file>`                                           | Whole-file and section entropy, PE overlay                                   |
| Compare builds              | `open-ctf diff <left> <right>`                                      | First difference and differing ranges                                        |
| Search patterns             | `open-ctf search <file> <pattern> --mode hex\|ascii\|utf16le`       | Offset and preview                                                           |
| Search byte regexes         | `open-ctf find <file> --pattern <regex> [--ignore-case]`            | Offset, length and printable preview per match                               |
| Export raw bytes            | `open-ctf dump <file> --offset <n> --length <n> --output <path>`    | Applied length and written byte count                                        |
| Extract printable blobs     | `open-ctf carve <file> --marker <regex> [--out <dir>]`              | Region offset, length, preview and written file per match                    |
| Recover Tauri assets        | `open-ctf tauri-assets <file> [--out <dir>]`                        | Key, blob offset, compressed/decompressed size and written file per asset    |
| Patch                       | `open-ctf patch <file> --offset <n> --bytes <hex> --out <copy>`     | Before/after whole-file hashes                                               |

## Limits agents must respect

- `strings` defaults to 100 hits; the engine caps a request at 10,000, or at
  2,000,000 with `--all`. `--skip <n>` drops leading hits before the limit.
- `find` defaults to 100 matches; the engine clamps `--limit` to 5,000 and
  `--context` to 512 bytes. An invalid pattern is `binary/parse`.
- `dump` exports at most 64 MiB per request; a range outside the file is
  `binary/range` and nothing is written.
- `carve` defaults to 20 examined matches; the engine clamps `--limit` to 100.
  Regions shorter than `--min` (200 bytes) are dropped; expansion caps are
  `--expand-left` 4,096 and `--max` 262,144 bytes. An invalid marker is
  `binary/parse`.
- `tauri-assets` defaults to 200 assets; the engine clamps `--limit` to 1,000.
  A PE without an interleaved Tauri asset table answers an empty report; a
  non-PE input is `binary/parse`. Each asset blob must decode as one complete
  Brotli stream that consumes its declared length; trailing bytes reject the
  record.
- `disasm` defaults to 64 instructions and caps at 4,096.
- `diff` reports at most 64 differing ranges.
- Every bounded report carries `total` and `truncated`.
- `utf16le` means ASCII characters stored with a zero high byte, not arbitrary
  UTF-16 text.

## Stable codes

| Code                         | What to do                                                                         |
|------------------------------|------------------------------------------------------------------------------------|
| `binary/parse`               | The file is not a decodable container. Stop and report it.                         |
| `binary/range`               | The offset or length is outside the file. Re-check the value.                      |
| `binary/unsupported`         | The format or architecture is not implemented. Do not substitute another analysis. |
| `binary/io`                  | Read/write failure or an unknown engine message. Report the original error.        |
| `handle/invalid`             | The session is closed. Open a new one.                                             |
| `capability/not-implemented` | The addon is absent or the route is declared unsupported. Do not invent a result.  |

Branch on `code`, never on message text. CLI usage failures add
`open-ctf.cli.*` codes and exit `2`.

## Hard rules

1. Never claim a section, offset, import or instruction without printing the
   report that contains it.
2. Never describe Mach-O runtime binding, ARM/ARM64 disassembly, decompilation
   or debugging as available. Mach-O load commands, segments, sections, dylibs,
   build versions, the `LC_SYMTAB` symbol table, the fat slice table and the
   classic dyld bind opcode streams (`macho-bindings`) are available; the
   rebase stream is not decoded and nothing is bound at runtime.
3. A fat Mach-O is not a thin image: `macho-slices` lists its architectures and
   `macho-extract` writes one slice, which can then be opened with `macho` or
   `macho-symbols`. Never point `--out` at the source container.
4. Before patching, state the file, the offset and the exact bytes. Prefer
   `--out` so the source stays untouched.
5. Never present a hash as a security verdict. It only proves the bytes changed.
6. Do not overwrite the only copy of a binary. An in-place patch requires the
   user's explicit request.
7. Report `truncated` results as truncated; do not present a partial listing as
   complete.
8. `mitigations` reports header and load-config facts. A present certificate
   table is not a verified signature, and a set CFG bit is not proof that every
   indirect call is checked.

## Key files

| Path                                                         | Contents                                 |
|--------------------------------------------------------------|------------------------------------------|
| `projects/crates/ctf-domain/src/challenge.rs`                | `Challenge`, `BinaryView`, `OpenCtf`.    |
| `projects/crates/ctf-domain/src/report.rs`                   | `capabilities()` and `ChallengeReport`.  |
| `projects/crates/ctf-domain/src/error.rs`                    | Stable `CtfError` and `Result`.          |
| `projects/crates/ctf-domain/src/workflow/`                   | Identify, triage, solve, verify.         |
| `projects/crates/ctf-solvers/src/`                           | One solver algorithm per file.           |
| `projects/crates/ctf-formats/src/`                           | One format projection (or pending copy) per file. |
| `projects/crates/ctf-napi/src/lib.rs`                        | Entry points and the handle table.       |
| `documentation/duplication.md`                               | Duplicated and product-local modules.    |
| `projects/packages/open-ctf/src/api.ts`                      | `OpenCTF` session and `capabilities()`.  |
| `projects/packages/open-ctf/src/types.ts`                    | Every report shape.                      |
| `projects/packages/open-ctf/src/errors.ts`                   | Stable codes and `translateNativeError`. |
| `projects/packages/open-ctf/src/cli.ts`                      | Command tree and rendering.              |
| `projects/packages/open-ctf/src/native.ts`                   | Addon discovery and `OPEN_CTF_NATIVE`.   |
| `projects/packages/open-ctf-skills/skills/open-ctf/SKILL.md` | The packaged skill.                      |

The implemented surface is exactly what `open-ctf capabilities` reports.
