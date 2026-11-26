# Duplication ledger

Every format module in `projects/crates/ctf-formats` that is also owned by
OpenIDA or by a Boost crate is listed here. This pass does not delete anything
that still has a consumer: the module stays reachable, carries a
`// TODO(boost): owner migration` marker while a fact is still pending, and is
migrated when the pinned `boost.rs` revision exposes the same fact. When the
marker and this table disagree, the table wins.

Pinned upstream revision: `f191fdc4134a5be749f289315dfcacc7c4ad9200`
(`✨ Own x86 decoding in data-binary-x64`). Every `git` dependency in
`Cargo.toml` points at that revision, `data-compression` is consumed with the
`lzma`, `deflate` and `brotli` features, and `data-binary-x64` is consumed with
`default-features = false, features = ["decode"]`, which exposes
`data_binary_x64::decode::{Decoder, Instruction, Syntax}`.

Decision values:

- **keep** — this crate owns the projection; only the *facts* it reads come from
  the listed Boost owner, or the owner does not expose the field at all.
- **duplicate** — a full copy of an owner that already exists; delete it and call
  the owner once the pinned revision is bumped.
- **migrated** — the byte observation now calls the pinned owner and only the
  product projection remains here.

## Migrated byte observation (`ctf-domain`)

These six modules no longer contain a local byte scanner. Their options,
paging, candidate evidence and report shapes stay product-side; the observation
is read from `data-binary-inspect` at the pinned revision.

| Path                | Owner crate  | Pinned upstream call                                      | Decision |
|---------------------|--------------|-----------------------------------------------------------|----------|
| `src/diff.rs`       | `ctf-domain` | `diff::{diff, DiffOptions}`                               | migrated |
| `src/find.rs`       | `ctf-domain` | `find::find` for literal patterns; regex stays product    | migrated |
| `src/text.rs`       | `ctf-domain` | `text::{extract, TextMode, TextOptions}`                  | migrated |
| `src/dump.rs`       | `ctf-domain` | `dump::window` (raw export; `hexdump` owns rendering)     | migrated |
| `src/entropy.rs`    | `ctf-domain` | `entropy::range` (`shannon` behind it)                    | migrated |
| `src/carve.rs`      | `ctf-domain` | `find::find` marker scan + `dump::window` region slice    | migrated |

Product policy that deliberately stays in `ctf-domain`:

- `find` keeps a byte-regex matcher because the pinned owner only scans
  literals. Literal patterns are delegated to `find::find`; patterns that need
  regex syntax, or whose matches would overlap, use the product matcher so the
  reported `total`/`skip` do not change.
- `text` keeps the `ascii`/`utf16le`/`both` switch, `skip`/`all` paging and the
  per-hit encoding tag. UTF-16LE still scans both byte alignments.
- `entropy` keeps section selection, the PE overlay range and four-decimal
  rounding; the Shannon arithmetic is the owner's.
- `dump` and `carve` keep the 64 MiB clamp, destination policy and carve
  expansion/deduplication rules; range slicing is the owner's.

## Migrated compression codecs (`ctf-formats`)

The DEFLATE family no longer has a local decoder. `inflate`, `nsis`,
`pyinstaller` and `png` select the pinned `data-compression` envelope
explicitly, and the `miniz_oxide` crate was deleted from both `[dependencies]`
and `[dev-dependencies]`; `cargo tree -i miniz_oxide` reports no dependents.
Options, offsets, caps and report shapes stay product-side.

| Path                 | Owner crate   | Pinned upstream call                                | Envelope | Decision |
|----------------------|---------------|-----------------------------------------------------|----------|----------|
| `src/inflate.rs`     | `ctf-formats` | `Envelope::Zlib` / `Envelope::Raw` + `CodecLimits`  | zlib/raw | migrated |
| `src/nsis.rs`        | `ctf-formats` | `Envelope::Raw` for the header block and file chunks | raw      | migrated |
| `src/pyinstaller.rs` | `ctf-formats` | `Envelope::Zlib` for entries and `PYZ` modules       | zlib     | migrated |
| `src/png.rs`         | `ctf-formats` | `Envelope::Zlib` for `zTXt` and compressed `iTXt`    | zlib     | migrated |

The gzip route of `inflate` keeps its historical shape: it skips the member
header and decodes the bare DEFLATE payload with `Envelope::Raw`, so a gzip
trailer is still ignored. `nsis` and `pyinstaller` keep their container
projections; only the compression call moved upstream. Tests use fixed Node.js
24.18.0 `zlib` vectors plus plaintext SHA-256 and checksum values, so the
decoder is never exercised against this crate's own encoder.

The Brotli decoder of `tauri` is migrated at the same revision. The interleaved
`(key, blob)` walk stays product-side; only the stream decode moved upstream,
and the old "the stream must consume its declared length" rule is now an
explicit `is_complete() && trailing_input == 0` check. The third-party `brotli`
crate was deleted from both `[dependencies]` and `[dev-dependencies]`:
`cargo tree -e normal,build,dev -i brotli` reports no third-party crate, and the
fixtures are fixed Node.js 24.18.0 `zlib.brotliCompressSync` vectors (quality 9)
with their plaintext SHA-256 and decoded length recorded next to them.

| Path           | Owner crate       | Pinned upstream call                          | Decision |
|----------------|-------------------|-----------------------------------------------|----------|
| `src/tauri.rs` | `data-compression` | `Brotli::decode_bounded` + `CodecLimits`      | migrated |

## Format modules (`ctf-formats`)

33 module paths are listed: 29 stay product-side and four are **migrated**
(their byte scanner is deleted and the owner is called). Each row carries the
field-by-field decision against the pinned owner's public API. A module is kept
because the owner does not expose at least one reported field with the same
semantics; the reason column names that field.

| Path                      | Owner crate          | Pinned upstream call                                  | Decision | Missing field / reason |
|---------------------------|----------------------|-------------------------------------------------------|----------|------------------------|
| `src/disasm.rs`           | `data-binary-x64`    | `decode::{Decoder, Instruction, Syntax}`              | migrated | — |
| `src/elf_symbols.rs`      | `data-binary-pe`     | `elf::{parse_elf, read_elf_symbols, sections_of_type}`| migrated | — |
| `src/macho/symbols.rs`    | `data-binary-mach-o` | `mach_o::{parse_macho, read_macho_symbols}`           | migrated | — |
| `src/probe.rs`            | `data-binary-probe`  | `ProbeSession::probe` + `Signature`/`BytePattern`     | migrated | — (anchored pass; embedded/tail scan is CTF policy) |
| `src/debug.rs`            | `data-binary-pe`     | `pe::{parse_pe, rva_to_offset}` (container facts)     | keep     | the owner's `PeCodeView` drops the `NB10` offset/timestamp and its GUID is raw bytes; `PeDebugEntry::type_name()` maps 7/8/11/12/13/17 to different labels than the report |
| `src/certificates.rs`     | `data-binary-pe`     | none                                                  | keep     | no security-directory / `WIN_CERTIFICATE` walk |
| `src/code_signature.rs`   | `data-binary-mach-o` | none                                                  | keep     | no `LC_CODE_SIGNATURE` / `CodeDirectory` blob decoder |
| `src/dynamic.rs`          | `data-binary-pe`     | none                                                  | keep     | `parse_elf` exposes no program headers, `PT_INTERP`, `PT_DYNAMIC` or `DT_*` entries |
| `src/gadgets.rs`          | `data-binary-x64`    | none                                                  | keep     | no ROP gadget scanner; only instruction encode/decode |
| `src/load_config.rs`      | `data-binary-pe`     | none                                                  | keep     | no load-config directory fields |
| `src/macho/`              | `data-binary-mach-o` | `parse_macho` (header/segments/sections/dylibs/symtab)| keep    | `LC_UUID`, `LC_BUILD_VERSION`, `LC_VERSION_MIN_*`, code signature, chained fixups, export trie, function starts, encryption and fat slices are not exposed; `MachDylib` has no `timestamp` and no `lazy` kind |
| `src/mitigations.rs`      | `data-binary-pe`     | none                                                  | keep     | no `DllCharacteristics` / W^X summary |
| `src/notes.rs`            | `data-binary-pe`     | none                                                  | keep     | no `PT_NOTE`/`SHT_NOTE` walk, build-id, ABI tag or GNU property decoding |
| `src/nsis.rs`             | container owner      | none (candidate)                                      | keep     | no NSIS container owner; only the DEFLATE/LZMA stream is migrated |
| `src/overlay.rs`          | `data-binary-inspect`| none                                                  | keep     | no overlay/last-section heuristic or overlay signature list |
| `src/pe_bound_imports.rs` | `data-binary-pe`     | none                                                  | keep     | no bound-import directory |
| `src/pe_delay_imports.rs` | `data-binary-pe`     | none                                                  | keep     | no delay-import directory |
| `src/pe_exception.rs`     | `data-binary-pe`     | none                                                  | keep     | no exception directory / unwind info |
| `src/pe_rich_header.rs`   | `data-binary-pe`     | none                                                  | keep     | no Rich header entries |
| `src/pyc.rs`              | container owner      | none (candidate)                                      | keep     | no CPython marshal reader |
| `src/pyc_opcodes.rs`      | container owner      | none (candidate)                                      | keep     | no 3.11–3.13 opcode tables |
| `src/pyinstaller.rs`      | container owner      | none (candidate)                                      | keep     | container walk stays product-side; only zlib is migrated |
| `src/relocations.rs`      | `data-binary-pe`     | none                                                  | keep     | no base-relocation directory |
| `src/resources.rs`        | `data-binary-pe`     | none                                                  | keep     | no resource directory tree |
| `src/segments.rs`         | `data-binary-pe`     | none                                                  | keep     | `parse_elf` exposes sections, not program headers |
| `src/tauri.rs`            | container owner      | none (candidate)                                      | keep     | interleaved-record walk stays product-side; only Brotli is migrated |
| `src/tls.rs`              | `data-binary-pe`     | none                                                  | keep     | no TLS directory / callbacks |
| `src/unpack.rs`           | container owner      | `data-binary-sevenz` (7z index)                       | keep     | format sniff, extraction policy and asar/NSIS/PyInstaller projections are product-side |
| `src/version.rs`          | `data-binary-pe`     | none                                                  | keep     | no version-resource parser |
| `src/pcap.rs`             | `data-binary-pcap`   | none (candidate)                                      | keep     | no pcap owner; frame/endpoint projection is product-side |
| `src/png.rs`              | `data-binary-png`    | none (candidate)                                      | keep     | no PNG owner; chunk/CRC/pixel projection is product-side |
| `src/packer.rs`           | `data-binary-probe`  | `ProbeSession` (shared signature facts)               | keep     | packer signature table, confidence tiers and PE corroboration are product policy |
| `src/archive.rs` (`asar`)| container owner      | none (candidate)                                      | keep     | no ASAR container owner |

Migration notes for the four moved modules:

- `disasm` keeps the PE virtual-address mapping, the 64/4096 count policy, the
  syntax switch and the stop-on-invalid rule. The owner's `.byte` fallback is
  never emitted: an invalid decode ends the listing exactly as before. All five
  asserted renderings (`mov rbp,rsp`, `sub rsp,0x20`, `ret`, `push ebp`,
  `mov ebp,esp`) come from `Instruction::format(Syntax)`.
- `elf_symbols` keeps the `STT_*`/`STB_*`/visibility name rendering, the
  `UND`/`ABS`/`COM` section fallbacks and the 4096 cap; `parse_elf` expands the
  section names and `read_elf_symbols` reads the entries.
- `macho/symbols` keeps the `N_*` kind labels, `external`/`debug` flags and the
  limit; `parse_macho` owns the `LC_SYMTAB` walk and `read_macho_symbols` the
  `nlist` records. The fat-container rejection and the `LC_SYMTAB` requirement
  stay product-side so the `binary/unsupported` envelope is unchanged.
- `probe` already called `data-binary-probe` for the anchored pass before this
  pass; the ledger now records it as migrated. The embedded-magic and zip
  tail-window scans remain CTF policy.

## Batch 6 — hex/base64 conversions

`boost-crypto::encoding` is the existing encoding boundary and it already
delegates base64/base64url to `data-encoding`
(`data_encoding::representation::Base64`); `data-binary-inspect` decodes hex
through `data_encoding::representation::Hex`. `data-encoding` itself is not a
direct dependency of any OpenCTF crate, so the standard conversions are routed
through the existing `boost-crypto` dependency instead of adding a new crate:

| Path                                        | Change                                                        |
|---------------------------------------------|---------------------------------------------------------------|
| `ctf-formats/src/disasm.rs`                 | local hex loop → `boost_crypto::encoding::hex_encode`         |
| `ctf-formats/src/macho/util.rs`             | UUID hex loop → `hex_encode`                                  |
| `ctf-formats/src/notes.rs`                  | bounded preview → `hex_encode` + preview suffix               |
| `ctf-formats/src/unpack.rs`                 | method-id hex → `hex_encode`                                  |
| `ctf-solvers/src/decode.rs`                 | preview hex → `hex_encode` (decode already used `hex_decode`) |
| `ctf-solvers/src/xor.rs`                    | preview hex → `hex_encode`                                    |
| `ctf-napi/src/commands/binary.rs`           | `read` hex → `hex_encode`                                     |

Recorded as remaining, not converted:

- `ctf-formats/src/inflate.rs` and `ctf-formats/src/overlay.rs` render
  space-separated byte windows (`"90 90"`), which is a display policy rather
  than a plain hex conversion.
- `png` stays entirely product-side (chunk walk, CRC, pixel projection) until a
  `data-binary-png` owner wiring pass; only its `zTXt`/`iTXt` inflate step is
  migrated to `data-compression`.
- `data-encoding` remains transitive; a future pass may add it as a direct
  workspace dependency once it is also used for decode-side facts.

## Deleted dependencies

| Dependency               | Evidence                                                                 |
|--------------------------|--------------------------------------------------------------------------|
| `iced-x86`               | removed from the workspace and `ctf-formats` manifests; `Cargo.lock` has zero `iced` entries and `cargo tree -e normal,build,dev -i iced-x86` matches no package |
| `miniz_oxide`            | deleted from `ctf-formats`; `cargo tree -i miniz_oxide` reports no dependents |
| `brotli` (third-party)   | deleted from `ctf-formats`; `cargo tree -e normal,build,dev -i brotli` reports no third-party crate |

## Next batch

The next migration consumes the same pinned revision or a later one only after
an owner oracle exists for each fact:

1. `pcap` frame/endpoint facts → `data-binary-pcap`.
2. `png` chunk/CRC/pixel facts → `data-binary-png`; the CTF chunk view becomes a
   projection over the same facts.
3. `packer` signatures and confidence → `data-binary-probe` +
   `data-binary-pe`.
4. `archive`/`asar` container facts → the container owner candidate.
5. Decompression (`unpack`) → `data-compression`: the DEFLATE, zlib and gzip
   family is migrated at `0e2b81c4`, and the Brotli stream decode of `tauri` is
   migrated at `d440aae8`; only the 7z container projection remains.
6. PNG chunk facts specifically (length ordering, CRC failure classes and
   `IEND` trailing data) → `data-binary-png`.

Each step must keep the product projection, pin one revision, run the product
workflow and an independent oracle on the same corpus, and only then delete the
local parser.

## Not duplicated

- `ctf-solvers` (Caesar, XOR, cyclic, decoders, digests, JWT, URL) has no Boost
  equivalent yet; the algorithms are CTF-specific.
- The session itself (open, header, sections, strings, search, hex dump, read,
  patch, address mapping) is `boost.rs/data-binary-inspect` and is never copied.
- `ctf-formats::overlay::shannon` remains the one product-side entropy helper
  used by the overlay projection; `ctf-domain::entropy` now calls the owner and
  only rounds its result.
