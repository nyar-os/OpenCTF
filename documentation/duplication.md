# Boost duplication ledger

Every format module in `projects/crates/ctf-formats` that is also owned by a
Boost crate is listed here. The previous wiring pass deleted every module whose
parser the pinned owner now exposes: the module files are gone, the session
opens, the owner reads the bytes and the report shape is projected back.
`src/owners.rs` is the only file that carries those projections; it contains no
format constant, offset or opcode table.

Every `git` dependency in `Cargo.toml` is pinned with `rev`;
`data-compression` is consumed with the `deflate` and `brotli` features,
`data-binary-x64` with `default-features = false, features = ["decode"]`, and
`data-checksum` supplies CRC-32. `Cargo.lock` records the same revision.

Decision values:

- **migrated** — the local parser is deleted; the session calls the pinned owner
  and `owners.rs` projects the owner type onto the existing report shape.
- **product-local** — the pinned owner does not expose the fact; the module
  stays in `ctf-formats` and this table names the reason.

## Migrated PE facts

All 12 modules were deleted. The owner type aliases keep every `serde` field
name, so the JSON and CLI output are unchanged.

| Deleted path                | Owner call                                        | Report shape |
|-----------------------------|---------------------------------------------------|--------------|
| `src/certificates.rs`       | `pe::read_certificates`                           | `CertificatesReport` ← `PeCertificatesReport` |
| `src/debug.rs`              | `pe::read_debug_directory`                        | `DebugReport` projection (limit, `stable_type_name()`, decoded GUID text) |
| `src/load_config.rs`        | `pe::read_load_config`                            | `PeLoadConfigReport` ← owner type |
| `src/mitigations.rs`        | `pe::read_mitigations`                            | `MitigationsReport` ← `PeMitigationsReport` |
| `src/pe_bound_imports.rs`   | `pe::read_bound_imports`                          | `PeBoundImportsReport` |
| `src/pe_delay_imports.rs`   | `pe::read_delay_imports`                          | `PeDelayImportsReport` |
| `src/pe_exception.rs`       | `pe::read_exception_directory`                    | `PeExceptionReport` |
| `src/pe_rich_header.rs`     | `pe::read_rich_header`                            | `PeRichHeaderReport` |
| `src/relocations.rs`        | `pe::read_relocations`                            | `RelocationsReport` ← `PeRelocationsReport` |
| `src/resources.rs`          | `pe::read_resources`                              | `ResourcesReport` ← `PeResourcesReport` |
| `src/tls.rs`                | `pe::read_tls_directory`                          | `PeTlsReport` |
| `src/version.rs`            | `pe::read_version_resources`                      | `VersionReport` ← `PeVersionReport` |

Projection notes:

- `debug` honours the request limit after the owner has parsed the directory and
  rewrites `type_name()` through `stable_type_name()`, so the `codeview`, `fpo`,
  `pogo` and `misc` labels are unchanged.
- `mitigations` now reads `DllCharacteristics` from the parsed optional header
  instead of a hand-computed offset, which fixes the PE32+ field position
  (offset `0x46` from the optional header, not `0x4a`). The projection test
  fixture writes the value at the specification offset; the assertion is
  unchanged.

## Migrated ELF facts

| Deleted path            | Owner call                                | Report shape |
|-------------------------|-------------------------------------------|--------------|
| `src/dynamic.rs`        | `elf::read_dynamic`                       | `ElfDynamicReport` field-by-field projection |
| `src/elf_symbols.rs`    | `elf::{parse_elf, sections_of_type, read_elf_symbols}` | `ElfStaticSymbolsReport`; name rendering and the 4096 cap stay product-side |
| `src/segments.rs`       | `elf::read_program_headers`               | `ElfSegmentsReport`; type/flag text is derived from the owner enums |
| `src/notes.rs`          | `elf::read_notes`                         | `ElfNotesReport`; source label is `ElfNoteSource::as_str()` |

The owner structs for dynamic dependencies, program headers and notes do not
derive `serde`, so their fields are copied into the existing report structs
without renaming (including `is64`, `physicalAddress`, `flagText`, `buildId`
and `abiTag`). The Mach-O structs share this constraint.

## Migrated Mach-O facts

The whole `src/macho/` directory and `src/code_signature.rs` were deleted
(10 files). `owners::macho` and `owners::code_signature` now call the owner.

| Deleted path                  | Owner call                                  | Report shape |
|-------------------------------|---------------------------------------------|--------------|
| `src/macho/image.rs`          | `mach_o::parse_macho`                       | `MachOReport`; UUID, build platform/min-OS/SDK, dylib versions and entry mapping projected |
| `src/macho/fat.rs`            | `mach_o::read_fat_slices` + `macho_magic`   | `MachOSlicesReport` |
| `src/macho/symbols.rs`        | `mach_o::read_macho_symbols`                | `MachOSymbolsReport` |
| `src/macho/function_starts.rs`| `mach_o::read_function_starts`              | `MachOFunctionStartsReport` |
| `src/macho/exports.rs`        | `mach_o::read_exports`                      | `MachOExportsReport` (`flag_names` rendered as strings) |
| `src/macho/encryption.rs`     | `mach_o::parse_macho` encryption info       | `MachOEncryptionReport` |
| `src/macho/chained_fixups.rs` | `mach_o::read_chained_fixups`               | `MachOChainedFixupsReport` |
| `src/macho/bindings.rs`       | `mach_o::read_bindings`                     | `MachOBindingsReport`; 512-entry cap stays product-side |
| `src/macho/util.rs`           | `mach_o::macho_magic`, `mach_o::fat_magic`  | — |
| `src/macho/mod.rs`            | —                                           | re-export only |
| `src/code_signature.rs`       | `mach_o::read_code_signature`               | `MachOCodeSignatureReport` (`flag_names` → `flagText`) |

Projection notes:

- `MachOReport` still exposes `architecture`, `kind`, `platform`, `minOs`,
  `sdk`, `entryAddress`, `readable`/`writable`/`executable` and packed version
  strings. Those are derived from `MachArchitecture`, the build-version record,
  the segment `initial_protection` bits and `render_version`; no field was
  renamed.
- `macho-slices` still rejects a thin image and `macho-extract` still refuses to
  overwrite the source; the slice bytes come from the session, the architecture
  table from `read_fat_slices`.
- A malformed bind/export/chained stream is now a `binary/parse` failure from
  the owner rather than a partial product-side walk. Valid streams keep the
  `present`/`total`/`truncated` report shape, and the missing
  `LC_FUNCTION_STARTS` case still answers `binary/unsupported`.

## Migrated container facts

| Deleted path           | Owner call                                    | Report shape |
|------------------------|-----------------------------------------------|--------------|
| `src/pyc.rs`           | `data_binary_container::pyc::analyze`, `sniff` | `PycReport` and friends are re-exported owner types |
| `src/pyc_opcodes.rs`   | `data_binary_container::pyc_opcodes`          | module re-export; tables are owned upstream |
| `src/pyinstaller.rs`   | `pyinstaller::{analyze_carchive, analyze_pyz, locate_cookie, looks_like_pyz}` | `PyInstallerReport`; extraction is owner-side |
| `src/nsis.rs`          | `nsis::{analyze, locate, SIGNATURE}`          | `NsisReport` |
| `src/tauri.rs`         | `tauri::{analyze, scan_assets}`               | `TauriAssetsReport` |
| `src/archive.rs`       | `asar::analyze`                               | `AsarReport` |

The container owner now validates the Python opcode table, the `marshal`
stream, the PyInstaller cookie/PYZ layout, the NSIS block chain, the Tauri
interleaved key/blob records and the asar header. Compression inside those
containers is part of the owner, so `ctf-formats` no longer selects
`Envelope::Zlib` for NSIS, PyInstaller or Tauri. Because the owner reads a
complete image, `unpack` hands it the session bytes; the extraction policy
(destination, overwrite refusal, limits) is still the caller's.

`pyc_opcodes` remains reachable as `open_ctf_formats::pyc_opcodes` through a
direct module re-export, and `sniff_pyc` is `pyc::sniff` re-exported at the crate
root, so the test surface did not change.

## Product-local modules kept in `ctf-formats`

| Path              | Reason |
|-------------------|--------|
| `src/pcap.rs`     | No `data-binary-pcap` owner. Frame, endpoint and protocol projection is CTF policy over the session bytes. |
| `src/png.rs`      | The `data-binary-png` walker is not available yet; chunk order, text policy and `IEND` trailing data stay product-side. Chunk CRC-32 calls `data-checksum` and `zTXt`/`iTXt` call `data-compression`. |
| `src/packer.rs`   | Packer section names, marker table, confidence tiers and PE corroboration are product policy; no shared owner exposes the same confidence contract. |
| `src/overlay.rs`  | Overlay/last-section heuristic and the overlay signature list are CTF policy; Shannon entropy calls `data-binary-inspect::entropy` and only the rounding stays product-side. |
| `src/unpack.rs`   | Format sniff and extraction policy; the 7z index/decode is `data-binary-sevenz` and the other containers are the owner projections above. |
| `src/gadgets.rs`  | ROP gadget selection and ranking are CTF policy; instruction decoding is `data-binary-x64::decode`. |
| `src/disasm.rs`   | PE address mapping, count policy, syntax switch and stop-on-invalid rule are product policy; `data-binary-x64::decode` owns the instruction decode. |
| `src/probe.rs`    | `data-binary-probe` owns the anchored pass; embedded-magic and zip tail-window scans are CTF policy. |
| `src/inflate.rs`  | `data-compression` owns the DEFLATE/zlib/gzip envelopes; options, caps and report shape are product-side. |
| `src/owners.rs`   | Projection glue only: open the session, call the owner, map its type. No parser. |

## Compression status

`inflate` and `png` call `data-compression` directly because their envelope
selection, gzip-member handling and PNG chunk policy are product-side. PNG
chunk CRC-32 is read from `data-checksum`; the mismatch is reported as a fact
and does not change the walk failure semantics. The NSIS, PyInstaller and Tauri
decoders moved into `data-binary-container` with the rest of their containers,
so those call sites no longer exist in this repo. `miniz_oxide` and the
third-party `brotli` crate remain absent from the dependency graph;
`data-encoding` remains transitive and is reached through `boost-crypto` for
standard hex/base64 conversions.

## Deleted dependencies

| Dependency             | Evidence |
|------------------------|----------|
| `iced-x86`             | absent from the workspace and `ctf-formats` manifests; `cargo tree -e normal,build,dev -i iced-x86` matches no package |
| `miniz_oxide`          | absent; `cargo tree -i miniz_oxide` reports no dependents |
| `brotli` (third-party) | absent; `cargo tree -e normal,build,dev -i brotli` matches no third-party crate |

## Remaining upstream work

1. `pcap` frame/endpoint facts → a `data-binary-pcap` owner.
2. `png` chunk structure, text policy and pixel preview → a shared image owner;
   the chunk CRC-32 and DEFLATE calls already use their owners.
3. `packer` signature confidence → a `data-binary-probe` + `data-binary-pe`
   owner for the corroboration tier.

Each step keeps the product projection, pins one revision, runs the product
workflow and an independent oracle on the same corpus, and only then deletes the
local policy.

## Not duplicated

- `ctf-solvers` (Caesar, XOR, cyclic, decoders, digests, JWT, URL) has no Boost
  equivalent; the algorithms are CTF-specific.
- The session itself (open, header, sections, strings, search, hex dump, read,
  patch, address mapping) is `boost.rs/data-binary-inspect` and is never copied.
- `ctf-formats::overlay::shannon` only rounds the result of
  `data-binary-inspect::entropy::shannon`; it no longer counts bytes locally.
