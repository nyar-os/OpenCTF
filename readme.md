# OpenCTF

![CTF workflows](https://img.shields.io/badge/workflows-misc%20%C2%B7%20reverse%20%C2%B7%20forensics-blue)
![Built-in engine](https://img.shields.io/badge/runtime-zero%20system%20dependencies-brightgreen)
![Auditable output](https://img.shields.io/badge/output-bounded%20reports-blueviolet)

## 💡 What is OpenCTF?

OpenCTF is a CTF toolbox for the moment a challenge hands you a file. One
command line, one TypeScript session and one Studio window answer the questions
that decide your next move: what is this container, is it packed, where is the
text, what does this install, which bytes are bytecode rather than machine code,
what changed between two builds, and did my patch alter only what I intended?

It ships a built-in engine, so it needs no external disassembler, archive
utility, SDK or system toolchain at runtime. Results are bounded reports with an
explicit truncation flag, and every failure carries a stable code instead of
prose you have to parse.

OpenCTF is not a decompiler and not a debugger. It does not produce pseudo-code,
attach to a running process or resolve relocations. When a format or
architecture is not implemented it says so instead of guessing.

## 🚀 Getting started

### 1. Agent path (recommended)

Point your agent at the packaged skill
`node_modules/@wae/open-ctf-skills/skills/open-ctf/SKILL.md`. The skill fixes the
preflight checks, the order of triage and the rules for safe patching, so the
agent does not have to improvise. A realistic prompt:

> A CTF challenge gives me `samples/challenge.exe`. Tell me the format and
> architecture, whether the entropy suggests packing, list both ASCII and
> UTF-16LE strings, and unpack anything embedded without running it.

### 2. Manual install

OpenCTF has no npm release yet: the application package is private and the
platform addons are unpublished. Until the first release, run from a checkout
built with the repository toolchain; the
[build guide](documentation/README.md#build-and-test) lists the commands. Once
the command is installed, a first pass over an unknown challenge file looks like
this:

```bash
open-ctf info ./samples/challenge.exe
open-ctf probe ./samples/challenge.exe
open-ctf entropy ./samples/challenge.exe
open-ctf strings ./samples/challenge.exe --encoding both
open-ctf overlay ./samples/challenge.exe
open-ctf unpack ./samples/challenge.exe --format pyinstaller --extract-dir ./payload
open-ctf disasm ./payload/PYZ-00.pyz/main.pyc --format pyc
open-ctf carve ./samples/challenge.exe --marker "flag" --out ./carved
open-ctf diff ./samples/challenge.exe ./samples/challenge-patched.exe
```

The full surface, each of which prints a human report and the same values as
JSON:

```bash
open-ctf capabilities
open-ctf info ./samples/app.exe
open-ctf sections ./samples/app.exe
open-ctf strings ./samples/app.exe --encoding both
open-ctf find ./samples/app.exe --pattern "https?://" --ignore-case
open-ctf dump ./samples/app.exe --offset 0x1000 --length 64 --output ./range.bin
open-ctf carve ./samples/app.exe --marker "synthetic-blob" --min 200 --limit 5
open-ctf tauri-assets ./samples/tauri-app.exe --out ./assets
open-ctf imports ./samples/app.exe
open-ctf macho ./samples/app.macho
open-ctf macho-slices ./samples/universal.macho
open-ctf macho-extract ./samples/universal.macho --index 1 --out ./samples/app.arm64.macho
open-ctf mitigations ./samples/app.exe
open-ctf resources ./samples/app.exe
open-ctf relocations ./samples/app.exe
open-ctf exception ./samples/app.exe
open-ctf pe-delay-imports ./samples/app.exe
open-ctf pe-bound-imports ./samples/app.exe
open-ctf pe-rich-header ./samples/app.exe
open-ctf dynamic ./samples/app.elf
open-ctf elf-symbols ./samples/app.elf
open-ctf segments ./samples/app.elf
open-ctf notes ./samples/app.elf
open-ctf certificates ./samples/app.exe
open-ctf tls ./samples/app.exe
open-ctf load-config ./samples/app.exe
open-ctf code-signature ./samples/app.macho
open-ctf macho-symbols ./samples/app.macho --limit 200
open-ctf macho-function-starts ./samples/app.macho --limit 200
open-ctf macho-exports ./samples/app.macho
open-ctf macho-encryption ./samples/app.macho
open-ctf macho-chained-fixups ./samples/app.macho
open-ctf macho-bindings ./samples/app.macho
open-ctf disasm ./samples/app.exe --offset 0x1000 --count 20
open-ctf disasm ./samples/app.pyc --code main
open-ctf entropy ./samples/app.exe
open-ctf overlay ./samples/app.exe
open-ctf inflate ./samples/app.exe --offset 0x600 --out ./payload.bin
open-ctf unpack ./samples/installer.exe --format nsis --extract-dir ./payload
open-ctf unpack ./samples/app.asar --extract-dir ./source
open-ctf diff build/app.exe build/app-patched.exe
```

Every command prints a human report. The same values are available as JSON from
the TypeScript session, so a script and a person read the same result.

## ✨ Highlights

- **First contact.** One `info`, `sections`, `entropy` and `overlay` pass tells
  you the container, the architecture, the entry point, the image base, the
  section permissions and whether the file looks packed, before you choose a
  direction.
- **Evidence, not guesses.** Hardening facts (ASLR, high-entropy VA, DEP, CFG, GS
  cookies, W+X sections, relocations and certificate-table presence) are read
  from the PE header and load config, and the PE resource tree is listed by type,
  name and language.
- **Format-aware forensics.** PE and ELF headers, sections, entry points, image
  bases and hashes; Mach-O load commands, segments, sections, dylibs, UUID,
  build versions and the `LC_SYMTAB` symbol table, plus the architecture table
  of fat containers. Mach-O stays partial until the rebase stream and the chained
  pointers are decoded.
- **Text in both encodings.** ASCII runs by default, plus the ASCII-in-UTF-16LE
  runs that Windows binaries commonly embed — often where a challenge hides its
  flag.
- **Address mapping both ways.** RVA or virtual address to file offset, and file
  offset back to RVA and VA, so a disassembly hit lines up with a hexdump.
- **Symbols where the format has them.** PE imports, exports, COFF symbols, and
  PE debug directory entries with `RSDS` / `NB10` CodeView records.
- **Product metadata.** PE `RT_VERSION` file and product versions plus the
  `StringFileInfo` pairs, when the resource exists.
- **x86 and x64 disassembly.** Intel, MASM or NASM syntax, with the file offset
  and virtual address of every instruction.
- **Bytecode decoding.** CPython `marshal` streams and `.pyc` containers decoded
  statically through `disasm --format pyc` to every code object, with the 3.11
  through 3.13 bytecode disassembled as word-code pairs: the opcode table named
  by the container magic (raw streams take the 3.12 table unless `--python` pins
  another), arguments resolved against the names, constants and locals tables,
  jump targets and inline cache slots counted.
- **Container unpacking.** `unpack` decodes NSIS installers to the first header,
  the solid/non-solid framing and method, the eight header blocks, the script
  command stream with every opcode named and its parameters rendered from the
  string table, and the `File` extraction manifest; Electron `asar` archives to
  the sixteen-byte header, the data-area offset and the full file tree; `7z`
  containers to the version, coder methods, packed folders and entry table with
  entries decoded through internalized pure-Rust LZMA1/LZMA2/BCJ codecs; and
  PyInstaller `CArchive` bundles through the `MEI` cookie to the table of
  contents and every embedded `PYZ` module, which `disasm --format pyc` then
  decodes. Extraction mirrors the archive paths and is traversal-safe.
- **Packing triage and payload peeking.** Whole-file and per-section Shannon
  entropy for PE, ELF and Mach-O, an overlay report that names NSIS, PyInstaller,
  archive signatures and the leading magic, and bounded zlib, gzip and raw
  DEFLATE decoding of one embedded stream with the decoded magic and ASCII head.
- **Carving and searching.** Byte-regex `find` with printable previews and
  `carve`, which expands printable regions around marker matches and writes each
  region to a file.
- **Deeper container and cipher triage.** `url` decomposes a URL and decodes its
  query parameters; `cyclic` generates a de Bruijn pattern and finds a stack
  offset; `packer` identifies UPX, ASPack, VMProtect and similar protectors from
  section names and markers; `caesar` ranks or applies rotations;
  `png` walks chunks, extracts text and reports bytes after `IEND`; and `pcap`
  summarizes classic captures with protocol and endpoint counters.
- **Six-category CTF helpers.** `probe` identifies a container from anchored,
  embedded and zip-tail magics; `hash` computes MD4, MD5, SHA-1 and SHA-2
  digests over a file or a byte range; `decode` chains base64, base64url, hex,
  base32, rot13, percent encoding and HTML entities; `xor` brute-forces or
  applies a one-byte XOR key with a flag-aware score; `gadgets` lists basic x64
  ROP candidates in executable sections; and `jwt` decodes a token header and
  payload, flagging `alg=none` and unsigned tokens without pretending to verify
  them.
- **Binary diff.** Size and hash for both sides, the first differing offset and
  the differing ranges, or a clear `identical` verdict.
- **Patching you can audit.** Atomic writes with the before and after hash of
  the whole file; pass `--out` to keep the original untouched.
- **Bounded by default.** Every listing has a limit and reports
  `truncated: true` when it cut results, so a huge binary cannot turn into an
  unbounded report.

## 🧭 How it works

One engine answers every surface. The command line, the TypeScript session, the
Studio window and the agent skill read the same handles and the same reports, so
a section shown in the Studio is the section the command line printed. When the
Studio is opened without a connected host it says so and stays empty instead of
drawing sample data.

## 🚧 What this build does not do

- No decompiler: no pseudo-code, control-flow graph or type recovery.
- No debugger: it does not attach, set breakpoints or inspect a running process.
- No non-x86 disassembly: ARM and ARM64 return a stable unsupported error.
- No signature verification: `mitigations` reports whether the certificate
  table is present, not whether the Authenticode signature is valid.
- No Mach-O runtime binding: load commands, segments, sections, dylibs, build
  versions, the `LC_SYMTAB` symbol table and the classic dyld bind, weak-bind
  and lazy-bind opcode streams are decoded, but the rebase stream is not and
  nothing is bound at runtime.
- No fat Mach-O in-place inspection: `macho-slices` lists the architecture
  table and `macho-extract` writes one slice to a new file, which `macho` can
  then inspect. The source container is never modified.
- No big-endian ELF: rejected with a stable code instead of a guessed layout.
- No relocation resolution: import and export tables are parsed, not applied.
- No crypto, stego or web exploitation helpers: this toolbox covers the binary
  and container side of a challenge, not every category.
- No release artifacts: the packages are private and no installer exists.

## 🧪 Examples

- [Package usage](projects/packages/open-ctf/README.md) — the session API, the
  export map and the constraints.
- [Smoke test](projects/packages/open-ctf/tests/smoke.test.ts) — runnable
  evidence for the error contract and the declared capability gap.
- [CLI reference](documentation/cli.md) — every command, flag, default and exit
  code.

## 📚 Documentation

- [Capabilities](documentation/capabilities.md) — the support matrix, every
  limit and every unsupported boundary.
- [CLI reference](documentation/cli.md) — all `open-ctf` commands.
- [Agent guide](documentation/agents.md) — capability discovery, stable codes
  and guardrails for automation.
- [Package README](projects/packages/open-ctf/README.md) — the npm-facing API
  surface.
- [Maintainer guide](documentation/README.md) — layout, build, CI and release
  state.

## 📜 License

[Apache-2.0](License.md)
