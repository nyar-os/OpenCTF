# @wae/open-ctf

The `OpenCTF` TypeScript session and the `open-ctf` command line, both reading
one built-in binary inspection engine. It is the binary and container side of a
CTF toolbox: identify an unknown challenge file, triage packing, recover strings
and hidden payloads, unpack installers and PyInstaller bundles, disassemble
x86/x64 or CPython bytecode, and prove a patch with before and after hashes. No
analysis is re-implemented in TypeScript, so the SDK and the CLI cannot disagree
about a file.

The platform addon is resolved automatically from
`@wae/open-ctf-<platform>-<arch>`. Set `OPEN_CTF_NATIVE` to an absolute `.node`
path to use a local build instead.

## Exports

| Import | Contents |
| :--- | :--- |
| `.` | `OpenCTF`, `capabilities`, `errorCodes`, `CtfError`, `NotImplementedError`, `translateNativeError`, `isCtfError`, GUI helpers, `nativeBinding` and every report type |
| `open-ctf` (bin) | The command line; see the [CLI reference](../../../documentation/cli.md) |

## Example

```ts
import { OpenCTF, capabilities, decodeJwt } from '@wae/open-ctf';

const ctf = new OpenCTF({ path: 'samples/app.exe' });
const info = ctf.info();
console.log(info.format, info.architecture, info.hash);
console.log(ctf.sections().sections.length);
console.log(ctf.stringsEncoded({ encoding: 'both', limit: 50 }).hits);
console.log(ctf.imports(20).entries);
console.log(ctf.probe().findings);
console.log(ctf.hash({ algorithm: 'sha256' }).digest);
console.log(ctf.decode({ codec: 'auto' }).text);
console.log(ctf.xor().guesses[0]);
console.log(ctf.gadgets({ limit: 20 }).hits);
ctf.close();

console.log(decodeJwt('header.payload.signature').warnings);
console.log(capabilities().features.disassembly);
```

Patching writes a copy when an output path is given, and the report carries the
whole-file hash before and after:

```ts
const ctf = new OpenCTF({ path: 'samples/app.exe' });
const report = ctf.patch(0x200, '90,90', 'samples/app-patched.exe');
console.log(report.beforeHash, report.afterHash);
ctf.close();
```

## Constraints

- Instances are handles. A closed handle is rejected instead of being reopened
  silently, and every constructor call must be paired with `close()`.
- `resources()` lists the PE resource tree leaves by type, name, language and
  size. It reports `present: false` when the image has no resource directory.
- `probe()` names a container from anchored, embedded and zip-tail magic bytes.
  Findings are candidates with confidence, offset and reason, not parsed
  structures.
- `hash()` computes MD4, MD5, SHA-1 and SHA-2 digests over the whole file or one
  byte range through the internal `boost-crypto` implementation.
- `decode()` peels base64, base64url, hex, base32, rot13, percent encoding and
  HTML entities; `codec: 'auto'` chains decoders while the output stays printable.
- `xor()` brute-forces all 255 single-byte keys with a flag-aware score, or
  decrypts with a known key.
- `gadgets()` lists byte-level x64 `ret`, `pop`, `syscall` and stack-jump
  candidates in executable sections; disassembler confirmation is still required.
- `decodeJwt()` decodes a token header and payload without verifying the
  signature, and flags `alg=none` and unsigned tokens.
- `relocations()` decodes the PE base relocation blocks, reporting each block's
  page RVA, entry count and fixup types. It reports `present: false` when the
  image has no relocations.
- `exception()` lists the PE exception directory runtime functions with their
  begin/end RVAs, unwind info RVA and, on x64, the decoded unwind header. ARM and
  ARM64 packed entries are unmasked. It reports `present: false` when the image
  has no exception directory.
- `dynamic()` reports the ELF interpreter, SONAME, `NEEDED` libraries and
  rpath/runpath. It reports `present: false` for a static image.
- `segments()` lists the ELF program headers with type, offsets, addresses,
  sizes, permissions and alignment for both ELF32 and ELF64.
- `notes()` decodes ELF `PT_NOTE` / `SHT_NOTE` records: the GNU build id as hex,
  the GNU ABI tag, GNU property entries and a bounded hex preview for other
  notes. It reports `present: false` when the image has no notes.
- `certificates()` lists the PE attribute certificate table entries with their
  revision, type and `PKCS#7` payload shape. It never verifies a signature or a
  chain.
- `tls()` decodes the PE TLS directory and callback array, mapping each callback
  VA back to an RVA and file offset. It never calls a callback.
- `loadConfig()` decodes the PE load configuration: security cookie, SEH table,
  CFG pointers, decoded `GuardFlags` and the `CodeIntegrity` block.
- `codeSignature()` decodes the Mach-O embedded signature SuperBlob and its first
  `CodeDirectory` (identifier, team id, hash type, flags). It never verifies.
- `mitigations()` reads PE header and load-config facts (ASLR, DEP, CFG, GS,
  W+X sections, relocations, certificate-table presence). It does not verify
  Authenticode signatures.
- Mach-O support covers headers, load commands, segments, sections, dylibs,
  build versions, the `LC_SYMTAB` symbol table, the `LC_FUNCTION_STARTS` table,
  the dyld export trie and the fat architecture table; dyld bind opcodes are not
  decoded.
  `extractSlice(index, output)` writes one fat slice to a new file and refuses
  to overwrite the source container.
  Big-endian ELF and unknown containers are rejected with
  `binary/unsupported`, not guessed at.
- Disassembly covers x86 and x64 only; other architectures answer
  `binary/unsupported`.
- `stringsEncoded({ encoding: 'utf16le' })` matches ASCII characters stored with
  a zero high byte. Arbitrary UTF-16 text is not decoded.
- UTF-16LE is encoded as `'utf16le'` in the API. The CLI accepts the same
  spelling.
- Every listing is bounded: string scans default to 100 hits (maximum 10,000),
  disassembly to 64 instructions (maximum 4,096) and diffs to 64 ranges.
  Reports set `truncated` instead of growing without bound.
- `patch()` without an output path writes the source file in place. Prefer an
  explicit output path.
- The package is private and has no npm release yet.

Supported behaviour and every boundary are documented in
[Capabilities](../../../documentation/capabilities.md). For the product overview
start at the [root README](../../../readme.md).
