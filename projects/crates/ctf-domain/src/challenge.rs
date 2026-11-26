//! The opened challenge and its product session.
//!
//! [`OpenCtf`] is the product facade over one opened file: it keeps the
//! documented defaults, takes a raw [`BinaryView`] for callers that only need
//! the shared engine, and forwards every orthogonal operation to the crate that
//! owns it. Format facts come from `open-ctf-formats`, algorithms from
//! `open-ctf-solvers`, and the shared inspection session from
//! `boost.rs/data-binary-inspect`; this module adds no second parser.
//!
//! [`Challenge`] is the product model of one artifact: the name, the detected
//! container, the architecture and the size, without the bytes. Anything that
//! has to be interpreted becomes [`crate::Evidence`] or a
//! [`crate::Candidate`] instead of a mutable field here.

use std::path::{Path, PathBuf};

use data_binary_inspect::{
    Architecture, BinaryFormat, BinaryInfo, BinarySession, ExportsReport, ImportsReport, InspectOptions, PatchReport,
    SearchOptions, SearchReport, SectionInfo as Section, StringHit, StringsReport, SymbolsReport,
};
use open_ctf_formats::{
    CertificatesReport, DebugReport, DisassembleOptions, DisassemblyReport, EapolOptions, EapolReport, ElfDynamicReport,
    ElfNotesReport, ElfSegmentsReport, ElfStaticSymbolsReport, GadgetOptions, GadgetsReport, InflateOptions, InflateReport,
    MachOBindingsReport, MachOChainedFixupsReport, MachOCodeSignatureReport, MachOEncryptionReport, MachOExportsReport,
    MachOFunctionStartsReport, MachOReport, MachOSliceExtraction, MachOSlicesReport, MachOSymbolsReport, MitigationsReport,
    OverlayReport, PackerOptions, PackerReport, PcapOptions, PcapReport, PeBoundImportsReport, PeDelayImportsReport,
    PeExceptionReport, PeLoadConfigReport, PeRichHeaderReport, PeTlsReport, PngOptions, PngReport, ProbeOptions, ProbeReport,
    PycOptions, PycReport, RelocationsReport, ResourcesReport, TauriAssetsOptions, TauriAssetsReport, UnpackOptions,
    UnpackReport, VersionReport, WifiOptions, WifiReport, certificates, code_signature, debug, disasm, dynamic, elf_symbols,
    gadgets, inflate, load_config, macho, mitigations, notes, overlay, packer, pcap, pe_bound_imports, pe_delay_imports,
    pe_exception, pe_rich_header, png, probe, pyc, relocations, resources, segments, tauri, tls, unpack, version, wifi,
};
use open_ctf_solvers::{
    CaesarOptions, CaesarReport, DecodeOptions, DecodeReport, HashOptions, HashReport, XorOptions, XorReport, caesar, decode,
    hash, xor,
};
use serde::{Deserialize, Serialize};

use crate::{
    CtfError, Result,
    carve::{CarveOptions, CarveReport},
    diff::DiffReport,
    dump::{DumpOptions, DumpReport},
    entropy::EntropyReport,
    find::{FindOptions, FindReport},
    text::{EncodedStringsReport, StringsOptions},
};

/// Parses a hex byte string such as `90,90` or `0x90 0x90`.
pub fn parse_hex(text: &str) -> Result<Vec<u8>> {
    data_binary_inspect::parse_hex(text).map_err(CtfError::from)
}

/// One opened file with the kernel-facing method names.
///
/// The inspection itself lives in [`BinarySession`]; this wrapper keeps the
/// `BinaryView` surface that callers and tests already use.
#[derive(Debug, Clone)]
pub struct BinaryView {
    session: BinarySession,
}

impl BinaryView {
    /// Opens a file from disk and detects its container.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let session = BinarySession::open(InspectOptions::new(path.as_ref()))?;
        Ok(Self { session })
    }

    /// Builds a view over bytes already in memory.
    pub fn from_bytes(path: impl Into<PathBuf>, bytes: Vec<u8>) -> Self {
        Self { session: BinarySession::from_bytes(path, bytes) }
    }

    /// Path this view was opened from.
    pub fn path(&self) -> &Path {
        self.session.path()
    }

    /// File size in bytes.
    pub fn size(&self) -> u64 {
        self.session.size()
    }

    /// Detected container.
    pub fn format(&self) -> BinaryFormat {
        self.session.format()
    }

    /// Detected architecture, or `unknown`.
    pub fn architecture(&self) -> Architecture {
        self.session.architecture()
    }

    /// Reports the container, architecture, hash and header fields.
    pub fn info(&self) -> Result<BinaryInfo> {
        self.session.info().map_err(CtfError::from)
    }

    /// Decodes the section table.
    pub fn sections(&self) -> Result<Vec<Section>> {
        self.session.sections().map_err(CtfError::from)
    }

    /// Extracts printable ASCII runs of at least `min_len` bytes.
    pub fn strings(&self, min_len: usize) -> Vec<StringHit> {
        self.session.strings(Some(min_len), None).hits
    }

    /// Extracts ASCII or ASCII-in-UTF-16LE runs with the requested encoding.
    pub fn strings_encoded(&self, options: &StringsOptions) -> Result<EncodedStringsReport> {
        crate::text::scan(&self.session, options)
    }

    /// Searches the whole file with a byte regex described by `options`.
    pub fn find(&self, options: &FindOptions) -> Result<FindReport> {
        crate::find::find(&self.session, options)
    }

    /// Exports a raw byte range from the file into a caller-chosen path.
    pub fn dump(&self, options: &DumpOptions) -> Result<DumpReport> {
        crate::dump::dump(&self.session, options)
    }

    /// Extracts the printable regions around every marker match.
    pub fn carve(&self, options: &CarveOptions) -> Result<CarveReport> {
        crate::carve::carve(&self.session, options)
    }

    /// Extracts the embedded assets of a Tauri v2 container.
    pub fn tauri_assets(&self, options: &TauriAssetsOptions) -> Result<TauriAssetsReport> {
        Ok(tauri::tauri_assets(&self.session, options)?)
    }

    /// Lists imported functions.
    pub fn imports(&self, limit: Option<usize>) -> Result<ImportsReport> {
        self.session.imports(limit).map_err(CtfError::from)
    }

    /// Lists exported symbols.
    pub fn exports(&self, limit: Option<usize>) -> Result<ExportsReport> {
        self.session.exports(limit).map_err(CtfError::from)
    }

    /// Lists debug or dynamic symbols.
    pub fn symbols(&self, limit: Option<usize>) -> Result<SymbolsReport> {
        self.session.symbols(limit).map_err(CtfError::from)
    }

    /// Lists PE debug directory entries and `CodeView` PDB records.
    pub fn debug(&self, limit: Option<usize>) -> Result<DebugReport> {
        Ok(debug::analyze(&self.session, limit)?)
    }

    /// Decodes the PE version resource (`RT_VERSION`).
    pub fn version(&self) -> Result<VersionReport> {
        Ok(version::analyze(&self.session)?)
    }

    /// Decodes Mach-O load commands, segments, sections, dylibs and identity.
    pub fn macho(&self) -> Result<MachOReport> {
        Ok(macho::analyze(&self.session)?)
    }

    /// Lists the Mach-O `LC_SYMTAB` symbol table.
    pub fn macho_symbols(&self, limit: Option<usize>) -> Result<MachOSymbolsReport> {
        Ok(macho::symbols(&self.session, limit)?)
    }

    /// Decodes the Mach-O `LC_FUNCTION_STARTS` delta table.
    pub fn macho_function_starts(&self, limit: Option<usize>) -> Result<MachOFunctionStartsReport> {
        Ok(macho::function_starts(&self.session, limit)?)
    }

    /// Decodes the dyld export trie of a Mach-O image.
    pub fn macho_exports(&self) -> Result<MachOExportsReport> {
        Ok(macho::exports(&self.session)?)
    }

    /// Lists the architecture slices of a fat/universal Mach-O container.
    pub fn macho_slices(&self) -> Result<MachOSlicesReport> {
        Ok(macho::slices(&self.session)?)
    }

    /// Decodes `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64`.
    pub fn macho_encryption(&self) -> Result<MachOEncryptionReport> {
        Ok(macho::encryption(&self.session)?)
    }

    /// Decodes `LC_DYLD_CHAINED_FIXUPS` imports and its starts table.
    pub fn macho_chained_fixups(&self) -> Result<MachOChainedFixupsReport> {
        Ok(macho::chained_fixups(&self.session)?)
    }

    /// Decodes the classic dyld bind, weak-bind and lazy-bind opcode streams.
    pub fn macho_bindings(&self) -> Result<MachOBindingsReport> {
        Ok(macho::bindings(&self.session)?)
    }

    /// Decodes the Mach-O embedded code signature and its first `CodeDirectory`.
    pub fn code_signature(&self) -> Result<MachOCodeSignatureReport> {
        Ok(code_signature::analyze(&self.session)?)
    }

    /// Writes one fat/universal Mach-O slice to a caller-chosen path.
    pub fn extract_slice(&self, index: usize, output: &Path) -> Result<MachOSliceExtraction> {
        Ok(macho::extract(&self.session, index, output)?)
    }

    /// Summarises the PE mitigation posture.
    pub fn mitigations(&self) -> Result<MitigationsReport> {
        Ok(mitigations::analyze(&self.session)?)
    }

    /// Lists the PE resource directory leaves.
    pub fn resources(&self) -> Result<ResourcesReport> {
        Ok(resources::analyze(&self.session)?)
    }

    /// Decodes the PE exception directory runtime functions.
    pub fn exception(&self) -> Result<PeExceptionReport> {
        Ok(pe_exception::analyze(&self.session)?)
    }

    /// Decodes the PE delay-import descriptors and their thunks.
    pub fn delay_imports(&self) -> Result<PeDelayImportsReport> {
        Ok(pe_delay_imports::analyze(&self.session)?)
    }

    /// Decodes the PE bound-import descriptors and their forwarder refs.
    pub fn bound_imports(&self) -> Result<PeBoundImportsReport> {
        Ok(pe_bound_imports::analyze(&self.session)?)
    }

    /// Decodes the Rich header build stamp between the DOS stub and the PE header.
    pub fn rich_header(&self) -> Result<PeRichHeaderReport> {
        Ok(pe_rich_header::analyze(&self.session)?)
    }

    /// Decodes the PE base relocation blocks.
    pub fn relocations(&self) -> Result<RelocationsReport> {
        Ok(relocations::analyze(&self.session)?)
    }

    /// Reports ELF `PT_INTERP` and `PT_DYNAMIC` dependencies.
    pub fn dynamic(&self) -> Result<ElfDynamicReport> {
        Ok(dynamic::analyze(&self.session)?)
    }

    /// Lists the ELF static symbol table (`.symtab`) entries.
    pub fn static_symbols(&self) -> Result<ElfStaticSymbolsReport> {
        Ok(elf_symbols::analyze(&self.session)?)
    }

    /// Decodes the ELF program header table.
    pub fn segments(&self) -> Result<ElfSegmentsReport> {
        Ok(segments::analyze(&self.session)?)
    }

    /// Decodes ELF notes: build id, GNU ABI tag and GNU properties.
    pub fn notes(&self) -> Result<ElfNotesReport> {
        Ok(notes::analyze(&self.session)?)
    }

    /// Lists the PE attribute certificate table entries.
    pub fn certificates(&self) -> Result<CertificatesReport> {
        Ok(certificates::analyze(&self.session)?)
    }

    /// Decodes the PE TLS directory and its callback array.
    pub fn tls(&self) -> Result<PeTlsReport> {
        Ok(tls::analyze(&self.session)?)
    }

    /// Decodes the PE load configuration directory.
    pub fn load_config(&self) -> Result<PeLoadConfigReport> {
        Ok(load_config::analyze(&self.session)?)
    }

    /// Decodes `x86` / `x64` instructions from one file offset.
    pub fn disasm(&self, options: &DisassembleOptions) -> Result<DisassemblyReport> {
        Ok(disasm::analyze(&self.session, options)?)
    }

    /// Compares this binary against another open binary.
    pub fn diff(&self, other: &Self) -> Result<DiffReport> {
        crate::diff::compare(&self.session, &other.session)
    }

    /// Computes whole-file and per-section entropy plus the PE overlay.
    pub fn entropy(&self) -> Result<EntropyReport> {
        crate::entropy::analyze(&self.session)
    }

    /// Reports the overlay offset, size, entropy and embedded container signatures.
    pub fn overlay(&self) -> Result<OverlayReport> {
        Ok(overlay::analyze(&self.session)?)
    }

    /// Decodes one embedded zlib, gzip or raw DEFLATE stream.
    pub fn inflate(&self, options: &InflateOptions) -> Result<InflateReport> {
        Ok(inflate::decode(&self.session, options)?)
    }

    /// Decodes one container (`7z`, `asar` or `NSIS`) selected or sniffed by `format`.
    pub fn unpack(&self, options: &UnpackOptions) -> Result<UnpackReport> {
        Ok(unpack::analyze(&self.session, options)?)
    }

    /// Decodes a CPython marshal stream or pyc container and disassembles it.
    pub fn pyc(&self, options: &PycOptions) -> Result<PycReport> {
        Ok(pyc::analyze(&self.session, options)?)
    }

    /// Identifies the container from anchored and embedded magic bytes.
    pub fn probe(&self, options: &ProbeOptions) -> Result<ProbeReport> {
        Ok(probe::analyze(&self.session, options)?)
    }

    /// Hashes the whole file or one byte range with the requested algorithm.
    pub fn hash(&self, options: &HashOptions) -> Result<HashReport> {
        Ok(hash::compute(&self.session, options)?)
    }

    /// Decodes one byte range with the selected text or byte codec.
    pub fn decode(&self, options: &DecodeOptions) -> Result<DecodeReport> {
        Ok(decode::analyze(&self.session, options)?)
    }

    /// Cracks or applies a single-byte XOR key over one byte range.
    pub fn xor(&self, options: &XorOptions) -> Result<XorReport> {
        Ok(xor::analyze(&self.session, options)?)
    }

    /// Scans executable sections, or one explicit range, for basic x64 gadgets.
    pub fn gadgets(&self, options: &GadgetOptions) -> Result<GadgetsReport> {
        Ok(gadgets::analyze(&self.session, options)?)
    }

    /// Identifies common packers from section names and image markers.
    pub fn packer(&self, options: &PackerOptions) -> Result<PackerReport> {
        Ok(packer::analyze(&self.session, options)?)
    }

    /// Decodes or brute-forces a Caesar rotation over one byte range.
    pub fn caesar(&self, options: &CaesarOptions) -> Result<CaesarReport> {
        Ok(caesar::analyze(&self.session, options)?)
    }

    /// Walks PNG chunks and extracts text and trailing data.
    pub fn png(&self, options: &PngOptions) -> Result<PngReport> {
        Ok(png::analyze(&self.session, options)?)
    }

    /// Summarizes one classic pcap capture.
    pub fn pcap(&self, options: &PcapOptions) -> Result<PcapReport> {
        Ok(pcap::analyze(&self.session, options)?)
    }

    /// Summarizes one 802.11 capture (pcapng or classic pcap).
    pub fn wifi(&self, options: &WifiOptions) -> Result<WifiReport> {
        Ok(wifi::analyze(&self.session, options)?)
    }

    /// Extracts four-way handshakes and tests candidate WPA2 passphrases.
    pub fn wifi_handshake(&self, options: &EapolOptions) -> Result<EapolReport> {
        Ok(wifi::analyze_handshakes(&self.session, options)?)
    }

    /// Searches for a hex, ASCII or UTF-16LE pattern.
    pub fn search(&self, options: &SearchOptions) -> Result<SearchReport> {
        self.session.search(options).map_err(CtfError::from)
    }

    /// Renders a canonical hex dump.
    pub fn hexdump(&self, offset: u64, length: u64) -> Result<String> {
        self.session.hexdump(Some(offset), Some(length)).map_err(CtfError::from)
    }

    /// Reads a byte range from the file.
    pub fn read_bytes(&self, offset: u64, length: u64) -> Result<&[u8]> {
        self.session.read(offset, length).map_err(CtfError::from)
    }

    /// Writes patched bytes back to the opened file, atomically.
    pub fn patch(&mut self, offset: u64, data: &[u8]) -> Result<PatchReport> {
        self.session.patch(offset, data, None).map_err(CtfError::from)
    }

    /// Writes a patched copy to `output`, or back to the source when omitted.
    pub fn patch_to(&mut self, offset: u64, data: &[u8], output: Option<&Path>) -> Result<PatchReport> {
        self.session.patch(offset, data, output).map_err(CtfError::from)
    }

    /// Maps an RVA or virtual address onto a file offset.
    pub fn rva_to_offset(&self, address: u64) -> Result<u64> {
        self.session.rva_to_offset(address).map_err(CtfError::from)
    }

    /// Maps a file offset onto an absolute virtual address.
    pub fn offset_to_va(&self, offset: u64) -> Result<u64> {
        self.session.offset_to_va(offset).map_err(CtfError::from)
    }

    /// Maps a file offset onto a PE image-relative address.
    pub fn offset_to_rva(&self, offset: u64) -> Result<u64> {
        self.session.offset_to_rva(offset).map_err(CtfError::from)
    }
}

fn default_min_string_len() -> usize {
    4
}

fn default_strings_limit() -> Option<usize> {
    Some(100)
}

fn default_hexdump_length() -> u64 {
    256
}

/// Inputs of one [`OpenCtf`] session.
///
/// Serialized as JSON with camelCase keys, so `{ "path": "...", "minStringLen": 4 }`
/// is the wire form the addon and the TypeScript client both use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenCtfOptions {
    /// Binary to open.
    pub path: PathBuf,
    /// Minimum printable run length used by [`OpenCtf::strings`] when no override is given.
    #[serde(default = "default_min_string_len")]
    pub min_string_len: usize,
    /// Default hit limit used by [`OpenCtf::strings`]; `null` means unlimited.
    #[serde(default = "default_strings_limit")]
    pub strings_limit: Option<usize>,
    /// Default byte count used by [`OpenCtf::hexdump`].
    #[serde(default = "default_hexdump_length")]
    pub hexdump_length: u64,
}

impl OpenCtfOptions {
    /// Builds options with the documented defaults for one path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            min_string_len: default_min_string_len(),
            strings_limit: default_strings_limit(),
            hexdump_length: default_hexdump_length(),
        }
    }

    fn inspect_options(&self) -> InspectOptions {
        InspectOptions {
            path: self.path.clone(),
            min_string_len: self.min_string_len,
            strings_limit: self.strings_limit,
            hexdump_length: self.hexdump_length,
        }
    }
}

/// One open binary plus the defaults every operation should use.
///
/// This is the product API: construct it with [`OpenCtfOptions`], then call the
/// orthogonal methods. Explicit arguments win over the defaults carried by the
/// options, so a session can be reused for several bounded queries.
#[derive(Debug, Clone)]
pub struct OpenCtf {
    session: BinarySession,
    options: OpenCtfOptions,
}

impl OpenCtf {
    /// Opens the binary named by `options`.
    pub fn new(options: OpenCtfOptions) -> Result<Self> {
        let session = BinarySession::open(options.inspect_options())?;
        Ok(Self { session, options })
    }

    /// Builds a session from its JSON wire form.
    pub fn from_options_json(raw: &str) -> Result<Self> {
        let options: OpenCtfOptions =
            serde_json::from_str(raw).map_err(|error| CtfError::parse(format!("invalid OpenCtfOptions: {error}")))?;
        Self::new(options)
    }

    /// Options this session was built from.
    pub fn options(&self) -> &OpenCtfOptions {
        &self.options
    }

    /// Path of the open binary.
    pub fn path(&self) -> &Path {
        self.session.path()
    }

    /// Header summary.
    pub fn info(&self) -> Result<BinaryInfo> {
        self.session.info().map_err(CtfError::from)
    }

    /// Section table.
    pub fn sections(&self) -> Result<Vec<Section>> {
        self.session.sections().map_err(CtfError::from)
    }

    /// Extracts printable strings, falling back to the session defaults.
    pub fn strings(&self, min_len: Option<usize>, limit: Option<usize>) -> StringsReport {
        self.session.strings(min_len, limit)
    }

    /// Extracts ASCII or ASCII-in-UTF-16LE strings described by `options`.
    pub fn strings_encoded(&self, options: &StringsOptions) -> Result<EncodedStringsReport> {
        crate::text::scan(&self.session, options)
    }

    /// Searches the whole file with a byte regex described by `options`.
    pub fn find(&self, options: &FindOptions) -> Result<FindReport> {
        crate::find::find(&self.session, options)
    }

    /// Exports a raw byte range from the file into a caller-chosen path.
    pub fn dump(&self, options: &DumpOptions) -> Result<DumpReport> {
        crate::dump::dump(&self.session, options)
    }

    /// Extracts the printable regions around every marker match.
    pub fn carve(&self, options: &CarveOptions) -> Result<CarveReport> {
        crate::carve::carve(&self.session, options)
    }

    /// Extracts the embedded assets of a Tauri v2 container.
    pub fn tauri_assets(&self, options: &TauriAssetsOptions) -> Result<TauriAssetsReport> {
        Ok(tauri::tauri_assets(&self.session, options)?)
    }

    /// Lists imported functions.
    pub fn imports(&self, limit: Option<usize>) -> Result<ImportsReport> {
        self.session.imports(limit).map_err(CtfError::from)
    }

    /// Lists exported symbols.
    pub fn exports(&self, limit: Option<usize>) -> Result<ExportsReport> {
        self.session.exports(limit).map_err(CtfError::from)
    }

    /// Lists debug or dynamic symbols.
    pub fn symbols(&self, limit: Option<usize>) -> Result<SymbolsReport> {
        self.session.symbols(limit).map_err(CtfError::from)
    }

    /// Lists PE debug directory entries and `CodeView` PDB records.
    pub fn debug(&self, limit: Option<usize>) -> Result<DebugReport> {
        Ok(debug::analyze(&self.session, limit)?)
    }

    /// Decodes the PE version resource (`RT_VERSION`).
    pub fn version(&self) -> Result<VersionReport> {
        Ok(version::analyze(&self.session)?)
    }

    /// Decodes Mach-O load commands, segments, sections, dylibs and identity.
    pub fn macho(&self) -> Result<MachOReport> {
        Ok(macho::analyze(&self.session)?)
    }

    /// Lists the Mach-O `LC_SYMTAB` symbol table.
    pub fn macho_symbols(&self, limit: Option<usize>) -> Result<MachOSymbolsReport> {
        Ok(macho::symbols(&self.session, limit)?)
    }

    /// Decodes the Mach-O `LC_FUNCTION_STARTS` delta table.
    pub fn macho_function_starts(&self, limit: Option<usize>) -> Result<MachOFunctionStartsReport> {
        Ok(macho::function_starts(&self.session, limit)?)
    }

    /// Decodes the dyld export trie of a Mach-O image.
    pub fn macho_exports(&self) -> Result<MachOExportsReport> {
        Ok(macho::exports(&self.session)?)
    }

    /// Lists the architecture slices of a fat/universal Mach-O container.
    pub fn macho_slices(&self) -> Result<MachOSlicesReport> {
        Ok(macho::slices(&self.session)?)
    }

    /// Decodes `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64`.
    pub fn macho_encryption(&self) -> Result<MachOEncryptionReport> {
        Ok(macho::encryption(&self.session)?)
    }

    /// Decodes `LC_DYLD_CHAINED_FIXUPS` imports and its starts table.
    pub fn macho_chained_fixups(&self) -> Result<MachOChainedFixupsReport> {
        Ok(macho::chained_fixups(&self.session)?)
    }

    /// Decodes the classic dyld bind, weak-bind and lazy-bind opcode streams.
    pub fn macho_bindings(&self) -> Result<MachOBindingsReport> {
        Ok(macho::bindings(&self.session)?)
    }

    /// Decodes the Mach-O embedded code signature and its first `CodeDirectory`.
    pub fn code_signature(&self) -> Result<MachOCodeSignatureReport> {
        Ok(code_signature::analyze(&self.session)?)
    }

    /// Writes one fat/universal Mach-O slice to a caller-chosen path.
    pub fn extract_slice(&self, index: usize, output: &Path) -> Result<MachOSliceExtraction> {
        Ok(macho::extract(&self.session, index, output)?)
    }

    /// Summarises the PE mitigation posture.
    pub fn mitigations(&self) -> Result<MitigationsReport> {
        Ok(mitigations::analyze(&self.session)?)
    }

    /// Lists the PE resource directory leaves.
    pub fn resources(&self) -> Result<ResourcesReport> {
        Ok(resources::analyze(&self.session)?)
    }

    /// Decodes the PE exception directory runtime functions.
    pub fn exception(&self) -> Result<PeExceptionReport> {
        Ok(pe_exception::analyze(&self.session)?)
    }

    /// Decodes the PE delay-import descriptors and their thunks.
    pub fn delay_imports(&self) -> Result<PeDelayImportsReport> {
        Ok(pe_delay_imports::analyze(&self.session)?)
    }

    /// Decodes the PE bound-import descriptors and their forwarder refs.
    pub fn bound_imports(&self) -> Result<PeBoundImportsReport> {
        Ok(pe_bound_imports::analyze(&self.session)?)
    }

    /// Decodes the Rich header build stamp between the DOS stub and the PE header.
    pub fn rich_header(&self) -> Result<PeRichHeaderReport> {
        Ok(pe_rich_header::analyze(&self.session)?)
    }

    /// Decodes the PE base relocation blocks.
    pub fn relocations(&self) -> Result<RelocationsReport> {
        Ok(relocations::analyze(&self.session)?)
    }

    /// Reports ELF `PT_INTERP` and `PT_DYNAMIC` dependencies.
    pub fn dynamic(&self) -> Result<ElfDynamicReport> {
        Ok(dynamic::analyze(&self.session)?)
    }

    /// Lists the ELF static symbol table (`.symtab`) entries.
    pub fn static_symbols(&self) -> Result<ElfStaticSymbolsReport> {
        Ok(elf_symbols::analyze(&self.session)?)
    }

    /// Decodes the ELF program header table.
    pub fn segments(&self) -> Result<ElfSegmentsReport> {
        Ok(segments::analyze(&self.session)?)
    }

    /// Decodes ELF notes: build id, GNU ABI tag and GNU properties.
    pub fn notes(&self) -> Result<ElfNotesReport> {
        Ok(notes::analyze(&self.session)?)
    }

    /// Lists the PE attribute certificate table entries.
    pub fn certificates(&self) -> Result<CertificatesReport> {
        Ok(certificates::analyze(&self.session)?)
    }

    /// Decodes the PE TLS directory and its callback array.
    pub fn tls(&self) -> Result<PeTlsReport> {
        Ok(tls::analyze(&self.session)?)
    }

    /// Decodes the PE load configuration directory.
    pub fn load_config(&self) -> Result<PeLoadConfigReport> {
        Ok(load_config::analyze(&self.session)?)
    }

    /// Decodes `x86` / `x64` instructions from one file offset.
    pub fn disasm(&self, options: &DisassembleOptions) -> Result<DisassemblyReport> {
        Ok(disasm::analyze(&self.session, options)?)
    }

    /// Compares this binary against another open binary.
    pub fn diff(&self, other: &Self) -> Result<DiffReport> {
        crate::diff::compare(&self.session, &other.session)
    }

    /// Computes whole-file and per-section entropy plus the PE overlay.
    pub fn entropy(&self) -> Result<EntropyReport> {
        crate::entropy::analyze(&self.session)
    }

    /// Reports the overlay offset, size, entropy and embedded container signatures.
    pub fn overlay(&self) -> Result<OverlayReport> {
        Ok(overlay::analyze(&self.session)?)
    }

    /// Decodes one embedded zlib, gzip or raw DEFLATE stream.
    pub fn inflate(&self, options: &InflateOptions) -> Result<InflateReport> {
        Ok(inflate::decode(&self.session, options)?)
    }

    /// Decodes one container (`7z`, `asar` or `NSIS`) selected or sniffed by `format`.
    pub fn unpack(&self, options: &UnpackOptions) -> Result<UnpackReport> {
        Ok(unpack::analyze(&self.session, options)?)
    }

    /// Decodes a CPython marshal stream or pyc container and disassembles it.
    pub fn pyc(&self, options: &PycOptions) -> Result<PycReport> {
        Ok(pyc::analyze(&self.session, options)?)
    }

    /// Identifies the container from anchored and embedded magic bytes.
    pub fn probe(&self, options: &ProbeOptions) -> Result<ProbeReport> {
        Ok(probe::analyze(&self.session, options)?)
    }

    /// Hashes the whole file or one byte range with the requested algorithm.
    pub fn hash(&self, options: &HashOptions) -> Result<HashReport> {
        Ok(hash::compute(&self.session, options)?)
    }

    /// Decodes one byte range with the selected text or byte codec.
    pub fn decode(&self, options: &DecodeOptions) -> Result<DecodeReport> {
        Ok(decode::analyze(&self.session, options)?)
    }

    /// Cracks or applies a single-byte XOR key over one byte range.
    pub fn xor(&self, options: &XorOptions) -> Result<XorReport> {
        Ok(xor::analyze(&self.session, options)?)
    }

    /// Scans executable sections, or one explicit range, for basic x64 gadgets.
    pub fn gadgets(&self, options: &GadgetOptions) -> Result<GadgetsReport> {
        Ok(gadgets::analyze(&self.session, options)?)
    }

    /// Identifies common packers from section names and image markers.
    pub fn packer(&self, options: &PackerOptions) -> Result<PackerReport> {
        Ok(packer::analyze(&self.session, options)?)
    }

    /// Decodes or brute-forces a Caesar rotation over one byte range.
    pub fn caesar(&self, options: &CaesarOptions) -> Result<CaesarReport> {
        Ok(caesar::analyze(&self.session, options)?)
    }

    /// Walks PNG chunks and extracts text and trailing data.
    pub fn png(&self, options: &PngOptions) -> Result<PngReport> {
        Ok(png::analyze(&self.session, options)?)
    }

    /// Summarizes one classic pcap capture.
    pub fn pcap(&self, options: &PcapOptions) -> Result<PcapReport> {
        Ok(pcap::analyze(&self.session, options)?)
    }

    /// Summarizes one 802.11 capture (pcapng or classic pcap).
    pub fn wifi(&self, options: &WifiOptions) -> Result<WifiReport> {
        Ok(wifi::analyze(&self.session, options)?)
    }

    /// Extracts four-way handshakes and tests candidate WPA2 passphrases.
    pub fn wifi_handshake(&self, options: &EapolOptions) -> Result<EapolReport> {
        Ok(wifi::analyze_handshakes(&self.session, options)?)
    }

    /// Searches for a hex, ASCII or UTF-16LE pattern.
    pub fn search(&self, options: &SearchOptions) -> Result<SearchReport> {
        self.session.search(options).map_err(CtfError::from)
    }

    /// Renders a hex dump, falling back to the session defaults.
    pub fn hexdump(&self, offset: Option<u64>, length: Option<u64>) -> Result<String> {
        self.session.hexdump(offset, length).map_err(CtfError::from)
    }

    /// Reads a byte range from the file.
    pub fn read(&self, offset: u64, length: u64) -> Result<&[u8]> {
        self.session.read(offset, length).map_err(CtfError::from)
    }

    /// Writes patched bytes back to the source, or to `output` when given.
    pub fn patch(&mut self, offset: u64, data: &[u8], output: Option<&Path>) -> Result<PatchReport> {
        self.session.patch(offset, data, output).map_err(CtfError::from)
    }

    /// Maps an RVA or virtual address onto a file offset.
    pub fn rva(&self, address: u64) -> Result<u64> {
        self.session.rva_to_offset(address).map_err(CtfError::from)
    }

    /// Maps a file offset onto an absolute virtual address.
    pub fn offset_to_va(&self, offset: u64) -> Result<u64> {
        self.session.offset_to_va(offset).map_err(CtfError::from)
    }

    /// Maps a file offset onto a PE image-relative address.
    pub fn offset_to_rva(&self, offset: u64) -> Result<u64> {
        self.session.offset_to_rva(offset).map_err(CtfError::from)
    }

    /// Borrows the underlying session for callers that need the raw engine.
    pub fn session(&self) -> &BinarySession {
        &self.session
    }
}

/// The product model of one opened artifact.
///
/// A challenge carries identity and classification only: the bytes stay in the
/// [`OpenCtf`] session, and every interpretation is recorded as evidence or a
/// candidate so the report can separate facts from guesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// File name of the opened artifact.
    pub name: String,
    /// Path the artifact was opened from.
    pub path: String,
    /// Detected container: `pe`, `elf`, `macho` or `unknown`.
    pub format: String,
    /// Detected architecture: `x86`, `x64`, `arm64` or `unknown`.
    pub architecture: String,
    /// File size in bytes.
    pub size: u64,
}

impl Challenge {
    /// Classifies one open session without reading any interpretation.
    pub fn of(session: &OpenCtf) -> Result<Self> {
        let info = session.info()?;
        Ok(Self {
            name: session
                .path()
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| session.path().display().to_string()),
            path: session.path().display().to_string(),
            format: info.format,
            architecture: info.architecture,
            size: info.size,
        })
    }
}
