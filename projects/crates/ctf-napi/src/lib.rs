//! Thin Node-API surface for OpenCTF.
//!
//! Every export performs one orthogonal operation and returns a JSON string, so
//! the TypeScript layer owns argument parsing, help text and exit codes. Binary
//! semantics stay in `open-ctf-domain`; this layer only forwards operations,
//! keeps the live handle table and hosts the WebView window. The CLI and the
//! studio share the same table, so a file opened from one is visible to the
//! other.
//!
//! The `#[function]` entry points and `register_module!` stay in the crate root
//! because the wae macros reference their generated registration items by bare
//! identifier; each entry point delegates to the domain modules below.

use wae::{CallContext, JsValue, Result, function, register_module};

mod commands;
#[doc(hidden)]
pub mod dto;
mod error;
mod webview;

use commands::{binary, challenge, solver};

/// One live engine table per process, shared by every surface.
mod registry {
    use std::{
        collections::HashMap,
        sync::{Mutex, MutexGuard, OnceLock},
    };

    use open_ctf_domain::{CtfError, OpenCtf, OpenCtfOptions};
    use serde_json::{Value, json};

    use crate::error::encoded;

    pub(crate) struct Registry {
        next: u64,
        pub(crate) engines: HashMap<u64, OpenCtf>,
    }

    fn registry() -> &'static Mutex<Registry> {
        static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(Registry { next: 1, engines: HashMap::new() }))
    }

    pub(crate) fn lock() -> std::result::Result<MutexGuard<'static, Registry>, CtfError> {
        registry().lock().map_err(|_| CtfError::io("the binary handle table is poisoned"))
    }

    pub(crate) fn missing(handle: u64) -> CtfError {
        CtfError::new("handle/invalid", format!("no live binary has handle {handle}"))
    }

    pub(crate) fn with_engine(
        handle: u64,
        work: impl FnOnce(&OpenCtf) -> std::result::Result<Value, CtfError>,
    ) -> std::result::Result<Value, CtfError> {
        let registry = lock()?;
        let engine = registry.engines.get(&handle).ok_or_else(|| missing(handle))?;
        work(engine)
    }

    pub(crate) fn with_engine_mut(
        handle: u64,
        work: impl FnOnce(&mut OpenCtf) -> std::result::Result<Value, CtfError>,
    ) -> std::result::Result<Value, CtfError> {
        let mut registry = lock()?;
        let engine = registry.engines.get_mut(&handle).ok_or_else(|| missing(handle))?;
        work(engine)
    }

    pub(crate) fn open_engine(options: OpenCtfOptions) -> std::result::Result<Value, CtfError> {
        let engine = OpenCtf::new(options)?;
        let info = encoded(&engine.info()?)?;
        let mut registry = lock()?;
        let handle = registry.next;
        registry.next += 1;
        registry.engines.insert(handle, engine);
        Ok(json!({ "handle": handle, "info": info }))
    }

    pub(crate) fn close_engine(handle: u64) -> std::result::Result<(), CtfError> {
        let mut registry = lock()?;
        registry.engines.remove(&handle).map(|_| ()).ok_or_else(|| missing(handle))
    }
}

/// Library version of the native binding.
#[function]
fn version(ctx: CallContext) -> Result<JsValue> {
    ctx.env().string(env!("CARGO_PKG_VERSION"))
}

/// Reports the implemented and explicitly unsupported capability matrix.
#[function]
fn capabilities(ctx: CallContext) -> Result<JsValue> {
    let matrix = open_ctf_domain::capabilities().to_string();
    ctx.env().string(&matrix)
}

/// Opens a binary session from its options JSON and returns its handle and header summary.
#[function]
fn binary_open(ctx: CallContext) -> Result<JsValue> {
    binary::binary_open(ctx)
}

/// Returns the header summary of an open binary.
#[function]
fn binary_info(ctx: CallContext) -> Result<JsValue> {
    binary::binary_info(ctx)
}

/// Returns the section table of an open binary.
#[function]
fn binary_sections(ctx: CallContext) -> Result<JsValue> {
    binary::binary_sections(ctx)
}

/// Extracts printable strings, bounded by a minimum length and an optional limit.
#[function]
fn binary_strings(ctx: CallContext) -> Result<JsValue> {
    binary::binary_strings(ctx)
}

/// Extracts ASCII or ASCII-in-UTF-16LE strings described by an options JSON.
#[function]
fn binary_strings_encoded(ctx: CallContext) -> Result<JsValue> {
    binary::binary_strings_encoded(ctx)
}

/// Searches the whole file with a byte regex described by an options JSON.
#[function]
fn binary_find(ctx: CallContext) -> Result<JsValue> {
    binary::binary_find(ctx)
}

/// Exports a raw byte range into a caller-chosen file, described by an options JSON.
#[function]
fn binary_dump(ctx: CallContext) -> Result<JsValue> {
    binary::binary_dump(ctx)
}

/// Carves the printable regions around marker matches, described by an options JSON.
#[function]
fn binary_carve(ctx: CallContext) -> Result<JsValue> {
    binary::binary_carve(ctx)
}

/// Extracts the embedded assets of a Tauri v2 container, described by an options JSON.
#[function]
fn binary_tauri_assets(ctx: CallContext) -> Result<JsValue> {
    binary::binary_tauri_assets(ctx)
}

/// Decodes one embedded zlib, gzip or raw DEFLATE stream, described by an options JSON.
#[function]
fn binary_inflate(ctx: CallContext) -> Result<JsValue> {
    binary::binary_inflate(ctx)
}

/// Identifies the container from magic bytes, described by an options JSON.
#[function]
fn binary_probe(ctx: CallContext) -> Result<JsValue> {
    challenge::binary_probe(ctx)
}

/// Hashes the whole file or one byte range, described by an options JSON.
#[function]
fn binary_hash(ctx: CallContext) -> Result<JsValue> {
    solver::binary_hash(ctx)
}

/// Decodes one byte range with the selected codec, described by an options JSON.
#[function]
fn binary_decode(ctx: CallContext) -> Result<JsValue> {
    solver::binary_decode(ctx)
}

/// Cracks or applies a single-byte XOR key, described by an options JSON.
#[function]
fn binary_xor(ctx: CallContext) -> Result<JsValue> {
    solver::binary_xor(ctx)
}

/// Scans executable sections for basic x64 gadgets, described by an options JSON.
#[function]
fn binary_gadgets(ctx: CallContext) -> Result<JsValue> {
    solver::binary_gadgets(ctx)
}

/// Decodes a JWT header and payload without verifying its signature.
#[function]
fn jwt_decode(ctx: CallContext) -> Result<JsValue> {
    solver::jwt_decode(ctx)
}

/// Identifies common packers from section names and image markers.
#[function]
fn binary_packer(ctx: CallContext) -> Result<JsValue> {
    challenge::binary_packer(ctx)
}

/// Decodes or brute-forces a Caesar rotation over one byte range.
#[function]
fn binary_caesar(ctx: CallContext) -> Result<JsValue> {
    solver::binary_caesar(ctx)
}

/// Walks PNG chunks and extracts text and trailing data.
#[function]
fn binary_png(ctx: CallContext) -> Result<JsValue> {
    challenge::binary_png(ctx)
}

/// Summarizes one classic pcap capture.
#[function]
fn binary_pcap(ctx: CallContext) -> Result<JsValue> {
    challenge::binary_pcap(ctx)
}

/// Decomposes one URL string without making a request.
#[function]
fn url_parse(ctx: CallContext) -> Result<JsValue> {
    solver::url_parse(ctx)
}

/// Generates a de Bruijn cyclic pattern and optionally locates a value.
#[function]
fn cyclic_run(ctx: CallContext) -> Result<JsValue> {
    solver::cyclic_run(ctx)
}

/// Decodes one `7z`, `asar`, `NSIS` or PyInstaller container, described by an options JSON.
#[function]
fn binary_unpack(ctx: CallContext) -> Result<JsValue> {
    binary::binary_unpack(ctx)
}

/// Reports the PE overlay anatomy and its embedded container signatures.
#[function]
fn binary_overlay(ctx: CallContext) -> Result<JsValue> {
    binary::binary_overlay(ctx)
}

/// Renders a canonical hex dump of one byte range.
#[function]
fn binary_hexdump(ctx: CallContext) -> Result<JsValue> {
    binary::binary_hexdump(ctx)
}

/// Reads one byte range and returns it as a hex string.
#[function]
fn binary_read(ctx: CallContext) -> Result<JsValue> {
    binary::binary_read(ctx)
}

/// Patches bytes atomically, writing a copy when an output path is given.
#[function]
fn binary_patch(ctx: CallContext) -> Result<JsValue> {
    binary::binary_patch(ctx)
}

/// Maps an RVA or virtual address onto a file offset.
#[function]
fn binary_rva(ctx: CallContext) -> Result<JsValue> {
    binary::binary_rva(ctx)
}

/// Lists imported functions.
#[function]
fn binary_imports(ctx: CallContext) -> Result<JsValue> {
    binary::binary_imports(ctx)
}

/// Lists exported symbols.
#[function]
fn binary_exports(ctx: CallContext) -> Result<JsValue> {
    binary::binary_exports(ctx)
}

/// Lists debug or dynamic symbols.
#[function]
fn binary_symbols(ctx: CallContext) -> Result<JsValue> {
    binary::binary_symbols(ctx)
}

/// Lists PE debug directory entries and `CodeView` PDB records.
#[function]
fn binary_debug(ctx: CallContext) -> Result<JsValue> {
    binary::binary_debug(ctx)
}

/// Decodes the PE version resource.
#[function]
fn binary_version(ctx: CallContext) -> Result<JsValue> {
    binary::binary_version(ctx)
}

/// Decodes Mach-O load commands, segments, sections, dylibs and identity.
#[function]
fn binary_macho(ctx: CallContext) -> Result<JsValue> {
    binary::binary_macho(ctx)
}

/// Lists the PE resource directory leaves.
#[function]
fn binary_resources(ctx: CallContext) -> Result<JsValue> {
    binary::binary_resources(ctx)
}

/// Summarises the PE mitigation posture.
#[function]
fn binary_mitigations(ctx: CallContext) -> Result<JsValue> {
    binary::binary_mitigations(ctx)
}

/// Decodes the PE exception directory runtime functions.
#[function]
fn binary_exception(ctx: CallContext) -> Result<JsValue> {
    binary::binary_exception(ctx)
}

/// Decodes the PE delay-import descriptors and their thunks.
#[function]
fn binary_delay_imports(ctx: CallContext) -> Result<JsValue> {
    binary::binary_delay_imports(ctx)
}

/// Decodes the PE bound-import descriptors and their forwarder refs.
#[function]
fn binary_bound_imports(ctx: CallContext) -> Result<JsValue> {
    binary::binary_bound_imports(ctx)
}

/// Decodes the Rich header build stamp between the DOS stub and the PE header.
#[function]
fn binary_rich_header(ctx: CallContext) -> Result<JsValue> {
    binary::binary_rich_header(ctx)
}

/// Lists the ELF static symbol table (`.symtab`) entries.
#[function]
fn binary_static_symbols(ctx: CallContext) -> Result<JsValue> {
    binary::binary_static_symbols(ctx)
}

/// Decodes the PE base relocation blocks.
#[function]
fn binary_relocations(ctx: CallContext) -> Result<JsValue> {
    binary::binary_relocations(ctx)
}

/// Reports ELF `PT_INTERP` and `PT_DYNAMIC` dependencies.
#[function]
fn binary_dynamic(ctx: CallContext) -> Result<JsValue> {
    binary::binary_dynamic(ctx)
}

/// Decodes ELF notes: build id, GNU ABI tag and GNU properties.
#[function]
fn binary_notes(ctx: CallContext) -> Result<JsValue> {
    binary::binary_notes(ctx)
}

/// Lists the PE attribute certificate table entries.
#[function]
fn binary_certificates(ctx: CallContext) -> Result<JsValue> {
    binary::binary_certificates(ctx)
}

/// Decodes the PE TLS directory and its callback array.
#[function]
fn binary_tls(ctx: CallContext) -> Result<JsValue> {
    binary::binary_tls(ctx)
}

/// Decodes the PE load configuration directory.
#[function]
fn binary_load_config(ctx: CallContext) -> Result<JsValue> {
    binary::binary_load_config(ctx)
}

/// Decodes the ELF program header table.
#[function]
fn binary_segments(ctx: CallContext) -> Result<JsValue> {
    binary::binary_segments(ctx)
}

/// Decodes the Mach-O embedded code signature.
#[function]
fn binary_code_signature(ctx: CallContext) -> Result<JsValue> {
    binary::binary_code_signature(ctx)
}

/// Lists the Mach-O `LC_SYMTAB` symbol table.
#[function]
fn binary_macho_symbols(ctx: CallContext) -> Result<JsValue> {
    binary::binary_macho_symbols(ctx)
}

/// Decodes the Mach-O dyld export trie.
#[function]
fn binary_macho_exports(ctx: CallContext) -> Result<JsValue> {
    binary::binary_macho_exports(ctx)
}

/// Decodes the Mach-O `LC_ENCRYPTION_INFO` command.
#[function]
fn binary_macho_encryption(ctx: CallContext) -> Result<JsValue> {
    binary::binary_macho_encryption(ctx)
}

/// Decodes the Mach-O `LC_DYLD_CHAINED_FIXUPS` imports.
#[function]
fn binary_macho_chained_fixups(ctx: CallContext) -> Result<JsValue> {
    binary::binary_macho_chained_fixups(ctx)
}

/// Decodes the Mach-O classic dyld bind opcode streams.
#[function]
fn binary_macho_bindings(ctx: CallContext) -> Result<JsValue> {
    binary::binary_macho_bindings(ctx)
}

/// Decodes the Mach-O function start delta table.
#[function]
fn binary_macho_function_starts(ctx: CallContext) -> Result<JsValue> {
    binary::binary_macho_function_starts(ctx)
}

/// Lists the architecture slices of a fat/universal Mach-O container.
#[function]
fn binary_macho_slices(ctx: CallContext) -> Result<JsValue> {
    binary::binary_macho_slices(ctx)
}

/// Writes one fat/universal Mach-O slice to `output`.
#[function]
fn binary_macho_extract(ctx: CallContext) -> Result<JsValue> {
    binary::binary_macho_extract(ctx)
}

/// Disassembles x86 / x64 instructions or CPython bytecode, described by an options JSON.
#[function]
fn binary_disasm(ctx: CallContext) -> Result<JsValue> {
    binary::binary_disasm(ctx)
}

/// Searches for a hex, ASCII or UTF-16LE pattern described by an options JSON.
#[function]
fn binary_search(ctx: CallContext) -> Result<JsValue> {
    binary::binary_search(ctx)
}

/// Computes whole-file and per-section entropy plus the PE overlay.
#[function]
fn binary_entropy(ctx: CallContext) -> Result<JsValue> {
    binary::binary_entropy(ctx)
}

/// Compares two open binaries byte for byte.
#[function]
fn binary_diff(ctx: CallContext) -> Result<JsValue> {
    binary::binary_diff(ctx)
}

/// Maps a file offset onto an absolute virtual address.
#[function]
fn binary_offset_to_va(ctx: CallContext) -> Result<JsValue> {
    binary::binary_offset_to_va(ctx)
}

/// Maps a file offset onto a PE image-relative address.
#[function]
fn binary_offset_to_rva(ctx: CallContext) -> Result<JsValue> {
    binary::binary_offset_to_rva(ctx)
}

/// Releases one binary handle.
#[function]
fn binary_close(ctx: CallContext) -> Result<JsValue> {
    binary::binary_close(ctx)
}

/// Opens the OpenCTF WebView window, or focuses the live one.
#[function(js_name = "openGui")]
fn open_gui(ctx: CallContext) -> Result<JsValue> {
    webview::open_gui(ctx)
}

/// Pumps the host message loop once and reports the observed lifecycle state.
#[function(js_name = "pumpEvents")]
fn pump_events(ctx: CallContext) -> Result<JsValue> {
    webview::pump_events(ctx)
}

/// Closes the OpenCTF window; the result distinguishes "already closed".
#[function(js_name = "closeGui")]
fn close_gui(ctx: CallContext) -> Result<JsValue> {
    webview::close_gui(ctx)
}

/// Reports whether the OpenCTF window is alive.
#[function(js_name = "isGuiOpen")]
fn is_gui_open(ctx: CallContext) -> Result<JsValue> {
    webview::is_gui_open(ctx)
}

register_module![
    version,
    capabilities,
    binary_open,
    binary_info,
    binary_sections,
    binary_strings,
    binary_strings_encoded,
    binary_hexdump,
    binary_read,
    binary_patch,
    binary_rva,
    binary_imports,
    binary_exports,
    binary_symbols,
    binary_debug,
    binary_version,
    binary_macho,
    binary_macho_symbols,
    binary_macho_function_starts,
    binary_macho_exports,
    binary_macho_encryption,
    binary_macho_chained_fixups,
    binary_macho_bindings,
    binary_macho_slices,
    binary_macho_extract,
    binary_mitigations,
    binary_resources,
    binary_relocations,
    binary_exception,
    binary_delay_imports,
    binary_bound_imports,
    binary_rich_header,
    binary_static_symbols,
    binary_dynamic,
    binary_notes,
    binary_certificates,
    binary_tls,
    binary_load_config,
    binary_segments,
    binary_code_signature,
    binary_disasm,
    binary_diff,
    binary_entropy,
    binary_search,
    binary_find,
    binary_dump,
    binary_carve,
    binary_tauri_assets,
    binary_inflate,
    binary_probe,
    binary_hash,
    binary_decode,
    binary_xor,
    binary_gadgets,
    jwt_decode,
    binary_packer,
    binary_caesar,
    binary_png,
    binary_pcap,
    url_parse,
    cyclic_run,
    binary_unpack,
    binary_overlay,
    binary_offset_to_va,
    binary_offset_to_rva,
    binary_close,
    open_gui,
    pump_events,
    close_gui,
    is_gui_open
];
