//! Binary session and native format operations: open, headers, sections,
//! strings, raw bytes, patches, address mapping, comparison, the PE/ELF/Mach-O
//! directory reports, disassembly, search, find, dump, carve and container
//! decoding.

use std::path::Path;

use boost_crypto::encoding::hex_encode;
use open_ctf_domain::{
    CarveOptions, CtfError, DisassembleOptions, DisassemblySyntax, DumpOptions, FindOptions, InflateOptions, OpenCtfOptions,
    PycFormat, PycOptions, SearchOptions, StringsOptions, TauriAssetsOptions, UnpackOptions, sniff_pyc,
};
use serde::Deserialize;
use serde_json::{Value, json};
use wae::{CallContext, Error, JsValue, Result};

use crate::{
    error::{encoded, failure, handle, limit_value, number, optional_number, optional_text, respond, text},
    registry::{close_engine, lock, missing, open_engine, with_engine, with_engine_mut},
};

pub(crate) fn section_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| Ok(json!({ "sections": encoded(&engine.sections()?)? })))
}

pub(crate) fn strings_report(handle: u64, min_len: Option<u64>, limit: Option<u64>) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| {
        let min_len =
            min_len.map(|value| usize::try_from(value).map_err(|_| CtfError::range("`minLen` is too large"))).transpose()?;
        let limit = limit.map(|value| usize::try_from(value).unwrap_or(usize::MAX));
        encoded(&engine.strings(min_len, limit))
    })
}

fn strings_encoded_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<StringsOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid StringsOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.strings_encoded(&options)?))
}

pub(crate) fn hexdump_report(handle: u64, offset: Option<u64>, length: Option<u64>) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| {
        let resolved_offset = offset.unwrap_or(0);
        let resolved_length = length.unwrap_or(engine.options().hexdump_length);
        let text = engine.hexdump(Some(resolved_offset), Some(resolved_length))?;
        Ok(json!({ "offset": resolved_offset, "length": resolved_length, "text": text }))
    })
}

pub(crate) fn read_report(handle: u64, offset: u64, length: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| {
        let bytes = engine.read(offset, length)?;
        Ok(json!({ "offset": offset, "length": length, "hex": hex_encode(bytes) }))
    })
}

pub(crate) fn patch_report(
    handle: u64,
    offset: u64,
    hex_bytes: &str,
    output: Option<&Path>,
) -> std::result::Result<Value, CtfError> {
    let bytes = open_ctf_domain::parse_hex(hex_bytes)?;
    with_engine_mut(handle, |engine| encoded(&engine.patch(offset, &bytes, output)?))
}

pub(crate) fn rva_report(handle: u64, rva: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| Ok(json!({ "rva": rva, "offset": engine.rva(rva)? })))
}

pub(crate) fn imports_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.imports(limit_value(limit))?))
}

pub(crate) fn exports_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.exports(limit_value(limit))?))
}

pub(crate) fn symbols_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.symbols(limit_value(limit))?))
}

pub(crate) fn entropy_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.entropy()?))
}

pub(crate) fn diff_report(left: u64, right: u64) -> std::result::Result<Value, CtfError> {
    let registry = lock()?;
    let left_engine = registry.engines.get(&left).ok_or_else(|| missing(left))?;
    let right_engine = registry.engines.get(&right).ok_or_else(|| missing(right))?;
    encoded(&left_engine.diff(right_engine)?)
}

pub(crate) fn offset_to_va_report(handle: u64, offset: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| Ok(json!({ "offset": offset, "va": engine.offset_to_va(offset)? })))
}

pub(crate) fn offset_to_rva_report(handle: u64, offset: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| Ok(json!({ "offset": offset, "rva": engine.offset_to_rva(offset)? })))
}

pub(crate) fn binary_open(ctx: CallContext) -> Result<JsValue> {
    let raw = text(&ctx, 0)?;
    let options = serde_json::from_str::<OpenCtfOptions>(&raw)
        .map_err(|error| Error::new(format!("binary/parse: invalid options: {error}")))?;
    match open_engine(options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_info(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match with_engine(handle, |engine| encoded(&engine.info()?)) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_sections(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match section_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_strings(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let min_len = optional_number(&ctx, 1)?;
    let limit = optional_number(&ctx, 2)?;
    match strings_report(handle, min_len, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_strings_encoded(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match strings_encoded_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_hexdump(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = optional_number(&ctx, 1)?;
    let length = optional_number(&ctx, 2)?;
    match hexdump_report(handle, offset, length) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_read(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    let length = number(&ctx, 2)?;
    match read_report(handle, offset, length) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_patch(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    let hex_bytes = text(&ctx, 2)?;
    let output = optional_text(&ctx, 3)?;
    let path = output.as_deref().map(Path::new);
    match patch_report(handle, offset, &hex_bytes, path) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_rva(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let rva = number(&ctx, 1)?;
    match rva_report(handle, rva) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_imports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match imports_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_exports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match exports_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_symbols(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match symbols_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_entropy(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match entropy_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_diff(ctx: CallContext) -> Result<JsValue> {
    let left = handle(&ctx, 0)?;
    let right = handle(&ctx, 1)?;
    match diff_report(left, right) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_offset_to_va(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    match offset_to_va_report(handle, offset) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_offset_to_rva(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let offset = number(&ctx, 1)?;
    match offset_to_rva_report(handle, offset) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_close(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match close_engine(handle) {
        Ok(()) => ctx.env().boolean(true),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn debug_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.debug(limit_value(limit))?))
}

fn version_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.version()?))
}

fn mitigations_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.mitigations()?))
}

fn overlay_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.overlay()?))
}

fn resources_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.resources()?))
}

fn relocations_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.relocations()?))
}

fn exception_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.exception()?))
}

fn delay_imports_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.delay_imports()?))
}

fn bound_imports_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.bound_imports()?))
}

fn rich_header_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.rich_header()?))
}

fn certificates_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.certificates()?))
}

fn tls_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.tls()?))
}

fn load_config_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.load_config()?))
}

pub(crate) fn binary_debug(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match debug_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_version(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match version_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_mitigations(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match mitigations_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_overlay(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match overlay_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_resources(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match resources_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_relocations(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match relocations_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_exception(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match exception_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_delay_imports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match delay_imports_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_bound_imports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match bound_imports_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_rich_header(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match rich_header_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_certificates(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match certificates_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_tls(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match tls_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_load_config(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match load_config_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

fn static_symbols_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.static_symbols()?))
}

fn dynamic_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.dynamic()?))
}

fn notes_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.notes()?))
}

fn segments_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.segments()?))
}

pub(crate) fn binary_static_symbols(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match static_symbols_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_dynamic(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match dynamic_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_notes(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match notes_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_segments(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match segments_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

fn macho_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.macho()?))
}

fn macho_symbols_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.macho_symbols(limit_value(limit))?))
}

fn macho_slices_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.macho_slices()?))
}

fn macho_function_starts_report(handle: u64, limit: Option<u64>) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.macho_function_starts(limit_value(limit))?))
}

fn macho_exports_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.macho_exports()?))
}

fn macho_encryption_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.macho_encryption()?))
}

fn macho_chained_fixups_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.macho_chained_fixups()?))
}

fn macho_bindings_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.macho_bindings()?))
}

fn macho_extract_report(handle: u64, index: usize, output: &Path) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.extract_slice(index, output)?))
}

fn code_signature_report(handle: u64) -> std::result::Result<Value, CtfError> {
    with_engine(handle, |engine| encoded(&engine.code_signature()?))
}

pub(crate) fn binary_macho(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_symbols(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match macho_symbols_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_exports(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_exports_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_encryption(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_encryption_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_chained_fixups(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_chained_fixups_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_bindings(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_bindings_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_function_starts(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let limit = optional_number(&ctx, 1)?;
    match macho_function_starts_report(handle, limit) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_slices(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match macho_slices_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_macho_extract(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let index = number(&ctx, 1)?;
    let index = usize::try_from(index).map_err(|_| Error::new("binary/range: the slice index is too large"))?;
    let output = text(&ctx, 2)?;
    match macho_extract_report(handle, index, Path::new(&output)) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_code_signature(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    match code_signature_report(handle) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

/// Combined inputs of the unified disassembly route: `format` picks the
/// machine path (`x86`), the bytecode path (`pyc`) or a sniff of the bytes
/// at `offset` (`auto`). Fields irrelevant to the chosen path are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct DisasmInput {
    offset: Option<u64>,
    count: Option<usize>,
    syntax: Option<DisassemblySyntax>,
    format: Option<String>,
    code: Option<String>,
    python: Option<u16>,
    code_limit: Option<usize>,
    instruction_limit: Option<usize>,
}

pub(crate) fn disasm_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let input = serde_json::from_str::<DisasmInput>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid DisassembleOptions: {error}")))?;
    with_engine(handle, |engine| {
        let bytecode = match input.format.as_deref().unwrap_or("auto") {
            "x86" => false,
            "pyc" => true,
            "auto" => {
                let size = engine.session().size();
                let length = 8u64.min(size.saturating_sub(input.offset.unwrap_or(0)));
                length > 0 && sniff_pyc(engine.session().read(input.offset.unwrap_or(0), length)?)
            }
            other => {
                return Err(CtfError::parse(format!("unknown disassembly format `{other}`; expected auto, x86 or pyc")));
            }
        };
        if bytecode {
            let defaults = PycOptions::default();
            let options = PycOptions {
                offset: input.offset,
                format: PycFormat::Auto,
                code: input.code,
                python: input.python,
                code_limit: input.code_limit.unwrap_or(defaults.code_limit),
                instruction_limit: input.instruction_limit.unwrap_or(defaults.instruction_limit),
            };
            encoded(&engine.pyc(&options)?)
        }
        else {
            let defaults = DisassembleOptions::default();
            let options = DisassembleOptions {
                offset: input.offset.unwrap_or(defaults.offset),
                count: input.count.unwrap_or(defaults.count),
                syntax: input.syntax.unwrap_or(defaults.syntax),
            };
            encoded(&engine.disasm(&options)?)
        }
    })
}

pub(crate) fn search_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<SearchOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid SearchOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.search(&options)?))
}

fn find_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<FindOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid FindOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.find(&options)?))
}

fn dump_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<DumpOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid DumpOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.dump(&options)?))
}

fn carve_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<CarveOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid CarveOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.carve(&options)?))
}

fn tauri_assets_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<TauriAssetsOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid TauriAssetsOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.tauri_assets(&options)?))
}

fn inflate_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<InflateOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid InflateOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.inflate(&options)?))
}

fn unpack_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<UnpackOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid UnpackOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.unpack(&options)?))
}

pub(crate) fn binary_disasm(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match disasm_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_search(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match search_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_find(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match find_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_dump(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match dump_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_carve(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match carve_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_tauri_assets(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match tauri_assets_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_inflate(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match inflate_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_unpack(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match unpack_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}
