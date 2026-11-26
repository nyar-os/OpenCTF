//! ELF static symbol table listing.
//!
//! The upstream `symbols` view reports the dynamic symbol table; this module
//! walks the section headers to the first `SHT_SYMTAB` (`.symtab`) and reads
//! its entries together with the linked string table, so stripped-of-nothing
//! images expose their local and file-scope symbols too. The byte observation
//! is owned by `data-binary-pe::elf` (`parse_elf` + `read_elf_symbols`); this
//! module renders the `STT_*` type, `STB_*` binding, visibility and owning
//! section names, mapping `SHN_UNDEF`, `SHN_ABS` and `SHN_COMMON` to `UND`,
//! `ABS` and `COM`. A stripped image without `.symtab` reports
//! `present: false`.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::elf::{parse_elf, read_elf_symbols, sections_of_type};
use serde::{Deserialize, Serialize};

use crate::{CtfError, Result};

const SHT_SYMTAB: u32 = 2;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;

const MAX_STATIC_SYMBOLS: usize = 4_096;

/// One `.symtab` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfStaticSymbol {
    /// Name read from the linked string table, empty for the null symbol.
    pub name: String,
    /// `st_value`.
    pub value: u64,
    /// `st_size`.
    pub size: u64,
    /// `STT_*` name, or an empty string for an unknown type.
    pub symbol_type: String,
    /// `STB_*` name, or an empty string for an unknown binding.
    pub binding: String,
    /// Visibility name, or an empty string for an unknown one.
    pub visibility: String,
    /// Owning section name, or `UND`, `ABS`, `COM` and `sec <index>` fallbacks.
    pub section: String,
}

/// Bounded ELF static symbol listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElfStaticSymbolsReport {
    /// Whether the image has a `SHT_SYMTAB` section.
    pub present: bool,
    /// Whether the image uses the ELF64 layout.
    pub is64: bool,
    /// Symbols that survived the limit, in table order.
    pub symbols: Vec<ElfStaticSymbol>,
    /// Entries declared by the section size.
    pub total: usize,
    /// Whether a limit or unreadable data cut the listing.
    pub truncated: bool,
}

/// Lists the `.symtab` symbols of one session.
pub fn analyze(session: &BinarySession) -> Result<ElfStaticSymbolsReport> {
    if session.format() != BinaryFormat::Elf {
        return Err(CtfError::unsupported("ELF static symbols require an ELF container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = parse_elf(bytes).map_err(|error| CtfError::parse(format!("ELF: {error}")))?;
    let is64 = image.header.class.is_64();
    let empty = ElfStaticSymbolsReport { present: false, is64, symbols: Vec::new(), total: 0, truncated: false };
    let Some(symtab) = sections_of_type(&image, SHT_SYMTAB).into_iter().next()
    else {
        return Ok(empty);
    };

    let entries = read_elf_symbols(bytes, &image, symtab).map_err(|error| CtfError::parse(format!("ELF: {error}")))?;
    let total = entries.len();
    let mut report = ElfStaticSymbolsReport {
        present: true,
        is64,
        symbols: Vec::with_capacity(total.min(MAX_STATIC_SYMBOLS)),
        total,
        truncated: total > MAX_STATIC_SYMBOLS,
    };
    for entry in entries.into_iter().take(MAX_STATIC_SYMBOLS) {
        let section = match entry.section_index {
            SHN_UNDEF => "UND".to_string(),
            SHN_ABS => "ABS".to_string(),
            SHN_COMMON => "COM".to_string(),
            index => match image.sections.get(usize::from(index)) {
                Some(section) if !section.name.is_empty() => section.name.clone(),
                _ => format!("sec {index}"),
            },
        };
        let symbol_type = symbol_type_name(entry.kind()).to_string();
        let binding = binding_name(entry.binding()).to_string();
        let visibility = visibility_name(entry.other & 3).to_string();
        report.symbols.push(ElfStaticSymbol {
            name: entry.name,
            value: entry.value,
            size: entry.size,
            symbol_type,
            binding,
            visibility,
            section,
        });
    }
    Ok(report)
}

fn symbol_type_name(kind: u8) -> &'static str {
    match kind {
        0 => "NOTYPE",
        1 => "OBJECT",
        2 => "FUNC",
        3 => "SECTION",
        4 => "FILE",
        6 => "TLS",
        10 => "GNU_IFUNC",
        _ => "",
    }
}

fn binding_name(binding: u8) -> &'static str {
    match binding {
        0 => "LOCAL",
        1 => "GLOBAL",
        2 => "WEAK",
        10 => "GNU_UNIQUE",
        _ => "",
    }
}

fn visibility_name(visibility: u8) -> &'static str {
    match visibility {
        0 => "DEFAULT",
        1 => "INTERNAL",
        2 => "HIDDEN",
        3 => "PROTECTED",
        _ => "",
    }
}
