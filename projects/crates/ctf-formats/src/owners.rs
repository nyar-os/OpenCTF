//! Direct projections onto the pinned `boost.rs` format owners.
//!
//! Every module below used to carry its own parser. The pinned revision now
//! owns the byte observation (`data-binary-pe::pe`, `data-binary-pe::elf`,
//! `data-binary-mach-o::mach_o` and `data-binary-container`), so this file only
//! opens the session, calls the owner and maps the owner type onto the report
//! shape the kernel already exposes. No format constant, offset or opcode table
//! is decoded here.
//!
//! Types whose JSON shape is identical to the owner are re-exported under their
//! historical CTF name; the two shapes that still differ (Mach-O and the ELF
//! segment/note summaries) are projected field by field without renaming a
//! single report field.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_mach_o::mach_o::{self as macho_owner, MachOImage};
use data_binary_pe::pe;

use crate::{CtfError, Result};

/// Maps a container-owner failure onto the shared inspection error surface.
fn container_error(error: data_binary_container::ContainerError) -> CtfError {
    let message = error.to_string();
    match error.code() {
        "binary/unsupported" => CtfError::unsupported(message),
        "binary/range" => CtfError::range(message),
        "binary/io" => CtfError::io(message),
        _ => CtfError::parse(message),
    }
}

/// Reads the whole session and parses one PE image.
fn pe_image<'a>(session: &'a BinarySession, label: &str) -> Result<(&'a [u8], pe::PeImage)> {
    if session.format() != BinaryFormat::Pe {
        return Err(CtfError::unsupported(format!("{label} require a PE container")));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))?;
    Ok((bytes, image))
}

/// Reads the whole session and parses one thin Mach-O image.
fn macho_image<'a>(session: &'a BinarySession, label: &str) -> Result<(&'a [u8], MachOImage)> {
    let bytes = session.read(0, session.size())?;
    if macho_owner::fat_magic(bytes).is_some() {
        return Err(CtfError::unsupported("the Mach-O is a fat/universal container; use `macho-slices` and inspect a slice"));
    }
    if session.format() != BinaryFormat::MachO {
        return Err(CtfError::unsupported(format!("{label} require a Mach-O container")));
    }
    let image = macho_owner::parse_macho(bytes).map_err(|error| CtfError::parse(format!("Mach-O: {error}")))?;
    Ok((bytes, image))
}

pub mod certificates {
    //! PE attribute certificate table.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;

    use super::pe_image;
    use crate::{CtfError, Result};

    pub use data_binary_pe::pe::PeCertificate;

    /// Attribute certificate table summary.
    pub type CertificatesReport = pe::PeCertificatesReport;

    /// Decodes the PE attribute certificate table of one session.
    pub fn analyze(session: &BinarySession) -> Result<CertificatesReport> {
        let (bytes, image) = pe_image(session, "PE certificates")?;
        pe::read_certificates(&image, bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))
    }
}

pub mod debug {
    //! PE debug directory and `CodeView` records.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;
    use serde::{Deserialize, Serialize};

    use super::pe_image;
    use crate::{CtfError, Result};

    /// One `CodeView` record carried by a debug directory entry.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CodeViewInfo {
        /// Record magic: `RSDS` or `NB10`.
        pub signature: String,
        /// `RSDS` GUID, formatted as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
        pub guid: Option<String>,
        /// PDB age.
        pub age: u32,
        /// `NB10` record offset; `None` for `RSDS`.
        pub offset: Option<u32>,
        /// `NB10` timestamp; `None` for `RSDS`.
        pub timestamp: Option<u32>,
        /// PDB path as stored in the record, without the NUL terminator.
        pub path: String,
    }

    /// One `IMAGE_DEBUG_DIRECTORY` entry.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct DebugEntry {
        /// Debug type such as `codeview`, `fpo` or `pogo`.
        pub debug_type: String,
        /// COFF timestamp of the debug data.
        pub timestamp: u32,
        /// Major version of the debug data format.
        pub major_version: u16,
        /// Minor version of the debug data format.
        pub minor_version: u16,
        /// Size of the payload in bytes.
        pub size_of_data: u32,
        /// RVA of the payload.
        pub address_of_raw_data: u32,
        /// File offset of the payload.
        pub pointer_to_raw_data: u32,
        /// Decoded `CodeView` record, when this entry carries one.
        pub code_view: Option<CodeViewInfo>,
    }

    /// Bounded listing of [`DebugEntry`] values.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct DebugReport {
        /// Entries that survived the limit.
        pub entries: Vec<DebugEntry>,
        /// Number of entries before the limit was applied.
        pub total: usize,
        /// Whether the limit removed entries.
        pub truncated: bool,
    }

    /// Lists the debug directory of one open session.
    pub fn analyze(session: &BinarySession, limit: Option<usize>) -> Result<DebugReport> {
        let (bytes, image) = pe_image(session, "the PE debug directory")?;
        let entries =
            pe::read_debug_directory(&image, bytes).map_err(|error| CtfError::parse(format!("PE debug directory: {error}")))?;
        let total = entries.len();
        let limit = limit.unwrap_or(usize::MAX);
        Ok(DebugReport {
            truncated: total > limit,
            total,
            entries: entries
                .into_iter()
                .take(limit)
                .map(|entry| DebugEntry {
                    debug_type: entry.stable_type_name().to_string(),
                    timestamp: entry.timestamp,
                    major_version: entry.major_version,
                    minor_version: entry.minor_version,
                    size_of_data: entry.size_of_data,
                    address_of_raw_data: entry.address_of_raw_data,
                    pointer_to_raw_data: entry.pointer_to_raw_data,
                    code_view: entry.code_view.map(|view| {
                        let guid = view.guid_string();
                        CodeViewInfo {
                            signature: view.signature,
                            guid,
                            age: view.age,
                            offset: view.offset,
                            timestamp: view.timestamp,
                            path: view.path,
                        }
                    }),
                })
                .collect(),
        })
    }
}

pub mod pe_bound_imports {
    //! PE bound import table.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;

    use super::pe_image;
    use crate::{CtfError, Result};

    pub use data_binary_pe::pe::{PeBoundForwarder, PeBoundImportsReport, PeBoundModule};

    /// Decodes the bound import table of one session.
    pub fn analyze(session: &BinarySession) -> Result<PeBoundImportsReport> {
        let (bytes, image) = pe_image(session, "PE bound imports")?;
        pe::read_bound_imports(&image, bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))
    }
}

pub mod pe_delay_imports {
    //! PE delay-load import table.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;

    use super::pe_image;
    use crate::{CtfError, Result};

    pub use data_binary_pe::pe::{PeDelayImportsReport, PeDelayModule, PeDelayThunk};

    /// Decodes the delay-load import table of one session.
    pub fn analyze(session: &BinarySession) -> Result<PeDelayImportsReport> {
        let (bytes, image) = pe_image(session, "PE delay imports")?;
        pe::read_delay_imports(&image, bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))
    }
}

pub mod pe_exception {
    //! PE exception directory.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;

    use super::pe_image;
    use crate::{CtfError, Result};

    pub use data_binary_pe::pe::{PeExceptionReport, PeRuntimeFunction, PeUnwindInfo};

    /// Decodes the exception directory of one session.
    pub fn analyze(session: &BinarySession) -> Result<PeExceptionReport> {
        let (bytes, image) = pe_image(session, "PE exception directory")?;
        pe::read_exception_directory(&image, bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))
    }
}

pub mod pe_rich_header {
    //! PE rich header.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;

    use super::pe_image;
    use crate::{CtfError, Result};

    pub use data_binary_pe::pe::{PeRichEntry, PeRichHeaderReport};

    /// Decodes the rich header of one session.
    pub fn analyze(session: &BinarySession) -> Result<PeRichHeaderReport> {
        let (bytes, image) = pe_image(session, "PE rich headers")?;
        pe::read_rich_header(&image, bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))
    }
}

pub mod tls {
    //! PE TLS directory.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;

    use super::pe_image;
    use crate::{CtfError, Result};

    pub use data_binary_pe::pe::{PeTlsCallback, PeTlsReport};

    /// Decodes the TLS directory of one session.
    pub fn analyze(session: &BinarySession) -> Result<PeTlsReport> {
        let (bytes, image) = pe_image(session, "PE TLS directories")?;
        pe::read_tls_directory(&image, bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))
    }
}

pub mod load_config {
    //! PE load configuration.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;

    use super::pe_image;
    use crate::{CtfError, Result};

    pub use data_binary_pe::pe::{PeCodeIntegrityInfo as CodeIntegrityInfo, PeLoadConfigReport};

    /// Decodes the load configuration of one session.
    pub fn analyze(session: &BinarySession) -> Result<PeLoadConfigReport> {
        let (bytes, image) = pe_image(session, "PE load configurations")?;
        pe::read_load_config(&image, bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))
    }
}

pub mod mitigations {
    //! PE mitigation posture.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;

    use super::pe_image;
    use crate::{CtfError, Result};

    pub use data_binary_pe::pe::PeWritableExecutableSection as WritableExecutableSection;

    /// PE mitigation posture.
    pub type MitigationsReport = pe::PeMitigationsReport;

    /// Summarises the PE mitigation posture of one session.
    pub fn analyze(session: &BinarySession) -> Result<MitigationsReport> {
        let (bytes, image) = pe_image(session, "PE mitigations")?;
        pe::read_mitigations(&image, bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))
    }
}

pub mod relocations {
    //! PE base relocations.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;

    use super::pe_image;
    use crate::{CtfError, Result};

    pub use data_binary_pe::pe::{PeRelocationBlock as RelocationBlock, PeRelocationKindCount as RelocationKindCount};

    /// Base relocation table summary.
    pub type RelocationsReport = pe::PeRelocationsReport;

    /// Decodes the base relocation table of one session.
    pub fn analyze(session: &BinarySession) -> Result<RelocationsReport> {
        let (bytes, image) = pe_image(session, "PE relocations")?;
        pe::read_relocations(&image, bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))
    }
}

pub mod resources {
    //! PE resource directory.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;

    use super::pe_image;
    use crate::{CtfError, Result};

    pub use data_binary_pe::pe::PeResource;

    /// Bounded resource directory listing.
    pub type ResourcesReport = pe::PeResourcesReport;

    /// Decodes the resource directory of one session.
    pub fn analyze(session: &BinarySession) -> Result<ResourcesReport> {
        let (bytes, image) = pe_image(session, "PE resources")?;
        pe::read_resources(&image, bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))
    }
}

pub mod version {
    //! PE version resources.

    use data_binary_inspect::BinarySession;
    use data_binary_pe::pe;

    use super::pe_image;
    use crate::{CtfError, Result};

    pub use data_binary_pe::pe::{PeFixedFileInfo as FixedFileInfo, PeVersionString as VersionString};

    /// Decoded version resource of one PE file.
    pub type VersionReport = pe::PeVersionReport;

    /// Decodes the version resource of one session.
    pub fn analyze(session: &BinarySession) -> Result<VersionReport> {
        let (bytes, image) = pe_image(session, "PE version resources")?;
        pe::read_version_resources(&image, bytes).map_err(|error| CtfError::parse(format!("PE: {error}")))
    }
}

pub mod dynamic {
    //! ELF dynamic dependencies.

    use data_binary_inspect::{BinaryFormat, BinarySession};
    use data_binary_pe::elf;
    use serde::{Deserialize, Serialize};

    use crate::{CtfError, Result};

    /// Dynamic linking facts of one ELF image.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ElfDynamicReport {
        /// Whether a `PT_DYNAMIC` segment exists.
        pub present: bool,
        /// `PT_INTERP` program interpreter, when the segment exists.
        pub interpreter: Option<String>,
        /// `DT_SONAME` of the image, when set.
        pub soname: Option<String>,
        /// `DT_NEEDED` library names, in dynamic entry order.
        pub needed: Vec<String>,
        /// Entries of `DT_RPATH`, split on `:`.
        pub rpath: Vec<String>,
        /// Entries of `DT_RUNPATH`, split on `:`.
        pub runpath: Vec<String>,
        /// `DT_*` entries read before `DT_NULL`.
        pub dynamic_entries: usize,
        /// Whether a limit cut the listing.
        pub truncated: bool,
    }

    /// Decodes the ELF dynamic dependencies of one session.
    pub fn analyze(session: &BinarySession) -> Result<ElfDynamicReport> {
        if session.format() != BinaryFormat::Elf {
            return Err(CtfError::unsupported("ELF dynamic dependencies require an ELF container"));
        }
        let bytes = session.read(0, session.size())?;
        let report = elf::read_dynamic(bytes).map_err(|error| CtfError::parse(format!("ELF: {error}")))?;
        Ok(ElfDynamicReport {
            present: report.present,
            interpreter: report.interpreter,
            soname: report.soname,
            needed: report.needed,
            rpath: report.rpath,
            runpath: report.runpath,
            dynamic_entries: report.dynamic_entries,
            truncated: report.truncated,
        })
    }
}

pub mod segments {
    //! ELF program headers.

    use data_binary_inspect::{BinaryFormat, BinarySession};
    use data_binary_pe::elf;
    use serde::{Deserialize, Serialize};

    use crate::{CtfError, Result};

    /// One program header entry.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ElfSegment {
        /// Index in the program header table.
        pub index: usize,
        /// Stable segment type name, or `0x<type>` for an unknown value.
        pub segment_type: String,
        /// Raw `p_type`.
        pub type_value: u32,
        /// File offset of the segment payload.
        pub offset: u64,
        /// Segment virtual address.
        pub virtual_address: u64,
        /// Segment physical address.
        pub physical_address: u64,
        /// Bytes stored in the file.
        pub file_size: u64,
        /// Bytes occupied in memory.
        pub memory_size: u64,
        /// Raw `p_flags`.
        pub flags: u32,
        /// `p_flags` rendered as permissions, such as `R-X`.
        pub flag_text: String,
        /// Alignment requirement.
        pub alignment: u64,
    }

    /// ELF program header table summary.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ElfSegmentsReport {
        /// Whether the table contains at least one entry.
        pub present: bool,
        /// Whether the image uses the 64-bit program header layout.
        pub is64: bool,
        /// Entries that survived the limit, in table order.
        pub segments: Vec<ElfSegment>,
        /// Number of entries declared by the header.
        pub total: usize,
        /// Whether a limit or a malformed entry cut the listing.
        pub truncated: bool,
    }

    /// Decodes the ELF program header table of one session.
    pub fn analyze(session: &BinarySession) -> Result<ElfSegmentsReport> {
        if session.format() != BinaryFormat::Elf {
            return Err(CtfError::unsupported("ELF program headers require an ELF container"));
        }
        let bytes = session.read(0, session.size())?;
        let report = elf::read_program_headers(bytes).map_err(|error| CtfError::parse(format!("ELF: {error}")))?;
        Ok(ElfSegmentsReport {
            present: !report.segments.is_empty(),
            is64: report.is_64,
            total: report.total,
            truncated: report.truncated,
            segments: report
                .segments
                .into_iter()
                .map(|segment| ElfSegment {
                    index: segment.index,
                    segment_type: segment.segment_type.name(),
                    type_value: segment.segment_type.value(),
                    offset: segment.offset,
                    virtual_address: segment.virtual_address,
                    physical_address: segment.physical_address,
                    file_size: segment.file_size,
                    memory_size: segment.memory_size,
                    flags: segment.flags,
                    flag_text: segment.flag_text(),
                    alignment: segment.alignment,
                })
                .collect(),
        })
    }
}

pub mod notes {
    //! ELF notes.

    use data_binary_inspect::{BinaryFormat, BinarySession};
    use data_binary_pe::elf;
    use serde::{Deserialize, Serialize};

    use crate::{CtfError, Result};

    /// Decoded `NT_GNU_ABI_TAG` description.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ElfAbiTag {
        /// Target operating system recorded by the tag.
        pub os: String,
        /// Major kernel version.
        pub major: u32,
        /// Minor kernel version.
        pub minor: u32,
        /// Sub-minor kernel version.
        pub subminor: u32,
    }

    /// One entry of a `NT_GNU_PROPERTY_TYPE_0` note.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ElfGnuProperty {
        /// Stable property name, or `0x<type>` for an unknown value.
        pub property_type: String,
        /// Declared size of this property's data.
        pub data_size: u32,
        /// Property data as lowercase hex, bounded by the preview limit.
        pub data: String,
    }

    /// One note record.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ElfNote {
        /// Note owner without its NUL terminator, such as `GNU`.
        pub owner: String,
        /// Stable note type name, or `type <n>` for an unknown value.
        pub note_type: String,
        /// Declared description size in bytes.
        pub description_size: u32,
        /// Decoded description: build id hex, ABI tag version, property count or a
        /// bounded hex preview.
        pub description: String,
    }

    /// ELF note facts of one image.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ElfNotesReport {
        /// Whether at least one note region exists.
        pub present: bool,
        /// Where the notes were read from: `segments` or `sections`.
        pub source: Option<String>,
        /// `NT_GNU_BUILD_ID` as lowercase hex, when present.
        pub build_id: Option<String>,
        /// Decoded `NT_GNU_ABI_TAG`, when present.
        pub abi_tag: Option<ElfAbiTag>,
        /// Entries of the first `NT_GNU_PROPERTY_TYPE_0` note.
        pub properties: Vec<ElfGnuProperty>,
        /// Notes that survived the listing limit, in file order.
        pub notes: Vec<ElfNote>,
        /// Number of notes read before the limit was applied.
        pub total: usize,
        /// Whether a limit or a malformed record cut the listing.
        pub truncated: bool,
    }

    /// Decodes the ELF notes of one session.
    pub fn analyze(session: &BinarySession) -> Result<ElfNotesReport> {
        if session.format() != BinaryFormat::Elf {
            return Err(CtfError::unsupported("ELF notes require an ELF container"));
        }
        let bytes = session.read(0, session.size())?;
        let report = elf::read_notes(bytes).map_err(|error| CtfError::parse(format!("ELF: {error}")))?;
        Ok(ElfNotesReport {
            present: report.present,
            source: report.source.map(|source| source.as_str().to_string()),
            build_id: report.build_id,
            abi_tag: report.abi_tag.map(|tag| ElfAbiTag {
                os: tag.os,
                major: tag.major,
                minor: tag.minor,
                subminor: tag.subminor,
            }),
            properties: report
                .properties
                .into_iter()
                .map(|property| ElfGnuProperty {
                    property_type: property.property_type,
                    data_size: property.data_size,
                    data: property.data,
                })
                .collect(),
            notes: report
                .notes
                .into_iter()
                .map(|note| ElfNote {
                    owner: note.owner,
                    note_type: note.note_type,
                    description_size: note.description_size,
                    description: note.description,
                })
                .collect(),
            total: report.total,
            truncated: report.truncated,
        })
    }
}

pub mod elf_symbols {
    //! ELF static symbol table.

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
}

pub mod macho {
    //! Mach-O image projections onto `data-binary-mach-o::mach_o`.

    use std::path::Path;

    use data_binary_inspect::BinarySession;
    use data_binary_mach_o::mach_o::{
        self as owner, MachOEndian, MachOImage, read_bindings, read_chained_fixups, read_exports, read_fat_slices,
        read_function_starts, read_macho_symbols, render_version,
    };
    use serde::{Deserialize, Serialize};

    use super::{CtfError, Result, macho_image};

    const MAX_BINDINGS: usize = 512;
    const MAX_EXPORTS_SLICE: usize = 512;

    /// One linked or identifying dylib command.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachODylib {
        /// Command kind: `load`, `id`, `weak`, `reexport`, `lazy` or `upward`.
        pub kind: String,
        /// Install name stored in the command.
        pub name: String,
        /// Build timestamp recorded by the linker.
        pub timestamp: u32,
        /// Packed current version rendered as `major.minor.patch`.
        pub current_version: String,
        /// Packed compatibility version rendered as `major.minor.patch`.
        pub compatibility_version: String,
    }

    /// One segment load command.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOSegment {
        /// Segment name, such as `__TEXT`.
        pub name: String,
        /// Virtual address of the first byte.
        pub vm_address: u64,
        /// Size in memory.
        pub vm_size: u64,
        /// File offset of the first byte.
        pub file_offset: u64,
        /// Size in the file.
        pub file_size: u64,
        /// Whether the segment is readable.
        pub readable: bool,
        /// Whether the segment is writable.
        pub writable: bool,
        /// Whether the segment is executable.
        pub executable: bool,
    }

    /// One section entry with its owning segment.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOSection {
        /// Owning segment name.
        pub segment: String,
        /// Section name, such as `__text`.
        pub name: String,
        /// Virtual address of the first byte.
        pub address: u64,
        /// Size in bytes.
        pub size: u64,
        /// File offset of the first byte.
        pub file_offset: u64,
        /// Alignment expressed as a power of two.
        pub alignment: u32,
        /// Raw `S_*` section flags.
        pub flags: u32,
        /// Whether the owning segment is readable.
        pub readable: bool,
        /// Whether the owning segment is writable.
        pub writable: bool,
        /// Whether the owning segment is executable.
        pub executable: bool,
    }

    /// Full Mach-O image summary.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOReport {
        /// Whether the file uses the 64-bit header layout.
        pub is_64: bool,
        /// Byte order as `little` or `big`.
        pub endian: String,
        /// Raw `cputype`.
        pub cpu_type: i32,
        /// Raw `cpusubtype`.
        pub cpu_subtype: i32,
        /// Instruction-set family derived from `cputype`.
        pub architecture: String,
        /// Raw `filetype`.
        pub file_type: u32,
        /// `filetype` rendered as a stable name.
        pub kind: String,
        /// Raw header flags.
        pub flags: u32,
        /// Number of load commands.
        pub command_count: u32,
        /// Declared size of the load-command area.
        pub size_of_commands: u32,
        /// `LC_UUID` rendered as a canonical UUID.
        pub uuid: Option<String>,
        /// Platform from `LC_BUILD_VERSION` or `LC_VERSION_MIN_*`.
        pub platform: Option<String>,
        /// Minimum OS version rendered as `major.minor.patch`.
        pub min_os: Option<String>,
        /// SDK version rendered as `major.minor.patch`.
        pub sdk: Option<String>,
        /// `LC_MAIN` entry file offset.
        pub entry_offset: Option<u64>,
        /// Entry point mapped onto a virtual address, when a segment or section covers it.
        pub entry_address: Option<u64>,
        /// Dylib load commands in file order.
        pub dylibs: Vec<MachODylib>,
        /// Segments in load-command order.
        pub segments: Vec<MachOSegment>,
        /// Sections in file order.
        pub sections: Vec<MachOSection>,
    }

    /// One `nlist` entry of the `LC_SYMTAB` symbol table.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOSymbol {
        /// Name resolved through the string table; empty when the index is out of range.
        pub name: String,
        /// `n_value`, which is a virtual address for defined symbols.
        pub address: u64,
        /// Symbol kind derived from `n_type & N_TYPE`.
        pub kind: String,
        /// Whether the symbol is external (`N_EXT`).
        pub external: bool,
        /// Whether the entry is a debugging stab (`N_STAB`).
        pub debug: bool,
        /// `n_sect` for section-relative symbols, otherwise `None`.
        pub section: Option<u8>,
        /// Raw `n_desc`, for example the library ordinal of an undefined symbol.
        pub descriptor: u16,
    }

    /// Bounded listing of [`MachOSymbol`] values from `LC_SYMTAB`.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOSymbolsReport {
        /// Symbols that survived the limit.
        pub symbols: Vec<MachOSymbol>,
        /// Number of entries declared by `LC_SYMTAB`.
        pub total: usize,
        /// Whether the limit removed symbols.
        pub truncated: bool,
        /// Size of the linked string table in bytes.
        pub string_table_size: u32,
    }

    /// One symbol decoded from the dyld export trie.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOExport {
        /// Accumulated symbol name.
        pub name: String,
        /// Raw export flags.
        pub flags: u64,
        /// Flag names: `WEAK`, `REEXPORT`, `STUB_AND_RESOLVER`.
        pub flag_names: Vec<String>,
        /// Symbol address for regular exports.
        pub address: Option<u64>,
        /// Library ordinal for reexports or stub address for stub-and-resolver.
        pub other: Option<u64>,
    }

    /// Bounded listing of symbols from the dyld export trie.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOExportsReport {
        /// Whether the image carries an export trie.
        pub present: bool,
        /// Decoded exports in trie order.
        pub exports: Vec<MachOExport>,
        /// Entries found before the storage limit.
        pub total: usize,
        /// Whether the limit or a malformed node cut the walk.
        pub truncated: bool,
    }

    /// Mach-O encryption information.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOEncryptionReport {
        /// Whether the image carries an encryption info load command.
        pub present: bool,
        /// File offset of the encrypted range.
        pub crypt_offset: u32,
        /// Size of the encrypted range in bytes.
        pub crypt_size: u32,
        /// Encryption system identifier; `0` means the image is not encrypted.
        pub crypt_id: u32,
        /// Convenience flag derived from `crypt_id != 0`.
        pub encrypted: bool,
        /// Whether the fields came from `LC_ENCRYPTION_INFO_64`.
        pub is_64: bool,
    }

    /// One decoded `CodeDirectory` blob.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOCodeDirectory {
        /// Blob format version, such as `0x20200`.
        pub version: u32,
        /// Raw `flags` field.
        pub flags: u32,
        /// `flags` decoded into stable names.
        pub flag_text: Vec<String>,
        /// Hash algorithm name.
        pub hash_type: String,
        /// Size of one hash in bytes.
        pub hash_size: u8,
        /// Page size in bytes, derived from the log2 field.
        pub page_size: u32,
        /// Number of bytes covered by the signature.
        pub code_limit: u64,
        /// Signing identifier, usually the bundle id.
        pub identifier: String,
        /// Team identifier, when present.
        pub team_id: Option<String>,
        /// Number of code slots.
        pub code_slots: u32,
        /// Number of special slots.
        pub special_slots: u32,
    }

    /// Embedded signature summary.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOCodeSignatureReport {
        /// Whether the image has an `LC_CODE_SIGNATURE` command.
        pub present: bool,
        /// File offset of the signature blob.
        pub data_offset: u32,
        /// Declared signature size in bytes.
        pub data_size: u32,
        /// SuperBlob magic rendered as a stable name.
        pub magic: Option<String>,
        /// Number of entries in the SuperBlob index.
        pub blob_count: Option<u32>,
        /// Blob type names in index order.
        pub blob_types: Vec<String>,
        /// First `CodeDirectory`, when one is indexed.
        pub code_directory: Option<MachOCodeDirectory>,
        /// Whether a limit or a malformed structure cut the report.
        pub truncated: bool,
    }

    /// One architecture slice of a fat/universal Mach-O.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOSlice {
        /// Zero-based position in the fat architecture table.
        pub index: usize,
        /// Raw `cputype`.
        pub cpu_type: i32,
        /// Raw `cpusubtype`.
        pub cpu_subtype: i32,
        /// Instruction-set family derived from `cputype`.
        pub architecture: String,
        /// File offset of the slice.
        pub offset: u64,
        /// Size of the slice in bytes.
        pub size: u64,
        /// Alignment expressed as a power of two.
        pub alignment: u32,
        /// Slice header bitness, when the slice starts with a Mach-O magic.
        pub bits: Option<u32>,
    }

    /// Fat/universal Mach-O architecture table.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOSlicesReport {
        /// Whether the fat header uses the 64-bit `fat_arch_64` layout.
        pub is_fat64: bool,
        /// Slices in table order.
        pub slices: Vec<MachOSlice>,
    }

    /// One fat slice written to a caller-chosen path.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOSliceExtraction {
        /// Zero-based position in the fat architecture table.
        pub index: usize,
        /// Instruction-set family of the extracted slice.
        pub architecture: String,
        /// Source file offset of the slice.
        pub offset: u64,
        /// Number of bytes written.
        pub size: u64,
        /// Destination path.
        pub output: String,
    }

    /// One import entry of the `LC_DYLD_CHAINED_FIXUPS` table.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOChainedImport {
        /// Library ordinal; negative values are special ordinals such as `-2`.
        pub lib_ordinal: i32,
        /// Whether the import is weak.
        pub weak_import: bool,
        /// Offset into the symbol string pool.
        pub name_offset: u32,
        /// Resolved symbol name; empty when the pool is compressed or the offset is out of range.
        pub name: String,
        /// Addend for the `ADDEND` / `ADDEND64` import formats.
        pub addend: Option<i64>,
    }

    /// Decoded `dyld_chained_fixups_header`.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOChainedFixupsHeader {
        /// Structural version recorded by the linker; currently `0`.
        pub fixups_version: u32,
        /// Offset of `dyld_chained_starts_in_image`, relative to the start of the chain data.
        pub starts_offset: u32,
        /// Offset of the imports table, relative to the start of the chain data.
        pub imports_offset: u32,
        /// Offset of the symbol string pool, relative to the start of the chain data.
        pub symbols_offset: u32,
        /// Number of declared imports.
        pub imports_count: u32,
        /// Import entry layout: `1`, `2` or `3`.
        pub imports_format: u32,
        /// Symbol pool encoding: `0` uncompressed, `1` zlib.
        pub symbols_format: u32,
    }

    /// Summary of `LC_DYLD_CHAINED_FIXUPS`.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOChainedFixupsReport {
        /// Whether the image carries the command.
        pub present: bool,
        /// File offset of the chain data.
        pub data_offset: u32,
        /// Size of the chain data in bytes.
        pub data_size: u32,
        /// Decoded header, when the chain data is long enough.
        pub header: Option<MachOChainedFixupsHeader>,
        /// Imports that survived the limit.
        pub imports: Vec<MachOChainedImport>,
        /// Whether the import limit removed entries.
        pub truncated: bool,
        /// Segment count of `dyld_chained_starts_in_image`.
        pub starts_in_image: Option<u32>,
        /// Number of segments with a non-empty chained-start table.
        pub starts_in_segment_count: usize,
    }

    /// One binding decoded from a classic dyld bind opcode stream.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOBinding {
        /// Stream the binding came from: `bind`, `weak` or `lazy`.
        pub stream: String,
        /// Virtual address of the bound slot.
        pub address: u64,
        /// Name of the segment covering `address`, empty when no segment does.
        pub segment: String,
        /// Trailing symbol name of the last `SET_SYMBOL_TRAILING_FLAGS_IMM`.
        pub symbol: String,
        /// Install name for positive library ordinals, or a special-ordinal label.
        pub dylib: String,
        /// Bind type from `SET_TYPE_IMM`.
        pub bind_type: String,
        /// Whether the symbol flags carry `BIND_SYMBOL_FLAGS_WEAK_IMPORT`.
        pub weak: bool,
        /// Addend from the last `SET_ADDEND_SLEB`.
        pub addend: i64,
    }

    /// Bounded listing of the classic dyld bind opcode streams.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOBindingsReport {
        /// Whether the image carries an `LC_DYLD_INFO` or `LC_DYLD_INFO_ONLY` command.
        pub present: bool,
        /// Bindings that survived the limit.
        pub bindings: Vec<MachOBinding>,
        /// Bindings found before the walk was cut.
        pub total: usize,
        /// Whether the limit or a malformed stream cut the walk.
        pub truncated: bool,
    }

    /// `LC_FUNCTION_STARTS` summary.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MachOFunctionStartsReport {
        /// Increment base: the `__TEXT` virtual address.
        pub image_base: u64,
        /// Absolute function start addresses in table order.
        pub addresses: Vec<u64>,
        /// Number of entries the encoded table declares.
        pub total: usize,
        /// Whether the limit removed addresses.
        pub truncated: bool,
    }

    /// Decodes the Mach-O load commands of one session.
    pub fn analyze(session: &BinarySession) -> Result<MachOReport> {
        let (_, image) = macho_image(session, "Mach-O inspection")?;
        let segments = image
            .segments
            .iter()
            .map(|segment| MachOSegment {
                name: segment.name.clone(),
                vm_address: segment.vm_address,
                vm_size: segment.vm_size,
                file_offset: segment.file_offset,
                file_size: segment.file_size,
                readable: segment.initial_protection & 1 != 0,
                writable: segment.initial_protection & 2 != 0,
                executable: segment.initial_protection & 4 != 0,
            })
            .collect::<Vec<_>>();
        let sections = image
            .sections
            .iter()
            .map(|section| {
                let protection = image
                    .segments
                    .iter()
                    .find(|segment| segment.name == section.segment)
                    .map_or(0, |segment| segment.initial_protection);
                MachOSection {
                    segment: section.segment.clone(),
                    name: section.name.clone(),
                    address: section.address,
                    size: section.size,
                    file_offset: section.file_offset,
                    alignment: section.alignment,
                    flags: section.flags,
                    readable: protection & 1 != 0,
                    writable: protection & 2 != 0,
                    executable: protection & 4 != 0,
                }
            })
            .collect::<Vec<_>>();
        let entry_offset = image.entry_offset;
        Ok(MachOReport {
            is_64: image.header.is_64,
            endian: match image.header.endian {
                MachOEndian::Little => "little".to_string(),
                MachOEndian::Big => "big".to_string(),
            },
            cpu_type: image.header.cpu_type,
            cpu_subtype: image.header.cpu_subtype,
            architecture: owner::architecture(image.header.cpu_type).as_str().to_string(),
            file_type: image.header.file_type,
            kind: file_type_name(image.header.file_type).to_string(),
            flags: image.header.flags,
            command_count: image.header.command_count,
            size_of_commands: image.header.size_of_commands,
            uuid: image.uuid_string(),
            platform: image.build.map(|build| build.platform.as_str().to_string()),
            min_os: image.build.map(|build| build.min_os_version()),
            sdk: image.build.map(|build| build.sdk_version()),
            entry_offset,
            entry_address: entry_offset.and_then(|offset| map_file_offset(&image, offset)),
            dylibs: image
                .dylibs
                .iter()
                .map(|dylib| MachODylib {
                    kind: dylib.kind.as_str().to_string(),
                    name: dylib.name.clone(),
                    timestamp: dylib.timestamp,
                    current_version: render_version(dylib.current_version),
                    compatibility_version: render_version(dylib.compatibility_version),
                })
                .collect(),
            segments,
            sections,
        })
    }

    /// Decodes the `LC_SYMTAB` symbol table of one session.
    pub fn symbols(session: &BinarySession, limit: Option<usize>) -> Result<MachOSymbolsReport> {
        let (bytes, image) = macho_image(session, "Mach-O symbols")?;
        let Some(symtab) = image.symtab
        else {
            return Err(CtfError::unsupported("the Mach-O has no LC_SYMTAB command"));
        };
        let total = symtab.symbol_count as usize;
        let limit = limit.unwrap_or(usize::MAX);
        let entries = read_macho_symbols(bytes, &image).map_err(|error| CtfError::parse(format!("Mach-O: {error}")))?;
        let symbols = entries
            .iter()
            .take(total.min(limit))
            .map(|entry| {
                let debug = entry.symbol_type & 0xe0 == 0xe0;
                let kind = if debug { "debug".to_string() } else { symbol_kind(entry.symbol_type).to_string() };
                MachOSymbol {
                    name: entry.name.clone(),
                    address: entry.value,
                    kind: kind.clone(),
                    external: entry.symbol_type & 0x01 != 0,
                    debug,
                    section: (kind == "section").then_some(entry.section),
                    descriptor: entry.description,
                }
            })
            .collect::<Vec<_>>();
        Ok(MachOSymbolsReport { truncated: total > symbols.len(), symbols, total, string_table_size: symtab.string_size })
    }

    /// Decodes `LC_FUNCTION_STARTS` of one session.
    pub fn function_starts(session: &BinarySession, limit: Option<usize>) -> Result<MachOFunctionStartsReport> {
        let (bytes, image) = macho_image(session, "Mach-O function starts")?;
        if image.function_starts.is_none() {
            return Err(CtfError::unsupported("the Mach-O has no LC_FUNCTION_STARTS command"));
        }
        let report = read_function_starts(bytes, &image, limit).map_err(|error| CtfError::parse(format!("Mach-O: {error}")))?;
        Ok(MachOFunctionStartsReport {
            image_base: report.image_base,
            addresses: report.addresses,
            total: report.total,
            truncated: report.truncated,
        })
    }

    /// Decodes the dyld export trie of one session.
    pub fn exports(session: &BinarySession) -> Result<MachOExportsReport> {
        let (bytes, image) = macho_image(session, "Mach-O exports")?;
        let report = read_exports(bytes, &image);
        Ok(MachOExportsReport {
            present: report.present,
            total: report.total,
            truncated: report.truncated,
            exports: report
                .exports
                .into_iter()
                .take(MAX_EXPORTS_SLICE)
                .map(|export| MachOExport {
                    name: export.name,
                    flags: export.flags,
                    flag_names: export.flag_names.into_iter().map(str::to_string).collect(),
                    address: export.address,
                    other: export.other,
                })
                .collect(),
        })
    }

    /// Lists the architecture slices of a fat/universal Mach-O container.
    pub fn slices(session: &BinarySession) -> Result<MachOSlicesReport> {
        let bytes = session.read(0, session.size())?;
        if owner::fat_magic(bytes).is_none() {
            return Err(CtfError::unsupported(
                "the file is not a fat/universal Mach-O container; a thin image is inspected with `macho`",
            ));
        }
        let report = read_fat_slices(bytes).map_err(|error| CtfError::parse(format!("Mach-O: {error}")))?;
        let slices = report
            .slices
            .into_iter()
            .map(|slice| {
                let bits = bytes
                    .get(slice.offset as usize..slice.offset.saturating_add(slice.size) as usize)
                    .and_then(owner::macho_magic)
                    .map(|(is_64, _)| if is_64 { 64 } else { 32 });
                MachOSlice {
                    index: slice.index,
                    cpu_type: slice.cpu_type,
                    cpu_subtype: slice.cpu_subtype,
                    architecture: slice.architecture.as_str().to_string(),
                    offset: slice.offset,
                    size: slice.size,
                    alignment: slice.alignment,
                    bits,
                }
            })
            .collect();
        Ok(MachOSlicesReport { is_fat64: report.is_fat64, slices })
    }

    /// Writes one fat slice to `output`.
    pub fn extract(session: &BinarySession, index: usize, output: &Path) -> Result<MachOSliceExtraction> {
        if output == session.path() {
            return Err(CtfError::io("refusing to overwrite the source container"));
        }
        let report = slices(session)?;
        let slice = report.slices.get(index).ok_or_else(|| {
            CtfError::range(format!("slice {index} is out of range; the container has {} slice(s)", report.slices.len()))
        })?;
        let bytes = session.read(0, session.size())?;
        let start =
            usize::try_from(slice.offset).map_err(|_| CtfError::range("the slice offset does not fit this platform"))?;
        let end = start
            .checked_add(usize::try_from(slice.size).map_err(|_| CtfError::range("the slice size does not fit this platform"))?)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| CtfError::parse("the slice lies outside the file"))?;
        std::fs::write(output, &bytes[start..end])
            .map_err(|error| CtfError::io(format!("cannot write {}: {error}", output.display())))?;
        Ok(MachOSliceExtraction {
            index: slice.index,
            architecture: slice.architecture.clone(),
            offset: slice.offset,
            size: slice.size,
            output: output.display().to_string(),
        })
    }

    /// Decodes `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64` of one session.
    pub fn encryption(session: &BinarySession) -> Result<MachOEncryptionReport> {
        let (_, image) = macho_image(session, "Mach-O encryption info")?;
        Ok(match image.encryption {
            Some(info) => MachOEncryptionReport {
                present: true,
                crypt_offset: info.crypt_offset,
                crypt_size: info.crypt_size,
                crypt_id: info.crypt_id,
                encrypted: info.encrypted(),
                is_64: info.is_64,
            },
            None => MachOEncryptionReport {
                present: false,
                crypt_offset: 0,
                crypt_size: 0,
                crypt_id: 0,
                encrypted: false,
                is_64: false,
            },
        })
    }

    /// Decodes `LC_DYLD_CHAINED_FIXUPS` of one session.
    pub fn chained_fixups(session: &BinarySession) -> Result<MachOChainedFixupsReport> {
        let (bytes, image) = macho_image(session, "Mach-O chained fixups")?;
        let report = read_chained_fixups(bytes, &image);
        Ok(MachOChainedFixupsReport {
            present: report.present,
            data_offset: report.data_offset,
            data_size: report.data_size,
            header: report.header.map(|header| MachOChainedFixupsHeader {
                fixups_version: header.fixups_version,
                starts_offset: header.starts_offset,
                imports_offset: header.imports_offset,
                symbols_offset: header.symbols_offset,
                imports_count: header.imports_count,
                imports_format: header.imports_format,
                symbols_format: header.symbols_format,
            }),
            imports: report
                .imports
                .into_iter()
                .map(|import| MachOChainedImport {
                    lib_ordinal: import.lib_ordinal,
                    weak_import: import.weak_import,
                    name_offset: import.name_offset,
                    name: import.name,
                    addend: import.addend,
                })
                .collect(),
            truncated: report.truncated,
            starts_in_image: report.starts_in_image,
            starts_in_segment_count: report.starts_in_segment_count,
        })
    }

    /// Decodes the classic dyld bind opcode streams of one session.
    pub fn bindings(session: &BinarySession) -> Result<MachOBindingsReport> {
        let (bytes, image) = macho_image(session, "Mach-O dyld bind opcodes")?;
        let present = image.dyld_info.is_some();
        let all = read_bindings(bytes, &image).map_err(|error| CtfError::parse(format!("Mach-O: {error}")))?;
        let total = all.len();
        let bindings = all
            .into_iter()
            .take(MAX_BINDINGS)
            .map(|binding| {
                let stream = binding.stream_name().to_string();
                let dylib = binding.dylib_name();
                let bind_type = binding.bind_type.name();
                MachOBinding {
                    stream,
                    address: binding.address,
                    segment: binding.segment,
                    symbol: binding.symbol,
                    dylib,
                    bind_type,
                    weak: binding.weak,
                    addend: binding.addend,
                }
            })
            .collect();
        Ok(MachOBindingsReport { present, bindings, total, truncated: total > MAX_BINDINGS })
    }

    fn symbol_kind(symbol_type: u8) -> &'static str {
        match symbol_type & 0x0e {
            0x0 => "undefined",
            0x2 => "absolute",
            0xa => "indirect",
            0xc => "prebound",
            0xe => "section",
            _ => "other",
        }
    }

    fn file_type_name(file_type: u32) -> &'static str {
        match file_type {
            0x1 => "object",
            0x2 => "executable",
            0x3 => "fvmlib",
            0x4 => "core",
            0x5 => "preload",
            0x6 => "dylib",
            0x7 => "dylinker",
            0x8 => "bundle",
            0x9 => "dylib-stub",
            0xa => "dsym",
            0xb => "kext-bundle",
            _ => "other",
        }
    }

    fn map_file_offset(image: &MachOImage, offset: u64) -> Option<u64> {
        for section in &image.sections {
            if section.size > 0 && offset >= section.file_offset && offset < section.file_offset.saturating_add(section.size) {
                return Some(section.address.saturating_add(offset - section.file_offset));
            }
        }
        for segment in &image.segments {
            if segment.file_size > 0
                && offset >= segment.file_offset
                && offset < segment.file_offset.saturating_add(segment.file_size)
            {
                return Some(segment.vm_address.saturating_add(offset - segment.file_offset));
            }
        }
        None
    }
}

pub mod code_signature {
    //! Mach-O embedded code signature.

    use data_binary_inspect::BinarySession;
    use data_binary_mach_o::mach_o::read_code_signature;

    use super::{Result, macho_image};

    pub use super::macho::{MachOCodeDirectory, MachOCodeSignatureReport};

    /// Decodes the embedded code signature of one session.
    pub fn analyze(session: &BinarySession) -> Result<MachOCodeSignatureReport> {
        let (bytes, image) = macho_image(session, "Mach-O code signatures")?;
        let report = read_code_signature(bytes, &image);
        Ok(MachOCodeSignatureReport {
            present: report.present,
            data_offset: report.data_offset,
            data_size: report.data_size,
            magic: report.magic,
            blob_count: report.blob_count,
            blob_types: report.blob_types,
            code_directory: report.code_directory.map(|directory| MachOCodeDirectory {
                version: directory.version,
                flags: directory.flags,
                flag_text: directory.flag_names.into_iter().map(str::to_string).collect(),
                hash_type: directory.hash_type,
                hash_size: directory.hash_size,
                page_size: directory.page_size,
                code_limit: directory.code_limit,
                identifier: directory.identifier,
                team_id: directory.team_id,
                code_slots: directory.code_slots,
                special_slots: directory.special_slots,
            }),
            truncated: report.truncated,
        })
    }
}

pub mod archive {
    //! Electron `asar` archives.

    pub use data_binary_container::asar::{AsarEntry, AsarHeader, AsarOptions, AsarReport};
}

pub mod nsis {
    //! `NSIS` installer containers.

    pub use data_binary_container::nsis::{NsisBlock, NsisCommand, NsisFile, NsisHeader, NsisOptions, NsisReport, SIGNATURE};
}

pub mod pyinstaller {
    //! PyInstaller bundles.

    pub use data_binary_container::pyinstaller::{
        PyInstallerEntry, PyInstallerModule, PyInstallerOptions, PyInstallerReport, analyze_carchive, analyze_pyz,
        locate_cookie, looks_like_pyz,
    };
}

pub mod pyc {
    //! Python bytecode and `.pyc` containers.

    use data_binary_container::pyc as owner;
    use data_binary_inspect::BinarySession;

    pub use data_binary_container::pyc::{PycCodeObject, PycConst, PycFormat, PycInstruction, PycOptions, PycReport};

    use super::container_error;
    use crate::Result;

    /// Decodes one `marshal` stream or `.pyc` container of one session.
    pub fn analyze(session: &BinarySession, options: &PycOptions) -> Result<PycReport> {
        let bytes = session.read(0, session.size())?;
        owner::analyze(bytes, options).map_err(container_error)
    }

    /// Whether a window of bytes looks like Python bytecode.
    pub use data_binary_container::pyc::sniff;
}

pub mod tauri {
    //! Tauri v2 embedded assets.

    use data_binary_inspect::{BinaryFormat, BinarySession};

    pub use data_binary_container::tauri::{TauriAsset, TauriAssetsOptions, TauriAssetsReport, scan_assets};

    use super::container_error;
    use crate::{CtfError, Result};

    /// Extracts the embedded assets of a Tauri v2 PE image.
    pub fn tauri_assets(session: &BinarySession, options: &TauriAssetsOptions) -> Result<TauriAssetsReport> {
        if session.format() != BinaryFormat::Pe {
            return Err(CtfError::parse("Tauri assets require a PE container"));
        }
        let bytes = session.read(0, session.size())?;
        data_binary_container::tauri::analyze(bytes, options).map_err(container_error)
    }
}
