//! CTF-side format projections.
//!
//! Each module reads one container, image, capture or archive and returns the
//! facts a challenge needs. The shared inspection session, the containers that
//! `boost.rs/data-binary-*` already owns, and the byte access primitives are
//! not re-implemented here.
//!
//! Status of the modules:
//!
//! - `pcap`, `png`, `packer` and `archive` are the CTF projections this pass
//!   keeps; the frame, chunk and signature facts move to their Boost owner once
//!   the pinned revision exposes them.
//! - `disasm` calls `data-binary-x64::decode`, `elf_symbols` calls
//!   `data-binary-pe::elf`, `macho/symbols` calls `data-binary-mach-o` and
//!   `probe` uses `data-binary-probe`; only the report projection stays here.
//! - The DEFLATE family in `inflate`, `nsis`, `pyinstaller` and `png` calls the
//!   pinned `boost.rs/data-compression` envelope; no local decoder remains.
//! - Every other module is a copy that duplicates an OpenIDA or Boost owner. It
//!   stays reachable because consumers still exist, carries a
//!   `TODO(boost): owner migration` marker, and is recorded in
//!   `documentation/duplication.md` with its target owner and the missing field.
//!
//! The stable failure type is the upstream inspection error re-exported as
//! [`CtfError`], so a projection failure keeps the same wire code as its owner.

#![recursion_limit = "256"]

pub mod archive;
pub mod certificates;
pub mod code_signature;
pub mod debug;
pub mod disasm;
pub mod dynamic;
pub mod elf_symbols;
pub mod gadgets;
pub mod inflate;
pub mod load_config;
pub mod macho;
pub mod mitigations;
pub mod notes;
pub mod nsis;
pub mod overlay;
pub mod packer;
pub mod pcap;
pub mod pe_bound_imports;
pub mod pe_delay_imports;
pub mod pe_exception;
pub mod pe_rich_header;
pub mod png;
pub mod probe;
pub mod pyc;
pub mod pyc_opcodes;
pub mod pyinstaller;
pub mod relocations;
pub mod resources;
pub mod segments;
pub mod tauri;
pub mod tls;
pub mod unpack;
pub mod version;

pub use archive::{AsarEntry, AsarHeader, AsarReport};
pub use certificates::{CertificatesReport, PeCertificate};
pub use code_signature::{MachOCodeDirectory, MachOCodeSignatureReport};
pub use debug::{CodeViewInfo, DebugEntry, DebugReport};
pub use disasm::{DisassembleOptions, DisassemblyInstruction, DisassemblyReport, DisassemblySyntax};
pub use dynamic::ElfDynamicReport;
pub use elf_symbols::{ElfStaticSymbol, ElfStaticSymbolsReport};
pub use gadgets::{GadgetHit, GadgetOptions, GadgetsReport};
pub use inflate::{InflateFormat, InflateOptions, InflateReport};
pub use load_config::{CodeIntegrityInfo, PeLoadConfigReport};
pub use macho::{
    MachOBinding, MachOBindingsReport, MachOChainedFixupsHeader, MachOChainedFixupsReport, MachOChainedImport, MachODylib,
    MachOEncryptionReport, MachOExport, MachOExportsReport, MachOFunctionStartsReport, MachOReport, MachOSection, MachOSegment,
    MachOSlice, MachOSliceExtraction, MachOSlicesReport, MachOSymbol, MachOSymbolsReport,
};
pub use mitigations::{MitigationsReport, WritableExecutableSection};
pub use notes::{ElfAbiTag, ElfGnuProperty, ElfNote, ElfNotesReport};
pub use nsis::{NsisBlock, NsisCommand, NsisFile, NsisHeader, NsisReport};
pub use overlay::{OverlayReport, OverlaySignature};
pub use packer::{PackerMatch, PackerOptions, PackerReport};
pub use pcap::{PcapEndpoint, PcapOptions, PcapProtocol, PcapReport};
pub use pe_bound_imports::{PeBoundForwarder, PeBoundImportsReport, PeBoundModule};
pub use pe_delay_imports::{PeDelayImportsReport, PeDelayModule, PeDelayThunk};
pub use pe_exception::{PeExceptionReport, PeRuntimeFunction, PeUnwindInfo};
pub use pe_rich_header::{PeRichEntry, PeRichHeaderReport};
pub use png::{PngChunk, PngOptions, PngReport};
pub use probe::{ProbeFinding, ProbeOptions, ProbeReport};
pub use pyc::{PycCodeObject, PycConst, PycFormat, PycInstruction, PycOptions, PycReport};
pub use pyinstaller::{PyInstallerEntry, PyInstallerModule, PyInstallerOptions, PyInstallerReport};
pub use relocations::{RelocationBlock, RelocationKindCount, RelocationsReport};
pub use resources::{PeResource, ResourcesReport};
pub use segments::{ElfSegment, ElfSegmentsReport};
pub use tauri::{TauriAsset, TauriAssetsOptions, TauriAssetsReport, scan_assets};
pub use tls::{PeTlsCallback, PeTlsReport};
pub use unpack::{SevenZEntry, SevenZFolder, SevenZPackRange, SevenZReport, UnpackFormat, UnpackOptions, UnpackReport};
pub use version::{FixedFileInfo, VersionReport, VersionString};

/// Whether a byte window looks like a `marshal` stream or a `.pyc` container.
pub use pyc::sniff as sniff_pyc;

pub use data_binary_inspect::{Architecture, BinaryFormat, InspectError as CtfError, Result};
