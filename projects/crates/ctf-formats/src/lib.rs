//! CTF-side format projections.
//!
//! Each module reads one container, image, capture or archive and returns the
//! facts a challenge needs. The shared inspection session, the containers that
//! `boost.rs/data-binary-*` already owns, and the byte access primitives are
//! not re-implemented here.
//!
//! Status of the modules:
//!
//! - `owners` holds every projection whose parser moved to the pinned Boost
//!   revision: PE (`data-binary-pe::pe`), ELF (`data-binary-pe::elf`), Mach-O
//!   (`data-binary-mach-o::mach_o`) and the PyInstaller / `NSIS` / `asar` /
//!   Tauri / Python bytecode containers (`data-binary-container`). It opens the
//!   session, calls the owner and maps the owner type onto the existing report
//!   shape; no format constant or opcode table is decoded there.
//! - `pcap`, `png`, `packer`, `overlay` and `unpack` are the CTF projections
//!   this pass keeps; the frame, chunk, signature and 7z orchestration facts
//!   have no owner in the pinned revision.
//! - `disasm` calls `data-binary-x64::decode`, `probe` uses
//!   `data-binary-probe` and `inflate` calls `data-compression`; only the
//!   report projection stays here.
//!
//! The stable failure type is the upstream inspection error re-exported as
//! [`CtfError`], so a projection failure keeps the same wire code as its owner.

#![recursion_limit = "256"]

mod owners;

pub mod disasm;
pub mod gadgets;
pub mod inflate;
pub mod overlay;
pub mod packer;
pub mod pcap;
pub mod png;
pub mod probe;
pub mod unpack;
pub mod wifi;

pub use owners::*;

/// Python 3.11-3.13 opcode tables, re-exported from `data-binary-container`.
pub use data_binary_container::pyc_opcodes;

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
pub use wifi::{
    CaptureSupport, EapolHandshake, EapolMessage, EapolOptions, EapolReport, WifiFrameType, WifiOptions, WifiReport, WifiSsid,
    analyze_handshakes, capture_support,
};

/// Whether a byte window looks like a `marshal` stream or a `.pyc` container.
pub use pyc::sniff as sniff_pyc;

pub use data_binary_inspect::{Architecture, BinaryFormat, InspectError as CtfError, Result};
