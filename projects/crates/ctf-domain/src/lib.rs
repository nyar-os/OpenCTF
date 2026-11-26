//! OpenCTF product domain.
//!
//! This crate owns the challenge model, the evidence log, the ranked candidates
//! and the assembled report. It orchestrates the owners around it and adds no
//! second parser:
//!
//! - `boost.rs/data-binary-inspect` performs the shared session work: open,
//!   header summary, section table, strings, search, hex dumps, byte reads,
//!   address mapping and atomic patching, plus the byte observation behind
//!   `text`, `find`, `dump`, `carve`, `diff` and `entropy`.
//! - `open-ctf-formats` projects the container, image, capture and archive
//!   facts a challenge needs.
//! - `open-ctf-solvers` owns the CTF algorithms: Caesar, XOR, cyclic patterns,
//!   decoders, digests, JWT and URLs.
//!
//! `text`, `find`, `dump`, `carve`, `diff` and `entropy` keep only the product
//! projection (options, paging, candidate/report shape); their byte observation
//! is read from the pinned `data-binary-inspect` revision recorded in
//! `documentation/duplication.md`.

#![recursion_limit = "256"]

pub mod candidates;
pub mod carve;
pub mod challenge;
pub mod diff;
pub mod dump;
pub mod entropy;
pub mod error;
pub mod evidence;
pub mod find;
pub mod report;
pub mod text;

/// Use-case orchestration: identify, triage, solve and verify.
pub mod workflow {
    pub mod identify;
    pub mod solve;
    pub mod triage;
    pub mod verify;
}

pub use candidates::{Candidate, CandidateSet};
pub use challenge::{BinaryView, Challenge, OpenCtf, OpenCtfOptions, parse_hex};
pub use error::{CtfError, Result};
pub use evidence::{Evidence, EvidenceKind};
pub use report::{ChallengeReport, capabilities};

// Format projections re-exported as the product surface.
/// Extracts the embedded assets of a Tauri v2 container.
pub use open_ctf_formats::scan_assets;
/// Whether a byte window looks like a `marshal` stream or a `.pyc` container.
pub use open_ctf_formats::sniff_pyc;
pub use open_ctf_formats::{
    AsarEntry, AsarHeader, AsarReport, CertificatesReport, CodeViewInfo, DebugEntry, DebugReport, DisassembleOptions,
    DisassemblyInstruction, DisassemblyReport, DisassemblySyntax, EapolHandshake, EapolMessage, EapolOptions, EapolReport,
    ElfAbiTag, ElfDynamicReport, ElfGnuProperty, ElfNote, ElfNotesReport, ElfSegment, ElfSegmentsReport, ElfStaticSymbol,
    ElfStaticSymbolsReport, FixedFileInfo, GadgetHit,
    GadgetOptions, GadgetsReport, InflateFormat, InflateOptions, InflateReport, MachOBinding, MachOBindingsReport,
    MachOChainedFixupsHeader, MachOChainedFixupsReport, MachOChainedImport, MachOCodeDirectory, MachOCodeSignatureReport,
    MachODylib, MachOEncryptionReport, MachOExport, MachOExportsReport, MachOFunctionStartsReport, MachOReport, MachOSection,
    MachOSegment, MachOSlice, MachOSliceExtraction, MachOSlicesReport, MachOSymbol, MachOSymbolsReport, MitigationsReport,
    NsisBlock, NsisCommand, NsisFile, NsisHeader, NsisReport, OverlayReport, OverlaySignature, PackerMatch, PackerOptions,
    PackerReport, PcapEndpoint, PcapOptions, PcapProtocol, PcapReport, PeBoundForwarder, PeBoundImportsReport, PeBoundModule,
    PeCertificate, PeDelayImportsReport, PeDelayModule, PeDelayThunk, PeExceptionReport, PeLoadConfigReport, PeResource,
    PeRichEntry, PeRichHeaderReport, PeRuntimeFunction, PeTlsCallback, PeTlsReport, PeUnwindInfo, PngChunk, PngOptions,
    PngReport, ProbeFinding, ProbeOptions, ProbeReport, PyInstallerEntry, PyInstallerModule, PyInstallerOptions,
    PyInstallerReport, PycCodeObject, PycConst, PycFormat, PycInstruction, PycOptions, PycReport, RelocationBlock,
    RelocationKindCount, RelocationsReport, ResourcesReport, SevenZEntry, SevenZFolder, SevenZPackRange, SevenZReport,
    TauriAsset, TauriAssetsOptions, TauriAssetsReport, UnpackFormat, UnpackOptions, UnpackReport, VersionReport, VersionString,
    WifiFrameType, WifiOptions, WifiReport, WifiSsid, WritableExecutableSection,
};

// Solver algorithms re-exported as the product surface.
/// Generates a de Bruijn cyclic pattern and optionally locates a value.
pub use open_ctf_solvers::cyclic;
/// Decodes one compact JWT without verifying its signature.
pub use open_ctf_solvers::decode_jwt;
/// Decomposes one URL string without making a request.
pub use open_ctf_solvers::parse_url;
pub use open_ctf_solvers::{
    CaesarCandidate, CaesarOptions, CaesarReport, CyclicOptions, CyclicReport, DecodeCodec, DecodeOptions, DecodeReport,
    DecodeStep, HashAlgorithm, HashOptions, HashReport, JwtReport, UrlParam, UrlReport, XorKeyGuess, XorOptions, XorReport,
};

// Shared inspection types re-exported so callers use one product surface.
pub use data_binary_inspect::{
    Architecture, BinaryFormat, BinaryInfo, BinarySession, ExportEntry, ExportsReport, ImportEntry, ImportsReport,
    InspectOptions, PatchReport, SearchHit, SearchMode, SearchOptions, SearchReport, SectionInfo as Section, StringHit,
    StringsReport, SymbolEntry, SymbolsReport,
};

// Product-side byte operations.
pub use carve::{CarveOptions, CarveRegion, CarveReport};
pub use diff::{DiffRange, DiffReport};
pub use dump::{DumpOptions, DumpReport};
pub use entropy::{EntropyReport, OverlayInfo, SectionEntropy};
pub use find::{FindHit, FindOptions, FindReport};
pub use text::{EncodedStringHit, EncodedStringsReport, StringEncoding, StringsOptions};

// Workflow entry points.
pub use workflow::{
    identify::{IdentifyOptions, identify},
    solve::{SolveOptions, solve},
    triage::{TriageOptions, triage},
    verify::{Verdict, VerifyRule, first_match, verify},
};
