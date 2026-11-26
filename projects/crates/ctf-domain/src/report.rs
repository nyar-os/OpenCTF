//! Product reports: the capability matrix and the assembled challenge report.
//!
//! `capabilities()` is the only support claim: a container may be recognised
//! and still unsupported, and a file suffix is never a support claim. The
//! assembled [`ChallengeReport`] keeps the three product-level groups — the
//! challenge itself, the evidence log and the ranked candidates — apart.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Candidate, Challenge, Evidence};

/// The three product-level groups of one analysis.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChallengeReport {
    /// Identity and classification of the opened artifact.
    pub challenge: Option<Challenge>,
    /// Everything observed, inferred, guessed or refused, in order.
    pub evidence: Vec<Evidence>,
    /// Ranked candidates produced by the solvers.
    pub candidates: Vec<Candidate>,
}

impl ChallengeReport {
    /// Starts a report for one identified challenge.
    pub fn new(challenge: Challenge) -> Self {
        Self { challenge: Some(challenge), evidence: Vec::new(), candidates: Vec::new() }
    }

    /// Appends one evidence record.
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    /// Appends several evidence records.
    pub fn with_evidence_all(mut self, evidence: impl IntoIterator<Item = Evidence>) -> Self {
        self.evidence.extend(evidence);
        self
    }

    /// Replaces the candidate list with the ranked view of `candidates`.
    pub fn with_candidates(mut self, candidates: &crate::CandidateSet) -> Self {
        self.candidates = candidates.ranked();
        self
    }
}

/// Reports what this build implements and what it explicitly does not.
pub fn capabilities() -> serde_json::Value {
    json!({
        "engine": { "package": "open-ctf-domain", "version": env!("CARGO_PKG_VERSION"), "api": "OpenCtf" },
        "upstream": {
            "inspect": "boost.rs/data-binary-inspect",
            "binary": "boost.rs/data-binary-pe",
            "machO": "boost.rs/data-binary-mach-o",
            "sevenZ": "boost.rs/data-binary-sevenz",
            "compression": "boost.rs/data-compression",
            "probe": "boost.rs/data-binary-probe",
            "crypto": "boost.rs/boost-crypto",
            "digest": "boost.rs/data-checksum",
        },
        "formats": {
            "pe": "supported",
            "elf": "supported",
            "macho": "partial",
            "unknown": "unsupported",
        },
        "features": {
            "info": "supported",
            "sections": "supported",
            "strings": "supported",
            "hexdump": "supported",
            "read": "supported",
            "patch": "supported",
            "rva": "supported",
            "imports": "supported",
            "exports": "supported",
            "symbols": "supported",
            "debug": "supported",
            "version": "supported",
            "macho-load-commands": "supported",
            "macho-segments": "supported",
            "macho-sections": "supported",
            "macho-dylibs": "supported",
            "macho-build-version": "supported",
            "macho-symbols": "supported",
            "macho-fat-slices": "supported",
            "macho-function-starts": "supported",
            "macho-exports": "supported",
            "macho-encryption": "supported",
            "macho-chained-fixups": "supported",
            "macho-bindings": "supported",
            "macho-slice-extraction": "supported",
            "macho-code-signature": "supported",
            "pe-mitigations": "supported",
            "pe-resources": "supported",
            "pe-relocations": "supported",
            "pe-exception": "supported",
            "pe-delay-imports": "supported",
            "pe-bound-imports": "supported",
            "pe-rich-header": "supported",
            "pe-certificates": "supported",
            "pe-tls": "supported",
            "pe-load-config": "supported",
            "elf-dynamic": "supported",
            "elf-static-symbols": "supported",
            "elf-notes": "supported",
            "elf-program-headers": "supported",
            "disassembly": "supported",
            "diff": "supported",
            "entropy": "supported",
            "overlay": "supported",
            "decompression": "supported",
            "unpack-archives": "supported",
            "sevenz-archives": "supported",
            "pyinstaller-archives": "supported",
            "cpython-bytecode": "supported",
            "search": "supported",
            "find": "supported",
            "dump": "supported",
            "carve": "supported",
            "tauri-assets": "supported",
            "offset-to-va": "supported",
            "offset-to-rva": "supported",
            "probe": "supported",
            "hash": "supported",
            "decode": "supported",
            "xor": "supported",
            "jwt": "supported",
            "gadgets": "supported",
            "url": "supported",
            "cyclic": "supported",
            "packer": "supported",
            "caesar": "supported",
            "png": "supported",
            "pcap": "supported",
        },
        "unsupported": {
            "decompilation": "not-implemented",
            "debugger": "not-implemented",
            "macho-import-bindings": "partial",
        },
        "architectures": {
            "x86": "supported",
            "x64": "supported",
            "arm64": "supported",
        },
    })
}
