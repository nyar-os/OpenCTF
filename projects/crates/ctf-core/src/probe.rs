//! Magic-byte identification of the open file.
//!
//! Anchored signatures run through `boost.rs/data-binary-probe`, which returns
//! ranked candidates with evidence ranges. A bounded second pass reuses the
//! same [`BytePattern`] values to look for embedded container magics, and the
//! tail window is checked for the zip end-of-central-directory record. A magic
//! hit is reported as a candidate, never as a validated structure.

use boost_source::binary::MemorySource;
use data_binary_inspect::BinarySession;
use data_binary_probe::{BytePattern, Confidence, ProbeAnchor, ProbeSession, Signature};
use serde::{Deserialize, Serialize};

use crate::Result;

/// Default cap on bytes read for signature matching.
const DEFAULT_SCAN_LIMIT: u64 = 1024 * 1024;

/// Hard cap on bytes read for signature matching.
const MAX_SCAN_LIMIT: u64 = 64 * 1024 * 1024;

/// Default cap on reported findings.
const DEFAULT_FINDINGS_LIMIT: usize = 64;

/// Hard cap on reported findings.
const MAX_FINDINGS_LIMIT: usize = 4096;

/// Window searched backwards for the zip end-of-central-directory record.
const ZIP_TAIL_WINDOW: u64 = 66 * 1024;

/// The zip end-of-central-directory signature.
const ZIP_EOCD: &[u8] = b"PK\x05\x06";

/// Strong magics searched anywhere inside the scanned window.
const EMBEDDED_MAGICS: &[(&str, &[u8])] = &[
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("gif", b"GIF87a"),
    ("gif", b"GIF89a"),
    ("zip", b"PK\x03\x04"),
    ("rar", b"Rar!\x1a\x07"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("gzip", b"\x1f\x8b\x08"),
    ("pdf", b"%PDF-"),
    ("elf", b"\x7fELF"),
    ("sqlite", b"SQLite format 3\0"),
];

/// Inputs of one [`crate::OpenCtf::probe`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProbeOptions {
    /// Cap on reported findings; clamped to 4096.
    #[serde(default = "default_findings_limit")]
    pub limit: usize,
    /// Bytes read for signature matching; clamped to 64 MiB.
    #[serde(default = "default_scan_limit")]
    pub scan_limit: u64,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self { limit: default_findings_limit(), scan_limit: default_scan_limit() }
    }
}

/// One format hypothesis with its evidence offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeFinding {
    /// Format identifier the matching signature declared.
    pub format: String,
    /// Confidence tier: `hint`, `candidate` or `identified`.
    pub confidence: String,
    /// Absolute file offset of the matched magic.
    pub offset: u64,
    /// Number of matched bytes.
    pub length: u64,
    /// Why this candidate was produced.
    pub reason: String,
}

/// Result of one [`crate::OpenCtf::probe`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeReport {
    /// Total file size in bytes.
    pub size: u64,
    /// Bytes actually searched for signatures.
    pub scanned: u64,
    /// Candidates in file-offset order, cut at the limit.
    pub findings: Vec<ProbeFinding>,
    /// Whether the findings list was cut at the limit.
    pub truncated: bool,
}

fn default_findings_limit() -> usize {
    DEFAULT_FINDINGS_LIMIT
}

fn default_scan_limit() -> u64 {
    DEFAULT_SCAN_LIMIT
}

/// Identifies the container of one open session from its magic bytes.
pub fn analyze(session: &BinarySession, options: &ProbeOptions) -> Result<ProbeReport> {
    let size = session.size();
    if size == 0 {
        return Ok(ProbeReport { size, scanned: 0, findings: Vec::new(), truncated: false });
    }
    let limit = options.limit.clamp(1, MAX_FINDINGS_LIMIT);
    let scan_limit = options.scan_limit.clamp(1, MAX_SCAN_LIMIT);
    let head_len = size.min(scan_limit);
    let head = session.read(0, head_len)?;

    let mut findings = Vec::new();

    let memory = MemorySource::from_bytes(session.path().display().to_string(), head.to_vec());
    let mut probe = ProbeSession::new();
    for signature in anchored_signatures() {
        probe.register(signature);
    }
    for candidate in probe.probe(&memory) {
        let evidence = candidate.evidence_ranges.first();
        findings.push(ProbeFinding {
            format: candidate.format_id.clone(),
            confidence: confidence_label(candidate.confidence).to_string(),
            offset: evidence.map_or(0, |extent| extent.start),
            length: evidence.map_or(0, |extent| extent.len),
            reason: candidate.reasons.join("; "),
        });
    }

    for (format, magic) in EMBEDDED_MAGICS {
        let pattern = BytePattern::exact(magic);
        // The anchored pass already covers offset zero, so the embedded pass
        // starts at the first possible interior offset.
        let mut offset = 1usize;
        while offset + magic.len() <= head.len() {
            if pattern.matches_at(&head[offset..]) {
                findings.push(ProbeFinding {
                    format: (*format).to_string(),
                    confidence: confidence_label(Confidence::Candidate).to_string(),
                    offset: offset as u64,
                    length: magic.len() as u64,
                    reason: "embedded magic inside the scanned window".to_string(),
                });
                break;
            }
            offset += 1;
        }
    }

    if let Some(offset) = zip_eocd_offset(session)? {
        findings.push(ProbeFinding {
            format: "zip".to_string(),
            confidence: confidence_label(Confidence::Candidate).to_string(),
            offset,
            length: ZIP_EOCD.len() as u64,
            reason: "zip end-of-central-directory record in the tail window".to_string(),
        });
    }

    findings.sort_by(|left, right| left.offset.cmp(&right.offset).then_with(|| left.format.cmp(&right.format)));
    findings.dedup_by(|left, right| left.offset == right.offset && left.format == right.format);
    let truncated = findings.len() > limit;
    findings.truncate(limit);

    Ok(ProbeReport { size, scanned: head_len, findings, truncated })
}

/// Signatures evaluated at their declared anchor inside the head buffer.
fn anchored_signatures() -> Vec<Signature> {
    let mut signatures = vec![
        Signature::at_start("png", b"\x89PNG\r\n\x1a\n"),
        Signature::at_start("jpeg", b"\xff\xd8\xff"),
        Signature::at_start("gif", b"GIF87a"),
        Signature::at_start("gif", b"GIF89a"),
        Signature::at_start("bmp", b"BM"),
        Signature::at_start("pdf", b"%PDF-"),
        Signature::at_start("elf", b"\x7fELF"),
        Signature::at_start("pe", b"MZ"),
        Signature::at_start("macho", &[0xcf, 0xfa, 0xed, 0xfe]),
        Signature::at_start("macho", &[0xce, 0xfa, 0xed, 0xfe]),
        Signature::at_start("macho", &[0xfe, 0xed, 0xfa, 0xcf]),
        Signature::at_start("macho", &[0xfe, 0xed, 0xfa, 0xce]),
        Signature::at_start("cafebabe", b"\xca\xfe\xba\xbe"),
        Signature::at_start("wasm", b"\0asm"),
        Signature::at_start("zip", b"PK\x03\x04"),
        Signature::at_start("zip", b"PK\x05\x06"),
        Signature::at_start("rar", b"Rar!\x1a\x07"),
        Signature::at_start("7z", b"7z\xbc\xaf\x27\x1c"),
        Signature::at_start("gzip", b"\x1f\x8b"),
        Signature::at_start("xz", b"\xfd7zXZ\0"),
        Signature::at_start("bzip2", b"BZh"),
        Signature::at_start("zstd", b"\x28\xb5\x2f\xfd"),
        Signature::at_start("sqlite", b"SQLite format 3\0"),
        Signature::at_start("lua", b"\x1bLua"),
        Signature::at_start("dex", b"dex\n"),
        Signature::at_start("ogg", b"OggS"),
        Signature::at_start("mp3", b"ID3"),
        Signature::at_start("psd", b"8BPS"),
        Signature::at_start("pcap", b"\xd4\xc3\xb2\xa1"),
        Signature::at_start("pcap", b"\xa1\xb2\xc3\xd4"),
        Signature::at_start("pcapng", b"\x0a\x0d\x0d\x0a"),
    ];
    signatures.push(fixed_signature("tar", 257, b"ustar"));
    signatures.push(fixed_signature("webp", 8, b"WEBP"));
    signatures.push(fixed_signature("wav", 8, b"WAVE"));
    signatures.push(fixed_signature("avi", 8, b"AVI "));
    signatures
}

/// Builds a signature anchored at one fixed offset from the file start.
fn fixed_signature(format: &str, offset: u64, bytes: &[u8]) -> Signature {
    Signature {
        format_id: format.to_string(),
        anchor: ProbeAnchor::Fixed(offset),
        pattern: BytePattern::exact(bytes),
        priority: 0,
    }
}

/// Returns the last zip end-of-central-directory offset inside the tail window.
fn zip_eocd_offset(session: &BinarySession) -> Result<Option<u64>> {
    let size = session.size();
    let start = size.saturating_sub(ZIP_TAIL_WINDOW);
    let tail = session.read(start, size - start)?;
    if tail.len() < ZIP_EOCD.len() {
        return Ok(None);
    }
    let mut found = None;
    let mut index = 0usize;
    while index + ZIP_EOCD.len() <= tail.len() {
        if &tail[index..index + ZIP_EOCD.len()] == ZIP_EOCD {
            found = Some(start + index as u64);
        }
        index += 1;
    }
    Ok(found)
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Hint => "hint",
        Confidence::Candidate => "candidate",
        Confidence::Identified => "identified",
    }
}
