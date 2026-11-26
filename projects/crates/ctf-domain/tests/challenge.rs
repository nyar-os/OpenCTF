//! Challenge model tests: identity, classification and identify evidence.
//!
//! A challenge carries no bytes and no guess. These tests assert that
//! identification only records what the container says, that a missing file
//! fails with the stable I/O code, and that the evidence log keeps facts and
//! probe candidates apart.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use open_ctf_domain::{Challenge, CtfError, EvidenceKind, IdentifyOptions, OpenCtf, OpenCtfOptions, identify};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct TempFile(PathBuf);

impl TempFile {
    fn new(label: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let name = format!("open-ctf-challenge-{}-{id}-{label}.bin", std::process::id());
        Self(std::env::temp_dir().join(name))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, bytes: &[u8]) {
        fs::write(&self.0, bytes).expect("write fixture");
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        fs::remove_file(&self.0).ok();
    }
}

/// A minimal little-endian ELF64 header: enough for container detection.
fn elf_header() -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    bytes
}

#[test]
fn challenge_records_the_container_and_size() {
    let file = TempFile::new("elf");
    file.write(&elf_header());

    let session = OpenCtf::new(OpenCtfOptions::new(file.path())).expect("open ELF header");
    let challenge = Challenge::of(&session).expect("classify");

    assert_eq!(challenge.format, "elf");
    assert_eq!(challenge.architecture, "x64");
    assert_eq!(challenge.size, 64);
    assert!(challenge.name.starts_with("open-ctf-challenge-"), "name: {}", challenge.name);
    assert_eq!(challenge.path, session.path().display().to_string());
}

#[test]
fn identify_records_facts_and_probe_candidates() {
    let file = TempFile::new("identify");
    file.write(b"just some text, no container");

    let report = identify(&IdentifyOptions::new(file.path())).expect("identify");
    let challenge = report.challenge.expect("challenge");
    assert_eq!(challenge.format, "unknown");
    assert_eq!(challenge.architecture, "unknown");

    assert!(report.candidates.is_empty(), "identification must not guess");
    assert!(report.evidence.iter().any(|evidence| evidence.kind == EvidenceKind::Fact && evidence.source == "info"));
    assert!(
        report
            .evidence
            .iter()
            .any(|evidence| evidence.source == "probe"
                && matches!(evidence.kind, EvidenceKind::Candidate | EvidenceKind::Inference)),
        "probe insight is recorded as a candidate or an inference"
    );
}

#[test]
fn identify_reports_a_missing_file_with_the_stable_io_code() {
    let error: CtfError = identify(&IdentifyOptions::new("C:\\open-ctf\\definitely-missing.bin")).unwrap_err();
    assert_eq!(error.code(), "binary/io");
    assert!(!error.message().is_empty());
}

#[test]
fn challenge_round_trips_through_json() {
    let file = TempFile::new("json");
    file.write(&elf_header());
    let session = OpenCtf::new(OpenCtfOptions::new(file.path())).expect("open");
    let challenge = Challenge::of(&session).expect("classify");

    let encoded = serde_json::to_string(&challenge).expect("serialize");
    assert!(encoded.contains("\"format\""));
    let decoded: Challenge = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded, challenge);
}
