//! Candidate model tests: ranking, deduplication and report conversion.
//!
//! A candidate is a hypothesis with the solver that produced it. These tests
//! assert that the set keeps the best score per value, that the order is stable,
//! and that the xor and Caesar reports convert without re-scoring.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use open_ctf_domain::{BinaryView, CaesarOptions, Candidate, CandidateSet, XorOptions};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct TempFile(PathBuf);

impl TempFile {
    fn new(label: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let name = format!("open-ctf-candidate-{}-{id}-{label}.bin", std::process::id());
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

fn candidate(source: &str, label: &str, value: &str, score: f64) -> Candidate {
    Candidate { source: source.to_string(), label: label.to_string(), value: value.to_string(), score }
}

#[test]
fn ranked_deduplicates_by_value_and_keeps_the_best_score() {
    let mut set = CandidateSet::new();
    set.push(candidate("xor", "key 0x5a", "CTF{low}", 0.5));
    set.push(candidate("caesar", "shift 13", "CTF{low}", 0.9));
    set.push(candidate("xor", "key 0x42", "CTF{high}", 2.5));
    set.push(candidate("caesar", "shift 1", "plain text", 1.0));

    let ranked = set.ranked();
    assert_eq!(ranked.len(), 3, "the duplicate value is dropped");
    assert_eq!(ranked[0].value, "CTF{high}");
    assert_eq!(ranked[1].value, "plain text");
    assert_eq!(ranked[2].value, "CTF{low}");
    assert_eq!(ranked[2].source, "caesar", "the better score wins the duplicate");
    assert_eq!(ranked[2].score, 0.9);
    assert_eq!(set.best().expect("best").value, "CTF{high}");
    assert_eq!(set.len(), 4, "len reports the raw count");
}

#[test]
fn xor_report_converts_without_rescoring() {
    let file = TempFile::new("xor");
    file.write(&[0x19, 0x0e, 0x1c, 0x21, 0x22, 0x35, 0x28, 0x05, 0x29, 0x33, 0x34, 0x3d, 0x36, 0x3f, 0x05, 0x38]);
    let view = BinaryView::open(file.path()).expect("open");

    let report = view.xor(&XorOptions { offset: None, length: None, key: None, limit: 3 }).expect("xor crack");
    let set = CandidateSet::from_xor(&report);

    assert_eq!(set.len(), report.guesses.len());
    assert_eq!(set.items[0].source, "xor");
    assert_eq!(set.items[0].label, format!("key {}", report.guesses[0].key_hex));
    assert_eq!(set.items[0].value, report.guesses[0].preview);
    assert_eq!(set.items[0].score, report.guesses[0].score);
}

#[test]
fn caesar_report_converts_without_rescoring() {
    let file = TempFile::new("caesar");
    file.write(b"PGS{pnrfne_fuvsg_13}");
    let view = BinaryView::open(file.path()).expect("open");

    let report = view.caesar(&CaesarOptions { offset: None, length: None, shift: None, limit: 3 }).expect("caesar crack");
    let set = CandidateSet::from_caesar(&report);

    assert_eq!(set.len(), report.candidates.len());
    assert_eq!(set.items[0].source, "caesar");
    assert_eq!(set.items[0].label, format!("shift {}", report.candidates[0].shift));
    assert_eq!(set.items[0].score, report.candidates[0].score);

    let flag = report.candidates.iter().find(|candidate| candidate.shift == 13).expect("shift 13 kept");
    assert_eq!(flag.preview, "CTF{caesar_shift_13}");
    assert!(set.items.iter().any(|item| item.label == "shift 13" && item.value == "CTF{caesar_shift_13}"));
}

#[test]
fn merging_two_sets_preserves_both_sources() {
    let file = TempFile::new("merge");
    file.write(b"PGS{pnrfne_fuvsg_13}");
    let view = BinaryView::open(file.path()).expect("open");

    let mut set = CandidateSet::from_caesar(
        &view.caesar(&CaesarOptions { offset: None, length: None, shift: None, limit: 2 }).expect("caesar"),
    );
    set.merge(CandidateSet::from_xor(&view.xor(&XorOptions { offset: None, length: None, key: None, limit: 2 }).expect("xor")));

    assert!(set.items.iter().any(|item| item.source == "caesar"));
    assert!(set.items.iter().any(|item| item.source == "xor"));
}
