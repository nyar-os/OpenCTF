//! Solver fixture corpus and its recorded identity.
//!
//! The corpus is the byte-level oracle the algorithm tests share. Each entry is
//! a literal whose SHA-256 is recorded from an independent tool
//! (`Get-FileHash` over the same bytes), so editing a fixture is detected as a
//! fixture change instead of silently changing an expected ranking. The NIST
//! vectors below are a second, published oracle.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use open_ctf_domain::BinaryView;
use open_ctf_solvers::{HashAlgorithm, HashOptions};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct TempFile(PathBuf);

impl TempFile {
    fn new(label: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let name = format!("open-ctf-solver-{}-{id}-{label}.bin", std::process::id());
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

/// The recorded corpus: label, bytes and the independently computed SHA-256.
fn corpus() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    vec![
        ("caesar", b"PGS{pnrfne_fuvsg_13}".to_vec(), "498e6bdb9ff0267ef105aeaadfeb387a97b33167a9a3935ca04d512a753e111b"),
        (
            "xor",
            vec![
                0x19, 0x0e, 0x1c, 0x21, 0x22, 0x35, 0x28, 0x05, 0x29, 0x33, 0x34, 0x3d, 0x36, 0x3f, 0x05, 0x38, 0x23, 0x2e,
                0x3f, 0x27,
            ],
            "1e8ef7b7830c004976b8db3a1a7e98609817c7655c79ae09580904c54726987d",
        ),
        ("base64", b"Q1RGe2Jhc2U2NF9jaGFpbn0=".to_vec(), "24dd7452c2b05ba238018feabe9642c4d5821ed572ada96b8a8b9c63d2736125"),
        (
            "jwt",
            b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjdGYifQ.signature".to_vec(),
            "40b663f7f63da1a2631954b8c2cb7d1bd23a8f5f46fda9042e16f6b21aea190e",
        ),
        ("cyclic", b"Aa0Aa1Aa2Aa3".to_vec(), "99300d67dff64ec070810251312e9a924fd219045534a9222b0cdf16ccc138ed"),
    ]
}

fn sha256(view: &BinaryView) -> String {
    view.hash(&HashOptions { algorithm: HashAlgorithm::Sha256, offset: None, length: None }).expect("hash fixture").digest
}

#[test]
fn corpus_digests_match_the_recording() {
    for (label, bytes, expected) in corpus() {
        let file = TempFile::new(label);
        file.write(&bytes);
        let view = BinaryView::open(file.path()).expect("open fixture");
        let report =
            view.hash(&HashOptions { algorithm: HashAlgorithm::Sha256, offset: None, length: None }).expect("hash fixture");
        assert_eq!(report.digest, expected, "{label} digest drifted");
        assert_eq!(report.length, bytes.len() as u64, "{label} length drifted");
        assert_eq!(report.source, "file", "{label} source drifted");
    }
}

#[test]
fn nist_sha256_vectors_are_stable() {
    let empty = BinaryView::from_bytes("empty.bin", Vec::new());
    assert_eq!(sha256(&empty), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    let abc = BinaryView::from_bytes("abc.bin", b"abc".to_vec());
    assert_eq!(sha256(&abc), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn corpus_loading_is_deterministic() {
    for (label, bytes, expected) in corpus() {
        let first = TempFile::new(&format!("{label}-a"));
        let second = TempFile::new(&format!("{label}-b"));
        first.write(&bytes);
        second.write(&bytes);

        let left = BinaryView::open(first.path()).expect("open first copy");
        let right = BinaryView::open(second.path()).expect("open second copy");
        assert_eq!(sha256(&left), sha256(&right), "{label} is not reproducible");
        assert_eq!(sha256(&left), expected, "{label} digest drifted");
    }
}
