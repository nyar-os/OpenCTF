//! Solver algorithm tests.
//!
//! Each test asserts the ranking, the preview and the failure code of one
//! solver. Fixtures are tiny byte strings so the expected value stays readable.

use open_ctf_domain::BinaryView;
use open_ctf_solvers::*;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct TempFile(PathBuf);

impl TempFile {
    fn new(label: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let name = format!("open-ctf-{}-{id}-{label}.bin", std::process::id());
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

#[test]
fn hash_matches_known_digests_for_file_and_range() {
    let file = TempFile::new("hash");
    file.write(b"abc");
    let view = BinaryView::open(file.path()).expect("open");

    let sha = view.hash(&HashOptions::default()).expect("sha256");
    assert_eq!(sha.algorithm, "sha256");
    assert_eq!(sha.source, "file");
    assert_eq!(sha.digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    let md5 = view.hash(&HashOptions { algorithm: HashAlgorithm::Md5, offset: Some(0), length: Some(1) }).expect("md5 range");
    assert_eq!(md5.source, "range");
    assert_eq!(md5.digest, "0cc175b9c0f1b6a831c399e269772661");

    let sha1 = view.hash(&HashOptions { algorithm: HashAlgorithm::Sha1, ..HashOptions::default() }).expect("sha1");
    assert_eq!(sha1.digest, "a9993e364706816aba3e25717850c26c9cd0d89d");
}

#[test]
fn decode_handles_base64_hex_rot13_and_auto_chains() {
    let file = TempFile::new("decode");
    file.write(b"ZmxhZ3t0ZXN0fQ==");
    let view = BinaryView::open(file.path()).expect("open");

    let explicit = view.decode(&DecodeOptions { codec: DecodeCodec::Base64, ..DecodeOptions::default() }).expect("base64");
    assert_eq!(explicit.text, "flag{test}");

    let auto = view.decode(&DecodeOptions::default()).expect("auto");
    assert_eq!(auto.text, "flag{test}");
    assert!(auto.steps.iter().any(|step| step.codec == "base64"));

    file.write(b"666c6167");
    let view = BinaryView::open(file.path()).expect("open");
    let hex = view.decode(&DecodeOptions { codec: DecodeCodec::Hex, ..DecodeOptions::default() }).expect("hex");
    assert_eq!(hex.text, "flag");

    file.write(b"uryyb");
    let view = BinaryView::open(file.path()).expect("open");
    let rot = view.decode(&DecodeOptions { codec: DecodeCodec::Rot13, ..DecodeOptions::default() }).expect("rot13");
    assert_eq!(rot.text, "hello");

    let error = view.decode(&DecodeOptions { codec: DecodeCodec::Base64, ..DecodeOptions::default() }).unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

#[test]
fn xor_brute_force_recovers_a_single_byte_key() {
    let plaintext = b"flag{xor_is_basic}";
    let encoded: Vec<u8> = plaintext.iter().map(|byte| byte ^ 0x42).collect();
    let file = TempFile::new("xor");
    file.write(&encoded);
    let view = BinaryView::open(file.path()).expect("open");

    let report = view.xor(&XorOptions::default()).expect("brute force");
    let best = report.guesses.first().expect("at least one guess");
    assert_eq!(best.key, 0x42);
    assert!(best.preview.contains("flag{"), "the preview leaks the flag: {}", best.preview);

    let known = view.xor(&XorOptions { key: Some("0x42".into()), ..XorOptions::default() }).expect("known key");
    assert_eq!(known.plaintext.as_deref(), Some("flag{xor_is_basic}"));

    let bad = view.xor(&XorOptions { key: Some("zz".into()), ..XorOptions::default() }).unwrap_err();
    assert_eq!(bad.code(), "binary/parse");
}

#[test]
fn jwt_decodes_header_payload_and_flags_alg_none() {
    let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJmbGFnIn0.";
    let report = decode_jwt(token).expect("decode the JWT");
    assert_eq!(report.algorithm, "none");
    assert!(report.unsigned);
    assert_eq!(report.payload["sub"], "flag");
    assert!(report.warnings.iter().any(|warning| warning.contains("alg=none")));
    assert!(report.signature_hex.is_empty());
}

#[test]
fn url_parses_query_and_warns_about_credentials() {
    let report = parse_url("https://user:pass@example.com:8443/a/b?next=%2Fadmin&flag=fl%61g#top").expect("url");

    assert_eq!(report.scheme.as_deref(), Some("https"));
    assert_eq!(report.host.as_deref(), Some("example.com"));
    assert_eq!(report.port, Some(8443));
    assert_eq!(report.path, "a/b");
    assert_eq!(report.params[0].decoded_value, "/admin");
    assert_eq!(report.params[1].decoded_value, "flag");
    assert!(report.warnings.iter().any(|warning| warning.contains("credentials")));
}

#[test]
fn cyclic_pattern_round_trips_a_find_offset() {
    let base = cyclic(&CyclicOptions { length: 64, find: None }).expect("pattern");
    assert_eq!(base.pattern.len(), 64);
    let needle = base.pattern[10..14].to_string();

    let report = cyclic(&CyclicOptions { length: 64, find: Some(needle) }).expect("find");
    assert_eq!(report.offset, Some(10));
}

#[test]
fn caesar_decodes_and_ranks_the_matching_shift() {
    let file = TempFile::new("caesar");
    file.write(b"iodj{fdhvdu}");
    let view = BinaryView::open(file.path()).expect("open");

    let known = view.caesar(&CaesarOptions { shift: Some(3), ..CaesarOptions::default() }).expect("shift 3");
    assert_eq!(known.plaintext.as_deref(), Some("flag{caesar}"));

    let brute = view.caesar(&CaesarOptions::default()).expect("brute force");
    assert_eq!(brute.candidates.first().expect("candidate").shift, 3);
    assert!(brute.candidates[0].preview.contains("flag{"));
}
