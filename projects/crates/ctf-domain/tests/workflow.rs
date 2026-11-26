//! Product workflow tests.
//!
//! These assertions cover the session defaults, the capability matrix, the
//! product-side byte operations (encoded strings, hexdump, patch, search, find,
//! dump, carve), diff and entropy. Format facts stay in
//! open-ctf-formats/tests/projections.rs and solver behaviour in
//! open-ctf-solvers/tests/algorithms.rs.

use open_ctf_domain::*;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn put_section(
    bytes: &mut [u8],
    offset: usize,
    name: &[u8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
) {
    let name_length = name.len().min(8);
    bytes[offset..offset + name_length].copy_from_slice(&name[..name_length]);
    put_u32(bytes, offset + 8, virtual_size);
    put_u32(bytes, offset + 12, virtual_address);
    put_u32(bytes, offset + 16, raw_size);
    put_u32(bytes, offset + 20, raw_pointer);
    put_u32(bytes, offset + 36, characteristics);
}

/// A two-section PE32+ image with a header at 0x80 and sections at 0x200/0x400.
fn pe_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x600];
    bytes[0] = 0x4d;
    bytes[1] = 0x5a;
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x84, 0x8664);
    put_u16(&mut bytes, 0x86, 2);
    put_u16(&mut bytes, 0x94, 0xf0);
    put_u16(&mut bytes, 0x98, 0x20b);
    put_u32(&mut bytes, 0x98 + 16, 0x1000);
    put_u64(&mut bytes, 0x98 + 24, 0x1_4000_0000);
    put_u32(&mut bytes, 0x98 + 60, 0x200);
    put_section(&mut bytes, 0x188, b".text", 0x100, 0x1000, 0x200, 0x200, 0x6000_0020);
    put_section(&mut bytes, 0x1b0, b".data", 0x100, 0x2000, 0x200, 0x400, 0xc000_0040);
    bytes
}

/// 单节 `PE32+`：`.rdata` 覆盖文件 0x200..0x800，内含导入、导出与一个 `COFF` 符号。
fn pe_analysis_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x800];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x84, 0x8664);
    put_u16(&mut bytes, 0x86, 1);
    put_u32(&mut bytes, 0x8c, 0x600);
    put_u32(&mut bytes, 0x90, 1);
    put_u16(&mut bytes, 0x94, 0xf0);
    put_u16(&mut bytes, 0x98, 0x20b);
    put_u64(&mut bytes, 0x98 + 24, 0x1_4000_0000);
    put_u32(&mut bytes, 0x98 + 56, 0x2000);
    put_u32(&mut bytes, 0x98 + 60, 0x200);
    put_u32(&mut bytes, 0x98 + 112, 0x1100);
    put_u32(&mut bytes, 0x98 + 116, 0x28);
    put_u32(&mut bytes, 0x98 + 120, 0x1000);
    put_u32(&mut bytes, 0x98 + 124, 0x28);

    let section = 0x188;
    bytes[section..section + 6].copy_from_slice(b".rdata");
    put_u32(&mut bytes, section + 8, 0x600);
    put_u32(&mut bytes, section + 12, 0x1000);
    put_u32(&mut bytes, section + 16, 0x600);
    put_u32(&mut bytes, section + 20, 0x200);
    put_u32(&mut bytes, section + 36, 0x4000_0040);

    put_u32(&mut bytes, 0x200, 0x1040);
    put_u32(&mut bytes, 0x20c, 0x1030);
    put_u32(&mut bytes, 0x210, 0x1060);
    bytes[0x230..0x23d].copy_from_slice(b"KERNEL32.dll\0");
    put_u64(&mut bytes, 0x240, 0x1080);
    put_u64(&mut bytes, 0x248, 0x8000_0000_0000_0001);
    put_u64(&mut bytes, 0x260, 0x1080);
    put_u64(&mut bytes, 0x268, 0x8000_0000_0000_0001);
    bytes[0x282..0x28e].copy_from_slice(b"ExitProcess\0");

    put_u32(&mut bytes, 0x300 + 12, 0x1130);
    put_u32(&mut bytes, 0x300 + 16, 1);
    put_u32(&mut bytes, 0x300 + 20, 2);
    put_u32(&mut bytes, 0x300 + 24, 1);
    put_u32(&mut bytes, 0x300 + 28, 0x1140);
    put_u32(&mut bytes, 0x300 + 32, 0x1148);
    put_u32(&mut bytes, 0x300 + 36, 0x114c);
    bytes[0x330..0x33b].copy_from_slice(b"sample.dll\0");
    put_u32(&mut bytes, 0x340, 0x1000);
    put_u32(&mut bytes, 0x348, 0x1150);
    put_u16(&mut bytes, 0x34c, 0);
    bytes[0x350..0x356].copy_from_slice(b"Start\0");

    bytes[0x600..0x606].copy_from_slice(b"native");
    put_u32(&mut bytes, 0x608, 0x1000);
    put_u16(&mut bytes, 0x60c, 1);
    put_u16(&mut bytes, 0x60e, 0x20);
    bytes[0x610] = 2;
    put_u32(&mut bytes, 0x612, 4);
    bytes
}
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
fn strings_report_offsets_and_honour_minimum_length() {
    let view = BinaryView::from_bytes("strings.bin", b"\x00hello\x00ab\x00world!\x00".to_vec());
    let hits = view.strings(2);
    assert_eq!(hits.len(), 3);
    assert_eq!(hits[0].value, "hello");
    assert_eq!(hits[0].offset, 1);
    assert_eq!(hits[1].value, "ab");
    assert_eq!(hits[1].offset, 7);
    assert_eq!(hits[2].value, "world!");
    assert_eq!(hits[2].offset, 10);

    let long = view.strings(3);
    assert_eq!(long.len(), 2);
    assert_eq!(long[0].value, "hello");
    assert_eq!(long[1].value, "world!");
}

#[test]
fn encoded_strings_match_the_ascii_scanner() {
    let view = BinaryView::from_bytes("encoded.bin", b"\x00hello\x00ab\x00world!\x00".to_vec());
    let report = view
        .strings_encoded(&StringsOptions { min_length: 2, encoding: StringEncoding::Ascii, ..StringsOptions::default() })
        .expect("ascii encoded strings");

    assert_eq!(report.encoding, StringEncoding::Ascii);
    assert_eq!(report.min_length, 2);
    assert_eq!(report.total, 3);
    assert!(!report.truncated);
    let values: Vec<&str> = report.hits.iter().map(|hit| hit.value.as_str()).collect();
    assert_eq!(values, vec!["hello", "ab", "world!"]);
    let legacy_hits = view.strings(2);
    let legacy: Vec<&str> = legacy_hits.iter().map(|hit| hit.value.as_str()).collect();
    assert_eq!(values, legacy);
    assert!(report.hits.iter().all(|hit| hit.encoding == StringEncoding::Ascii));
    assert_eq!(report.hits[0].offset, 1);
    assert_eq!(report.hits[0].length, 5);
}

#[test]
fn utf16le_strings_report_byte_offsets_and_lengths() {
    let view = BinaryView::from_bytes("wide.bin", b"\xff\x00H\x00e\x00l\x00l\x00o\x00\xff".to_vec());
    let options = StringsOptions { encoding: StringEncoding::Utf16Le, ..StringsOptions::default() };
    let report = view.strings_encoded(&options).expect("utf16 strings");

    assert_eq!(report.total, 1);
    let hit = &report.hits[0];
    assert_eq!(hit.value, "Hello");
    assert_eq!(hit.offset, 2);
    assert_eq!(hit.length, 10);
    assert_eq!(hit.encoding, StringEncoding::Utf16Le);

    let ascii_only = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Ascii, ..StringsOptions::default() })
        .expect("ascii only");
    assert_eq!(ascii_only.total, 0);
}

#[test]
fn both_encodings_merge_in_offset_order() {
    let mut bytes = b"abcde\x00\xff".to_vec();
    bytes.extend_from_slice(b"H\x00e\x00l\x00l\x00o\x00");
    let view = BinaryView::from_bytes("mixed.bin", bytes);
    let report = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Both, ..StringsOptions::default() })
        .expect("merged strings");

    assert_eq!(report.encoding, StringEncoding::Both);
    assert_eq!(report.total, 2);
    assert_eq!(report.hits[0].offset, 0);
    assert_eq!(report.hits[0].encoding, StringEncoding::Ascii);
    assert_eq!(report.hits[0].value, "abcde");
    assert_eq!(report.hits[1].offset, 7);
    assert_eq!(report.hits[1].encoding, StringEncoding::Utf16Le);
    assert_eq!(report.hits[1].value, "Hello");
}

#[test]
fn encoded_strings_honour_the_minimum_length() {
    let view = BinaryView::from_bytes("short-wide.bin", b"H\x00e\x00y\x00\x00\x00".to_vec());
    let filtered = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Utf16Le, min_length: 4, ..StringsOptions::default() })
        .expect("filtered utf16");
    assert_eq!(filtered.total, 0);

    let kept = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Utf16Le, min_length: 3, ..StringsOptions::default() })
        .expect("kept utf16");
    assert_eq!(kept.total, 1);
    assert_eq!(kept.hits[0].value, "Hey");

    let zero = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Utf16Le, min_length: 0, ..StringsOptions::default() })
        .expect("zero minimum");
    assert_eq!(zero.min_length, 1);
    assert_eq!(zero.total, 1);
}

#[test]
fn encoded_strings_apply_the_limit_once() {
    let file = TempFile::new("encoded-limit");
    file.write(b"\x00alpha\x00beta\x00gamma\x00");
    let engine = open_engine(&file);
    let report = engine
        .strings_encoded(&StringsOptions {
            encoding: StringEncoding::Both,
            min_length: 3,
            limit: 2,
            ..StringsOptions::default()
        })
        .expect("bounded strings");

    assert_eq!(report.total, 3);
    assert_eq!(report.hits.len(), 2);
    assert!(report.truncated);
    assert_eq!(report.limit, 2);
    assert_eq!(report.hits[0].value, "alpha");
    assert_eq!(report.hits[1].value, "beta");
}

#[test]
fn encoded_strings_page_with_skip_and_uncap_with_all() {
    let view = BinaryView::from_bytes("paged.bin", b"\x00alpha\x00beta\x00gamma\x00delta\x00".to_vec());
    let paged = view
        .strings_encoded(&StringsOptions {
            encoding: StringEncoding::Ascii,
            min_length: 3,
            limit: 2,
            skip: 2,
            ..StringsOptions::default()
        })
        .expect("paged strings");

    assert_eq!(paged.total, 4);
    assert_eq!(paged.skip, 2);
    assert!(!paged.all);
    assert!(paged.truncated);
    let values: Vec<&str> = paged.hits.iter().map(|hit| hit.value.as_str()).collect();
    assert_eq!(values, vec!["gamma", "delta"]);

    let tail = view
        .strings_encoded(&StringsOptions {
            encoding: StringEncoding::Ascii,
            min_length: 3,
            limit: 100,
            skip: 9,
            ..StringsOptions::default()
        })
        .expect("skip past the end");
    assert_eq!(tail.skip, 4);
    assert!(tail.hits.is_empty());
    assert!(tail.truncated);

    let uncapped = view
        .strings_encoded(&StringsOptions {
            encoding: StringEncoding::Ascii,
            min_length: 3,
            limit: 1,
            all: true,
            ..StringsOptions::default()
        })
        .expect("uncapped strings");
    assert!(uncapped.all);
    assert_eq!(uncapped.limit, 2_000_000);
    assert_eq!(uncapped.hits.len(), 4);
    assert!(!uncapped.truncated);

    let parsed: StringsOptions = serde_json::from_str(r#"{"skip": 3, "all": true}"#).expect("paged wire options");
    assert_eq!(parsed.skip, 3);
    assert!(parsed.all);
    let defaults: StringsOptions = serde_json::from_str("{}").expect("default wire options");
    assert_eq!(defaults.skip, 0);
    assert!(!defaults.all);
}

#[test]
fn encoded_strings_tolerate_odd_endings_and_truncated_pairs() {
    let view = BinaryView::from_bytes("odd.bin", b"\x00H\x00i\x00J".to_vec());
    let report = view
        .strings_encoded(&StringsOptions { encoding: StringEncoding::Both, min_length: 2, ..StringsOptions::default() })
        .expect("odd ending");
    assert_eq!(report.total, 1);
    assert_eq!(report.hits[0].value, "Hi");
    assert_eq!(report.hits[0].offset, 1);
    assert_eq!(report.hits[0].length, 4);

    let lone = BinaryView::from_bytes("lone.bin", b"\x00H".to_vec());
    assert_eq!(
        lone.strings_encoded(&StringsOptions { encoding: StringEncoding::Utf16Le, ..StringsOptions::default() })
            .expect("truncated pair")
            .total,
        0
    );
}

#[test]
fn strings_options_use_snake_case_defaults() {
    let defaults = serde_json::from_str::<StringsOptions>("{}").expect("default options");
    assert_eq!(defaults, StringsOptions::default());
    assert_eq!(defaults.min_length, 4);
    assert_eq!(defaults.limit, 100);
    assert_eq!(defaults.encoding, StringEncoding::Ascii);

    let parsed = serde_json::from_str::<StringsOptions>(r#"{"min_length": 2, "limit": 5, "encoding": "both"}"#)
        .expect("natural options");
    assert_eq!(parsed.min_length, 2);
    assert_eq!(parsed.limit, 5);
    assert_eq!(parsed.encoding, StringEncoding::Both);

    let report = BinaryView::from_bytes("json.bin", b"text".to_vec()).strings_encoded(&parsed).expect("json strings");
    let value = serde_json::to_value(&report).expect("report json");
    assert_eq!(value["min_length"], 2);
    assert_eq!(value["limit"], 5);
    assert_eq!(value["encoding"], "both");
    assert_eq!(value["hits"][0]["encoding"], "ascii");
}

#[test]
fn hexdump_uses_the_canonical_layout() {
    let view = BinaryView::from_bytes("hello.bin", b"Hello, world!".to_vec());
    let dump = view.hexdump(0, 13).expect("hexdump");
    let expected = concat!("00000000  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 ", "         ", " |Hello, world!|\n");
    assert_eq!(dump, expected);

    let empty = view.hexdump(0, 0).expect("empty dump");
    assert_eq!(empty, "");
    assert_eq!(view.hexdump(10, 4).unwrap_err().code(), "binary/range");
}

#[test]
fn patch_is_atomic_and_reports_hashes() {
    let file = TempFile::new("patch");
    file.write(&[0, 1, 2, 3, 4, 5, 6, 7]);
    let mut view = BinaryView::open(file.path()).expect("open patch target");

    let report = view.patch(2, &[0xaa, 0xbb]).expect("patch");
    assert_eq!(fs::read(file.path()).unwrap(), vec![0, 1, 0xaa, 0xbb, 4, 5, 6, 7]);
    assert_eq!(report.offset, 2);
    assert_eq!(report.length, 2);
    assert_eq!(report.before_hash.len(), 16);
    assert_ne!(report.before_hash, report.after_hash);
    assert_eq!(view.size(), 8);

    let error = view.patch(7, &[0, 0]).unwrap_err();
    assert_eq!(error.code(), "binary/range");
    assert_eq!(fs::read(file.path()).unwrap(), vec![0, 1, 0xaa, 0xbb, 4, 5, 6, 7]);
}

#[test]
fn patch_to_a_copy_leaves_the_source_untouched() {
    let source = TempFile::new("patch-source");
    source.write(&[1, 2, 3, 4]);
    let target = TempFile::new("patch-target");
    let mut view = BinaryView::open(source.path()).expect("open source");

    let report = view.patch_to(0, &[0xff], Some(target.path())).expect("patch copy");
    assert_eq!(fs::read(source.path()).unwrap(), vec![1, 2, 3, 4]);
    assert_eq!(fs::read(target.path()).unwrap(), vec![0xff, 2, 3, 4]);
    assert_eq!(report.path, target.path().display().to_string());
}

#[test]
fn engine_options_carry_the_defaults_used_by_operations() {
    let file = TempFile::new("engine");
    file.write(b"\x00alpha\x00beta\x00gamma\x00");
    let engine = OpenCtf::new(OpenCtfOptions { strings_limit: Some(2), min_string_len: 3, ..OpenCtfOptions::new(file.path()) })
        .expect("open engine");

    assert_eq!(engine.options().strings_limit, Some(2));
    assert_eq!(engine.info().expect("engine info").format, "unknown");

    let report = engine.strings(None, None);
    assert_eq!(report.total, 3);
    assert_eq!(report.hits.len(), 2);
    assert!(report.truncated);
    assert_eq!(report.hits[0].value, "alpha");

    let override_report = engine.strings(Some(5), Some(1));
    assert_eq!(override_report.total, 2);
    assert_eq!(override_report.hits.len(), 1);
    assert_eq!(override_report.hits[0].value, "alpha");

    let unlimited = OpenCtf::new(OpenCtfOptions { strings_limit: None, ..OpenCtfOptions::new(file.path()) })
        .expect("open unlimited engine");
    assert_eq!(unlimited.strings(None, None).hits.len(), 3);
}

#[test]
fn engine_hexdump_uses_its_configured_length() {
    let file = TempFile::new("engine-hexdump");
    file.write(b"abcdefgh");
    let engine = OpenCtf::new(OpenCtfOptions { hexdump_length: 4, ..OpenCtfOptions::new(file.path()) }).expect("open engine");

    let dump = engine.hexdump(None, None).expect("default dump");
    assert!(dump.contains("61 62 63 64"));
    assert!(!dump.contains("65 66"));
    assert_eq!(engine.read(0, 2).unwrap(), b"ab");
    assert_eq!(engine.read(6, 4).unwrap_err().code(), "binary/range");
}

#[test]
fn engine_options_round_trip_through_json() {
    let file = TempFile::new("engine-json");
    file.write(b"\x00engine\x00");
    let raw = serde_json::json!({ "path": file.path(), "min_string_len": 2 }).to_string();
    let engine = OpenCtf::from_options_json(&raw).expect("engine from json");
    assert_eq!(engine.options().min_string_len, 2);
    assert_eq!(engine.options().strings_limit, Some(100));
    assert_eq!(engine.options().hexdump_length, 256);
    assert_eq!(engine.strings(None, None).hits[0].value, "engine");

    let error = OpenCtf::from_options_json("{}").unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

#[test]
fn capabilities_declare_what_is_not_implemented() {
    let matrix = open_ctf_domain::capabilities();
    assert_eq!(matrix["formats"]["pe"], "supported");
    assert_eq!(matrix["formats"]["macho"], "partial");
    assert_eq!(matrix["features"]["imports"], "supported");
    assert_eq!(matrix["features"]["symbols"], "supported");
    assert_eq!(matrix["features"]["search"], "supported");
    assert_eq!(matrix["features"]["disassembly"], "supported");
    assert_eq!(matrix["features"]["version"], "supported");
    assert_eq!(matrix["features"]["macho-dylibs"], "supported");
    assert_eq!(matrix["features"]["macho-sections"], "supported");
    assert_eq!(matrix["features"]["macho-symbols"], "supported");
    assert_eq!(matrix["features"]["macho-fat-slices"], "supported");
    assert_eq!(matrix["features"]["pe-mitigations"], "supported");
    assert_eq!(matrix["features"]["pe-resources"], "supported");
    assert_eq!(matrix["unsupported"]["debugger"], "not-implemented");
}

#[test]
fn hex_parser_accepts_common_separators() {
    assert_eq!(open_ctf_domain::parse_hex("90,90").unwrap(), vec![0x90, 0x90]);
    assert_eq!(open_ctf_domain::parse_hex("0x90 0x0d").unwrap(), vec![0x90, 0x0d]);
    assert_eq!(open_ctf_domain::parse_hex("9090").unwrap(), vec![0x90, 0x90]);
    let error: CtfError = open_ctf_domain::parse_hex("9").unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

fn open_engine(file: &TempFile) -> OpenCtf {
    OpenCtf::new(OpenCtfOptions::new(file.path())).expect("open engine")
}

#[test]
fn diff_reports_identical_files() {
    let left_file = TempFile::new("diff-left");
    left_file.write(&[1, 2, 3, 4]);
    let right_file = TempFile::new("diff-right");
    right_file.write(&[1, 2, 3, 4]);
    let left = open_engine(&left_file);
    let right = open_engine(&right_file);

    let report = left.diff(&right).expect("diff");
    assert!(report.identical);
    assert_eq!(report.left_size, 4);
    assert_eq!(report.right_size, 4);
    assert_eq!(report.compared_bytes, 4);
    assert_eq!(report.left_hash, report.right_hash);
    assert_eq!(report.first_difference, None);
    assert!(report.differences.is_empty());
    assert_eq!(report.total, 0);
    assert!(!report.truncated);
}

#[test]
fn diff_reports_the_first_divergence_and_range() {
    let left_file = TempFile::new("diff-prefix-left");
    left_file.write(&[1, 2, 3, 4, 5]);
    let right_file = TempFile::new("diff-prefix-right");
    right_file.write(&[1, 2, 9, 4, 5]);
    let left = open_engine(&left_file);
    let right = open_engine(&right_file);

    let report = left.diff(&right).expect("diff");
    assert!(!report.identical);
    assert_eq!(report.compared_bytes, 5);
    assert_eq!(report.first_difference, Some(2));
    assert_ne!(report.left_hash, report.right_hash);
    assert_eq!(report.differences, vec![open_ctf_domain::DiffRange { offset: 2, length: 1 }]);
    assert_eq!(report.total, 1);
    assert!(!report.truncated);
}

#[test]
fn diff_handles_different_lengths() {
    let left_file = TempFile::new("diff-length-left");
    left_file.write(&[1, 2, 3]);
    let right_file = TempFile::new("diff-length-right");
    right_file.write(&[1, 2, 3, 4, 5]);
    let left = open_engine(&left_file);
    let right = open_engine(&right_file);

    let report = left.diff(&right).expect("diff");
    assert!(!report.identical);
    assert_eq!(report.left_size, 3);
    assert_eq!(report.right_size, 5);
    assert_eq!(report.compared_bytes, 3);
    assert_eq!(report.first_difference, Some(3));
    assert_eq!(report.differences, vec![open_ctf_domain::DiffRange { offset: 3, length: 2 }]);
}

#[test]
fn diff_caps_the_number_of_ranges() {
    let mut left_bytes = vec![0u8; 200];
    let mut right_bytes = vec![0u8; 200];
    for index in 0..100 {
        left_bytes[index * 2] = 1;
        right_bytes[index * 2] = 2;
    }
    let left_file = TempFile::new("diff-cap-left");
    left_file.write(&left_bytes);
    let right_file = TempFile::new("diff-cap-right");
    right_file.write(&right_bytes);
    let left = open_engine(&left_file);
    let right = open_engine(&right_file);

    let report = left.diff(&right).expect("diff");
    assert_eq!(report.total, 100);
    assert_eq!(report.differences.len(), 64);
    assert!(report.truncated);
    assert_eq!(report.first_difference, Some(0));
    assert_eq!(report.differences[0].offset, 0);
    assert_eq!(report.differences[63].offset, 126);
}

#[test]
fn entropy_of_uniform_and_high_entropy_data() {
    let uniform = BinaryView::from_bytes("zeros.bin", vec![0u8; 256]);
    let report = uniform.entropy().expect("uniform entropy");
    assert_eq!(report.file_size, 256);
    assert_eq!(report.file_entropy, 0.0);
    assert!(report.sections.is_empty());
    assert_eq!(report.overlay, None);

    let spread: Vec<u8> = (0..=255u8).collect();
    let high = BinaryView::from_bytes("spread.bin", spread);
    let report = high.entropy().expect("high entropy");
    assert_eq!(report.file_entropy, 8.0);
}

#[test]
fn entropy_reports_sections_and_the_pe_overlay() {
    let mut bytes = pe_bytes();
    for (index, byte) in bytes[0x200..0x400].iter_mut().enumerate() {
        *byte = index as u8;
    }
    bytes.extend_from_slice(&[0xaa; 16]);
    let view = BinaryView::from_bytes("overlay.exe", bytes);

    let report = view.entropy().expect("entropy");
    assert_eq!(report.file_size, 0x610);
    assert_eq!(report.sections.len(), 2);

    let text = report.sections.iter().find(|section| section.name == ".text").expect("text section");
    assert_eq!(text.offset, 0x200);
    assert_eq!(text.size, 0x200);
    assert_eq!(text.entropy, 8.0);

    let data = report.sections.iter().find(|section| section.name == ".data").expect("data section");
    assert_eq!(data.entropy, 0.0);

    let overlay = report.overlay.expect("overlay");
    assert_eq!(overlay.offset, 0x600);
    assert_eq!(overlay.size, 16);
}

#[test]
fn search_and_reverse_mapping_are_exposed() {
    let file = TempFile::new("pe-search");
    file.write(&pe_analysis_bytes());
    let view = BinaryView::open(file.path()).expect("open PE");

    let text = view.search(&SearchOptions::new(SearchMode::Ascii, "kernel32")).expect("ascii search");
    assert_eq!(text.mode, "ascii");
    assert_eq!(text.total, 1);
    assert_eq!(text.hits[0].offset, 0x230);
    assert_eq!(text.hits[0].preview, "KERNEL32");

    let hex = view.search(&SearchOptions::new(SearchMode::Hex, "45 78 69 74")).expect("hex search");
    assert_eq!(hex.hits[0].offset, 0x282);

    let wide = view.search(&SearchOptions::new(SearchMode::Utf16Le, "Exit")).expect("utf16 search");
    assert_eq!(wide.total, 0);

    assert_eq!(view.offset_to_rva(0x230).unwrap(), 0x1030);
    assert_eq!(view.offset_to_va(0x230).unwrap(), 0x1_4000_1030);
    assert_eq!(view.offset_to_rva(0x10).unwrap(), 0x10);
    assert_eq!(view.offset_to_va(0x800).unwrap_err().code(), "binary/range");
}

#[test]
fn find_reports_regex_hits_with_previews() {
    let view = BinaryView::from_bytes("find.bin", b"junk\x00marker-1\x00tail marker-2\x00".to_vec());
    let report = view.find(&FindOptions { pattern: "marker-[0-9]".into(), ..FindOptions::default() }).expect("regex hits");

    assert_eq!(report.pattern, "marker-[0-9]");
    assert!(!report.case_insensitive);
    assert_eq!(report.total, 2);
    assert_eq!(report.hits.len(), 2);
    assert!(!report.truncated);
    assert_eq!(report.hits[0].offset, 5);
    assert_eq!(report.hits[0].length, 8);
    assert!(report.hits[0].preview.starts_with("marker-1"));
    assert_eq!(report.hits[1].offset, 19);
    assert_eq!(report.context, 80);
    assert_eq!(report.limit, 100);
}

#[test]
fn find_honours_case_insensitive() {
    let view = BinaryView::from_bytes("find-case.bin", b"Marker here marker there".to_vec());
    let sensitive = view.find(&FindOptions { pattern: "marker".into(), ..FindOptions::default() }).expect("sensitive");
    assert_eq!(sensitive.total, 1);
    assert_eq!(sensitive.hits[0].offset, 12);

    let insensitive = view
        .find(&FindOptions { pattern: "marker".into(), case_insensitive: true, ..FindOptions::default() })
        .expect("insensitive");
    assert_eq!(insensitive.total, 2);
    assert!(insensitive.case_insensitive);
    assert_eq!(insensitive.hits[0].offset, 0);
}

#[test]
fn find_pages_with_skip_and_clamps_limit_and_context() {
    let view = BinaryView::from_bytes("find-page.bin", b"a1 b2 c3 d4 e5".to_vec());
    let paged = view
        .find(&FindOptions { pattern: "[a-z][0-9]".into(), skip: 2, limit: Some(2), ..FindOptions::default() })
        .expect("paged matches");
    assert_eq!(paged.total, 5);
    assert_eq!(paged.skip, 2);
    assert_eq!(paged.hits.len(), 2);
    assert!(paged.truncated);
    assert_eq!(paged.hits[0].offset, 6);
    assert_eq!(paged.hits[0].preview, "c3 d4 e5");

    let clamped = view
        .find(&FindOptions { pattern: "[a-z][0-9]".into(), limit: Some(9_999), context: 4_096, ..FindOptions::default() })
        .expect("clamped options");
    assert_eq!(clamped.limit, 5_000);
    assert_eq!(clamped.context, 512);
}

#[test]
fn find_rejects_invalid_patterns_and_reports_empty_results() {
    let view = BinaryView::from_bytes("find-bad.bin", b"abc".to_vec());
    let error: CtfError = view.find(&FindOptions { pattern: "(unclosed".into(), ..FindOptions::default() }).unwrap_err();
    assert_eq!(error.code(), "binary/parse");

    let empty = view.find(&FindOptions { pattern: "zzz".into(), ..FindOptions::default() }).expect("no match");
    assert!(empty.hits.is_empty());
    assert_eq!(empty.total, 0);
    assert!(!empty.truncated);
}

#[test]
fn find_options_use_snake_case_defaults() {
    let defaults: FindOptions = serde_json::from_str(r#"{ "pattern": "ab" }"#).expect("minimal wire options");
    assert!(!defaults.case_insensitive);
    assert_eq!(defaults.skip, 0);
    assert_eq!(defaults.limit, Some(100));
    assert_eq!(defaults.context, 80);

    let wire = serde_json::to_value(FindOptions::default()).expect("serialize options");
    assert!(wire.get("case_insensitive").is_some());
    assert!(serde_json::from_str::<FindOptions>("{}").is_err(), "the pattern is required");

    let view = BinaryView::from_bytes("find-wire.bin", b"ab\x00cd".to_vec());
    let report = view.find(&defaults).expect("wire find");
    let value = serde_json::to_value(&report).expect("serialize report");
    assert_eq!(value["case_insensitive"], false);
    assert_eq!(value["hits"][0]["offset"], 0);
    assert_eq!(value["hits"][0]["length"], 2);
    assert_eq!(value["hits"][0]["preview"], "ab.cd");
}

#[test]
fn dump_writes_a_byte_range_to_the_output_file() {
    let view = BinaryView::from_bytes("dump.bin", b"0123456789abcdef".to_vec());
    let output = TempFile::new("dump-out");
    let report =
        view.dump(&DumpOptions { offset: 4, length: 8, output: output.path().display().to_string() }).expect("dump range");

    assert_eq!(report.offset, 4);
    assert_eq!(report.length, 8);
    assert_eq!(report.written, 8);
    assert_eq!(fs::read(output.path()).expect("read output"), b"456789ab");

    let value = serde_json::to_value(&report).expect("serialize dump report");
    assert_eq!(value["written"], 8);
    assert!(value.get("output").is_some());
}

#[test]
fn dump_clamps_the_length_and_rejects_ranges_outside_the_file() {
    const CAP: usize = 64 * 1024 * 1024;
    let view = BinaryView::from_bytes("dump-big.bin", vec![0x41_u8; CAP]);
    let output = TempFile::new("dump-big-out");
    let report = view
        .dump(&DumpOptions { offset: 0, length: CAP + 1024, output: output.path().display().to_string() })
        .expect("clamped dump");
    assert_eq!(report.length, CAP);
    assert_eq!(report.written, CAP);
    assert_eq!(fs::metadata(output.path()).expect("output metadata").len(), CAP as u64);

    let outside = view.dump(&DumpOptions { offset: CAP as u64 + 1, length: 16, output: output.path().display().to_string() });
    assert_eq!(outside.unwrap_err().code(), "binary/range");
}

/// Builds a container of zero padding around one printable JavaScript-style
/// run that mentions the `synthetic-blob` marker twice.
fn carve_fixture() -> (Vec<u8>, usize, usize, usize) {
    let mut js: Vec<u8> = Vec::new();
    js.extend_from_slice(b"(function(){var mode=\"synthetic-blob\";document.addEventListener(\"click\",function(){\n");
    while js.len() < 300 {
        js.extend_from_slice(b"console.log(mode); ");
    }
    js.extend_from_slice(b"var rearm=\"synthetic-blob\"})})();");
    let js_len = js.len();

    let mut bytes = vec![0_u8; 2048];
    let start = bytes.len();
    bytes.extend_from_slice(&js);
    let marker = start + js.windows(14).position(|window| window == b"synthetic-blob").expect("marker");
    bytes.extend_from_slice(&vec![0_u8; 512]);
    (bytes, start, marker, js_len)
}

#[test]
fn carve_expands_the_printable_run_around_every_marker() {
    let (bytes, start, marker, js_len) = carve_fixture();
    let view = BinaryView::from_bytes("carve.bin", bytes);
    let report =
        view.carve(&CarveOptions { marker: "synthetic-blob".into(), ..CarveOptions::default() }).expect("carve regions");

    assert_eq!(report.marker, "synthetic-blob");
    assert_eq!(report.min_region, 200);
    assert_eq!(report.max_region, 262_144);
    assert_eq!(report.expand_left, 4_096);
    assert_eq!(report.limit, 20);
    assert!(report.output_dir.is_none());
    assert_eq!(report.total, 2);
    assert!(!report.truncated);
    assert_eq!(report.regions.len(), 1, "both matches share one printable region");

    let region = &report.regions[0];
    assert_eq!(region.marker_offset, marker as u64);
    assert_eq!(region.region_offset, start as u64);
    assert_eq!(region.region_length, js_len);
    assert!(region.preview.starts_with("(function(){var mode=\"synthetic-blob\";"));
    assert_eq!(region.preview.chars().count(), 120);
    assert!(region.preview.contains('.'), "the embedded newline renders as a dot");
    assert!(region.file.is_none());
}

#[test]
fn carve_writes_each_region_to_the_output_directory() {
    let (bytes, start, _marker, js_len) = carve_fixture();
    let view = BinaryView::from_bytes("carve-out.bin", bytes.clone());
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("open-ctf-{}-{id}-carve", std::process::id()));
    let report = view
        .carve(&CarveOptions {
            marker: "synthetic-blob".into(),
            output_dir: Some(dir.display().to_string()),
            ..CarveOptions::default()
        })
        .expect("carve with output");

    let file = report.regions[0].file.as_ref().expect("region file");
    assert!(file.ends_with("carve_0.bin"));
    assert_eq!(fs::read(file).expect("read region file"), &bytes[start..start + js_len]);
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn carve_filters_short_regions_and_clamps_the_limit() {
    let view = BinaryView::from_bytes("carve-small.bin", b"needle \x00 and more".to_vec());
    let short = view.carve(&CarveOptions { marker: "needle".into(), ..CarveOptions::default() }).expect("short run");
    assert_eq!(short.total, 1);
    assert!(short.regions.is_empty(), "the printable run is shorter than min_region");
    assert!(!short.truncated);

    let clamped =
        view.carve(&CarveOptions { marker: "more".into(), limit: 9_999, ..CarveOptions::default() }).expect("clamped");
    assert_eq!(clamped.limit, 100);

    let (bytes, _start, _marker, _js_len) = carve_fixture();
    let big = BinaryView::from_bytes("carve-cut.bin", bytes);
    let cut =
        big.carve(&CarveOptions { marker: "synthetic-blob".into(), limit: 1, ..CarveOptions::default() }).expect("cut scan");
    assert_eq!(cut.limit, 1);
    assert_eq!(cut.total, 1);
    assert!(cut.truncated);
    assert_eq!(cut.regions.len(), 1);

    let error: CtfError = big.carve(&CarveOptions { marker: "(unclosed".into(), ..CarveOptions::default() }).unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}

#[test]
fn carve_options_use_snake_case_defaults() {
    let defaults: CarveOptions = serde_json::from_str(r#"{ "marker": "ab" }"#).expect("minimal wire options");
    assert_eq!(defaults.min_region, 200);
    assert_eq!(defaults.max_region, 262_144);
    assert_eq!(defaults.expand_left, 4_096);
    assert_eq!(defaults.limit, 20);
    assert_eq!(defaults.output_dir, None);
    assert!(serde_json::from_str::<CarveOptions>("{}").is_err(), "the marker is required");

    let view = BinaryView::from_bytes("carve-wire.bin", b"ab".to_vec());
    let report = view.carve(&defaults).expect("wire carve");
    let value = serde_json::to_value(&report).expect("serialize report");
    assert_eq!(value["min_region"], 200);
    assert_eq!(value["expand_left"], 4_096);
    assert_eq!(value["output_dir"], serde_json::Value::Null);
}

#[test]
fn triage_records_bounded_facts_and_inferences() {
    let file = TempFile::new("pe-triage");
    file.write(&pe_analysis_bytes());
    let session = OpenCtf::new(OpenCtfOptions::new(file.path())).expect("open PE");

    let evidence = triage(&session, &TriageOptions::default()).expect("triage");
    assert!(evidence.iter().any(|item| item.source == "info" && item.kind == EvidenceKind::Fact));
    assert!(evidence.iter().any(|item| item.source == "entropy" && item.kind == EvidenceKind::Inference));
    assert!(evidence.iter().any(|item| item.source == "strings" && item.kind == EvidenceKind::Fact));
    assert!(evidence.iter().all(|item| !item.statement.is_empty()));
}

#[test]
fn solve_and_verify_recover_the_xored_flag() {
    let file = TempFile::new("xor-flag");
    file.write(&[0x24, 0x2e, 0x23, 0x25, 0x39, 0x3a, 0x2d, 0x30, 0x1d, 0x2b, 0x31, 0x1d, 0x20, 0x23, 0x31, 0x2b, 0x21, 0x3f]);
    let session = OpenCtf::new(OpenCtfOptions::new(file.path())).expect("open");

    let candidates = solve(&session, &SolveOptions { offset: 0, length: None, limit: 5 }).expect("solve");
    assert!(!candidates.is_empty(), "solve must return hypotheses");
    assert!(candidates.items.iter().any(|item| item.source == "xor"));

    let verdicts = verify(&candidates, &VerifyRule::flag()).expect("verify");
    assert!(verdicts.iter().any(|verdict| verdict.matched), "the flag must match");
    let found = first_match(&candidates, &VerifyRule::flag()).expect("verify").expect("flag candidate");
    assert_eq!(found.value, "flag{xor_is_basic}");
}

#[test]
fn verify_rejects_a_rule_that_matches_nothing() {
    let file = TempFile::new("plain");
    file.write(b"hello world");
    let session = OpenCtf::new(OpenCtfOptions::new(file.path())).expect("open");

    let candidates = solve(&session, &SolveOptions { offset: 0, length: Some(11), limit: 3 }).expect("solve");
    assert!(first_match(&candidates, &VerifyRule::flag()).expect("verify").is_none());

    let error = verify(&candidates, &VerifyRule::new("(")).unwrap_err();
    assert_eq!(error.code(), "binary/parse");
}
