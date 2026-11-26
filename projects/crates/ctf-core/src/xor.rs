//! Single-byte XOR cracking.
//!
//! CTF misc and crypto files are often XOR-ed with one repeated byte. This
//! module scores all 255 keys on a bounded sample of the selected range and
//! returns the best plaintext guesses; a known key decrypts the whole range.
//! The scoring is deliberately simple and local: no external word list.

use data_binary_inspect::BinarySession;
use serde::{Deserialize, Serialize};

use crate::{CtfError, Result};

/// Default number of key guesses returned.
const DEFAULT_GUESS_LIMIT: usize = 5;

/// Hard cap on key guesses returned.
const MAX_GUESS_LIMIT: usize = 255;

/// Bytes scored per key during brute force.
const SCORE_SAMPLE_LIMIT: usize = 1024 * 1024;

/// Maximum characters rendered into the plaintext preview.
const TEXT_PREVIEW_LIMIT: usize = 8192;

/// Maximum bytes rendered into the hex preview.
const HEX_PREVIEW_LIMIT: usize = 4096;

/// Characters rendered into one key-guess preview.
const GUESS_PREVIEW_LIMIT: usize = 96;

/// Inputs of one [`crate::OpenCtf::xor`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct XorOptions {
    /// First byte of the ciphertext; defaults to the file start.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Ciphertext length; defaults to the rest of the file.
    #[serde(default)]
    pub length: Option<u64>,
    /// Known single-byte key as decimal or hex (`0x42`, `2a`); omitted to brute-force.
    #[serde(default)]
    pub key: Option<String>,
    /// Number of guesses to return; clamped to 255.
    #[serde(default = "default_guess_limit")]
    pub limit: usize,
}

impl Default for XorOptions {
    fn default() -> Self {
        Self { offset: None, length: None, key: None, limit: default_guess_limit() }
    }
}

/// One ranked single-byte key hypothesis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XorKeyGuess {
    /// Key byte as a number.
    pub key: u8,
    /// Key byte as two lowercase hex digits.
    pub key_hex: String,
    /// Printability score; higher is more English-like.
    pub score: f64,
    /// Lossy plaintext preview for this key.
    pub preview: String,
}

/// Result of one [`crate::OpenCtf::xor`] call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XorReport {
    /// Ciphertext length in bytes.
    pub length: usize,
    /// Key byte used for decryption when one was supplied.
    pub key: Option<u8>,
    /// Lossy plaintext when a key was supplied.
    pub plaintext: Option<String>,
    /// Lowercase hex of the plaintext head when a key was supplied.
    pub hex: Option<String>,
    /// Ranked key guesses when no key was supplied.
    pub guesses: Vec<XorKeyGuess>,
}

fn default_guess_limit() -> usize {
    DEFAULT_GUESS_LIMIT
}

/// Cracks or applies a single-byte XOR key over one byte range.
pub fn analyze(session: &BinarySession, options: &XorOptions) -> Result<XorReport> {
    let size = session.size();
    let offset = options.offset.unwrap_or(0);
    if offset > size {
        return Err(CtfError::range("the XOR offset is past the end of the file"));
    }
    let length = options.length.unwrap_or(size - offset).min(size - offset);
    let bytes = session.read(offset, length)?;
    let key = options.key.as_deref().map(parse_key).transpose()?;
    let limit = options.limit.clamp(1, MAX_GUESS_LIMIT);

    let (key, plaintext, hex, guesses) = match key {
        Some(key) => {
            let decoded = apply(bytes, key);
            (Some(key), Some(render_text(&decoded)), Some(render_hex(&decoded)), Vec::new())
        }
        None => {
            let sample = &bytes[..bytes.len().min(SCORE_SAMPLE_LIMIT)];
            let mut guesses = Vec::new();
            for candidate in 1..=u8::MAX {
                let decoded = apply(sample, candidate);
                guesses.push(XorKeyGuess {
                    key: candidate,
                    key_hex: format!("{candidate:02x}"),
                    score: score(&decoded),
                    preview: render_guess(&decoded),
                });
            }
            guesses.sort_by(|left, right| right.score.total_cmp(&left.score).then_with(|| left.key.cmp(&right.key)));
            guesses.truncate(limit);
            (None, None, None, guesses)
        }
    };

    Ok(XorReport { length: bytes.len(), key, plaintext, hex, guesses })
}

/// Parses a one-byte key written as decimal, `0x` hex or bare hex letters.
fn parse_key(text: &str) -> Result<u8> {
    let trimmed = text.trim();
    let hex = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"));
    let parsed = if let Some(hex) = hex {
        u8::from_str_radix(hex, 16).ok()
    }
    else if trimmed.len() == 2
        && trimmed.chars().all(|ch| ch.is_ascii_hexdigit())
        && trimmed.chars().any(|ch| ch.is_ascii_alphabetic())
    {
        u8::from_str_radix(trimmed, 16).ok()
    }
    else {
        trimmed.parse::<u8>().ok()
    };
    parsed.ok_or_else(|| CtfError::parse("the XOR key must be one byte, decimal or hex such as 0x42"))
}

fn apply(bytes: &[u8], key: u8) -> Vec<u8> {
    bytes.iter().map(|byte| byte ^ key).collect()
}

/// Scores printable and English-like bytes; binary noise scores near zero.
fn score(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut total = 0.0;
    for &byte in bytes {
        total += match byte {
            b'{' | b'}' | b'_' => 1.6,
            b' ' => 1.4,
            b'e' | b't' | b'a' | b'o' | b'i' | b'n' => 1.4,
            b'a'..=b'z' => 1.1,
            b'A'..=b'Z' => 0.8,
            b'0'..=b'9' => 0.9,
            b'\n' | b'\r' | b'\t' => 0.6,
            0x21..=0x7e => 0.7,
            0x80..=0xff => 0.1,
            _ => -1.0,
        };
    }
    (total / bytes.len() as f64).max(0.0)
}

fn render_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.chars().count() > TEXT_PREVIEW_LIMIT { text.chars().take(TEXT_PREVIEW_LIMIT).collect() } else { text.into_owned() }
}

fn render_hex(bytes: &[u8]) -> String {
    let limit = bytes.len().min(HEX_PREVIEW_LIMIT);
    let mut hex = String::with_capacity(limit * 2);
    for byte in &bytes[..limit] {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn render_guess(bytes: &[u8]) -> String {
    bytes.iter().take(GUESS_PREVIEW_LIMIT).map(|&byte| if (0x20..=0x7e).contains(&byte) { byte as char } else { '.' }).collect()
}
