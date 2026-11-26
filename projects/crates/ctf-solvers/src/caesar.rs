//! Caesar shift cracking over ASCII letters.
//!
//! With a `shift` the selected range is decoded directly; without one all 25
//! rotations are scored with the same flag-aware heuristic used by the XOR
//! cracker, so `flag{...}` and English-like text rise to the top.

use data_binary_inspect::BinarySession;
use serde::{Deserialize, Serialize};

use crate::{CtfError, Result, xor::score_plaintext};

/// Maximum characters rendered into the plaintext preview.
const TEXT_PREVIEW_LIMIT: usize = 8192;

/// Characters rendered into one candidate preview.
const GUESS_PREVIEW_LIMIT: usize = 96;

/// Default number of candidates returned.
const DEFAULT_LIMIT: usize = 5;

/// Inputs of one `OpenCtf::caesar` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaesarOptions {
    /// First byte of the ciphertext; defaults to the file start.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Ciphertext length; defaults to the rest of the file.
    #[serde(default)]
    pub length: Option<u64>,
    /// Known rotation `0..=25`; omitted to try every shift.
    #[serde(default)]
    pub shift: Option<u8>,
    /// Number of shifts to return; clamped to 25.
    #[serde(default = "default_limit")]
    pub limit: usize,
}

impl Default for CaesarOptions {
    fn default() -> Self {
        Self { offset: None, length: None, shift: None, limit: default_limit() }
    }
}

/// One ranked shift hypothesis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaesarCandidate {
    /// Rotation applied to reach this plaintext.
    pub shift: u8,
    /// Printability score; higher is more flag-like or English-like.
    pub score: f64,
    /// Lossy plaintext preview.
    pub preview: String,
}

/// Result of one Caesar crack or decode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaesarReport {
    /// Ciphertext length in bytes.
    pub length: usize,
    /// Shift used for the plaintext when one was supplied.
    pub shift: Option<u8>,
    /// Lossy plaintext when a shift was supplied.
    pub plaintext: Option<String>,
    /// Ranked candidates when no shift was supplied.
    pub candidates: Vec<CaesarCandidate>,
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

/// Decodes or brute-forces a Caesar rotation over one byte range.
pub fn analyze(session: &BinarySession, options: &CaesarOptions) -> Result<CaesarReport> {
    let size = session.size();
    let offset = options.offset.unwrap_or(0);
    if offset > size {
        return Err(CtfError::range("the Caesar offset is past the end of the file"));
    }
    let length = options.length.unwrap_or(size - offset).min(size - offset);
    let bytes = session.read(offset, length)?;
    if let Some(shift) = options.shift {
        if shift > 25 {
            return Err(CtfError::parse("the Caesar shift must be between 0 and 25"));
        }
        let decoded = rotate(bytes, shift);
        return Ok(CaesarReport {
            length: bytes.len(),
            shift: Some(shift),
            plaintext: Some(render_text(&decoded)),
            candidates: Vec::new(),
        });
    }
    let limit = options.limit.clamp(1, 25);
    let mut candidates = Vec::new();
    for shift in 1..=25u8 {
        let decoded = rotate(bytes, shift);
        candidates.push(CaesarCandidate { shift, score: score_plaintext(&decoded), preview: render_guess(&decoded) });
    }
    candidates.sort_by(|left, right| right.score.total_cmp(&left.score).then_with(|| left.shift.cmp(&right.shift)));
    candidates.truncate(limit);
    Ok(CaesarReport { length: bytes.len(), shift: None, plaintext: None, candidates })
}

fn rotate(bytes: &[u8], shift: u8) -> Vec<u8> {
    bytes
        .iter()
        .map(|&byte| match byte {
            b'a'..=b'z' => b'a' + (byte - b'a' + 26 - shift) % 26,
            b'A'..=b'Z' => b'A' + (byte - b'A' + 26 - shift) % 26,
            other => other,
        })
        .collect()
}

fn render_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.chars().count() > TEXT_PREVIEW_LIMIT { text.chars().take(TEXT_PREVIEW_LIMIT).collect() } else { text.into_owned() }
}

fn render_guess(bytes: &[u8]) -> String {
    bytes.iter().take(GUESS_PREVIEW_LIMIT).map(|&byte| if (0x20..=0x7e).contains(&byte) { byte as char } else { '.' }).collect()
}
