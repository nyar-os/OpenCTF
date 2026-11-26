//! De Bruijn cyclic patterns for stack-offset measurement.
//!
//! The pattern is generated locally over the lowercase alphabet with order 3,
//! so every three-character window is unique. `find` locates the pattern piece
//! that overwrote the saved return address and returns its zero-based offset.

use serde::{Deserialize, Serialize};

use crate::{CtfError, Result};

/// Alphabet used by the generated pattern.
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

/// Order of the de Bruijn sequence.
const ORDER: usize = 3;

/// Default pattern length.
const DEFAULT_LENGTH: usize = 128;

/// Hard cap on the pattern recorded in the report.
const MAX_LENGTH: usize = 65536;

/// Bytes searched when locating a `find` value.
const FIND_WINDOW: usize = 1024 * 1024;

/// Inputs of one [`crate::cyclic`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CyclicOptions {
    /// Pattern length; clamped to 65536.
    #[serde(default = "default_length")]
    pub length: usize,
    /// Pattern piece to locate; its zero-based offset is reported when found.
    #[serde(default)]
    pub find: Option<String>,
}

impl Default for CyclicOptions {
    fn default() -> Self {
        Self { length: default_length(), find: None }
    }
}

/// Result of one cyclic pattern request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CyclicReport {
    /// Alphabet of the de Bruijn sequence.
    pub alphabet: String,
    /// Uniqueness order; every window of this many characters is unique.
    pub order: usize,
    /// Length of the reported pattern.
    pub length: usize,
    /// The generated pattern.
    pub pattern: String,
    /// The searched piece, when one was requested.
    pub find: Option<String>,
    /// Zero-based offset of `find` in the cyclic stream, when found.
    pub offset: Option<usize>,
}

fn default_length() -> usize {
    DEFAULT_LENGTH
}

/// Generates the pattern and locates `find` inside an extended cyclic stream.
pub fn run(options: &CyclicOptions) -> Result<CyclicReport> {
    if options.length == 0 {
        return Err(CtfError::range("the cyclic pattern length must be positive"));
    }
    let base = de_bruijn(ALPHABET.len(), ORDER);
    let length = options.length.min(MAX_LENGTH);
    let pattern = repeat_to(&base, length);
    let offset = options.find.as_ref().map(|needle| {
        if needle.is_empty() {
            return None;
        }
        let window = FIND_WINDOW.max(needle.len() * 2);
        let stream = repeat_to(&base, window);
        stream.find(needle.as_str())
    });
    Ok(CyclicReport {
        alphabet: String::from_utf8_lossy(ALPHABET).into_owned(),
        order: ORDER,
        length,
        pattern,
        find: options.find.clone(),
        offset: offset.unwrap_or(None),
    })
}

/// Builds a de Bruijn sequence `B(k, n)` over the first `k` alphabet letters.
fn de_bruijn(k: usize, n: usize) -> Vec<u8> {
    let mut scratch = vec![0usize; k * n];
    let mut digits = Vec::new();
    generate(1, 1, k, n, &mut scratch, &mut digits);
    let mut sequence: Vec<u8> = digits.iter().map(|&digit| ALPHABET[digit]).collect();
    let closing = sequence[..n - 1].to_vec();
    sequence.extend_from_slice(&closing);
    sequence
}

fn generate(t: usize, p: usize, k: usize, n: usize, scratch: &mut [usize], digits: &mut Vec<usize>) {
    if t > n {
        if n.is_multiple_of(p) {
            digits.extend_from_slice(&scratch[1..=p]);
        }
        return;
    }
    scratch[t] = scratch[t - p];
    generate(t + 1, p, k, n, scratch, digits);
    for digit in scratch[t - p] + 1..k {
        scratch[t] = digit;
        generate(t + 1, t, k, n, scratch, digits);
    }
}

fn repeat_to(base: &[u8], length: usize) -> String {
    if base.is_empty() {
        return String::new();
    }
    let mut output = String::with_capacity(length);
    while output.len() < length {
        let remaining = length - output.len();
        let take = remaining.min(base.len());
        output.push_str(&String::from_utf8_lossy(&base[..take]));
    }
    output
}
