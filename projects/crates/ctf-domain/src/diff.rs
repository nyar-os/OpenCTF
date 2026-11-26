//! Byte-level comparison of two open binaries.
//!
//! The comparison itself belongs to `data-binary-inspect`; this module maps the
//! owner report onto the product shape and keeps the content hashes already
//! reported by the inspection engine, so `diff` never grows a second hashing
//! convention. Differing ranges stay bounded to keep huge, completely different
//! files cheap to report.

use data_binary_inspect::{
    BinarySession,
    diff::{DiffOptions, diff},
};
use serde::{Deserialize, Serialize};

use crate::Result;

/// Maximum number of differing ranges kept in one report.
const MAX_RANGES: usize = 64;

/// One contiguous run of differing bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffRange {
    /// File offset where the run starts.
    pub offset: u64,
    /// Length of the run in bytes.
    pub length: u64,
}

/// Result of one [`crate::OpenCtf::diff`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    /// Size of the left file.
    pub left_size: u64,
    /// Size of the right file.
    pub right_size: u64,
    /// Content hash of the left file.
    pub left_hash: String,
    /// Content hash of the right file.
    pub right_hash: String,
    /// Whether both files are byte-for-byte identical.
    pub identical: bool,
    /// First offset that differs, or where one file ends.
    pub first_difference: Option<u64>,
    /// Differing ranges that survived the limit.
    pub differences: Vec<DiffRange>,
    /// Number of differing ranges before the limit was applied.
    pub total: usize,
    /// Whether the limit removed ranges.
    pub truncated: bool,
    /// Number of bytes compared: the shorter of the two sizes.
    pub compared_bytes: u64,
}

/// Compares two sessions through the shared byte-diff owner.
pub(crate) fn compare(left: &BinarySession, right: &BinarySession) -> Result<DiffReport> {
    let left_size = left.size();
    let right_size = right.size();
    let left_bytes = left.read(0, left_size)?;
    let right_bytes = right.read(0, right_size)?;
    let left_hash = left.info()?.hash;
    let right_hash = right.info()?.hash;

    let report = diff(left_bytes, right_bytes, &DiffOptions::new(MAX_RANGES, 16));
    let identical = left_size == right_size && report.summary.equal_prefix == left_size;
    let differences = report
        .ranges
        .iter()
        .map(|range| DiffRange { offset: range.offset, length: range.left_length.max(range.right_length) })
        .collect();

    Ok(DiffReport {
        left_size,
        right_size,
        left_hash,
        right_hash,
        identical,
        first_difference: (!identical).then_some(report.summary.equal_prefix),
        differences,
        total: report.total,
        truncated: report.truncated,
        compared_bytes: left_size.min(right_size),
    })
}
