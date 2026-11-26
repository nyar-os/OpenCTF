//! Raw byte-range export to a caller-chosen file.
//!
//! The range check belongs to `data-binary-inspect`; this module keeps the
//! product policy (the 64 MiB clamp and the destination path) and writes the
//! selected window unchanged, so a range can be fed to a second tool without a
//! lossy round trip.

use std::path::Path;

use data_binary_inspect::{BinarySession, dump::window};
use serde::{Deserialize, Serialize};

use crate::Result;

/// Hard cap on the number of bytes one dump request can export.
const MAX_DUMP_LENGTH: usize = 64 * 1024 * 1024;

/// Inputs of one [`crate::OpenCtf::dump`] call.
///
/// Serialized as JSON with camelCase keys, so `{ "offset": 1024, "length": 256,
/// "output": "range.bin" }` is the wire form the addon and the TypeScript
/// client both use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DumpOptions {
    /// File offset of the first byte to export.
    pub offset: u64,
    /// Number of bytes to export; requests above 64 MiB are clamped to the cap.
    pub length: usize,
    /// Destination file the raw bytes are written to.
    pub output: String,
}

/// Result of one [`crate::OpenCtf::dump`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DumpReport {
    /// File offset the export started at.
    pub offset: u64,
    /// Requested length after the 64 MiB clamp.
    pub length: usize,
    /// Number of bytes actually written to the output file.
    pub written: usize,
    /// Destination file the bytes were written to.
    pub output: String,
}

/// Exports the byte range described by `options` into `options.output`.
pub fn dump(session: &BinarySession, options: &DumpOptions) -> Result<DumpReport> {
    let length = options.length.min(MAX_DUMP_LENGTH);
    let bytes = session.read(options.offset, length as u64)?;
    let selected = window(bytes, 0, None)?;
    std::fs::write(Path::new(&options.output), selected)?;
    Ok(DumpReport { offset: options.offset, length, written: selected.len(), output: options.output.clone() })
}
