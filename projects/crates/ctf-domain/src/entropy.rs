//! Shannon entropy per section and for the whole file, plus the `PE` overlay.
//!
//! The arithmetic belongs to `data-binary-inspect`; this module keeps the
//! product projection: which sections to measure, the `PE` overlay range and the
//! four-decimal rounding used in reports. The overlay starts after the highest
//! section raw end; a file with no trailing bytes reports no overlay at all.

use data_binary_inspect::{BinaryFormat, BinarySession, entropy::range as entropy_range};
use serde::{Deserialize, Serialize};

use crate::Result;

/// Entropy of one section payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SectionEntropy {
    /// Section name as stored in the container.
    pub name: String,
    /// Raw file offset of the section payload.
    pub offset: u64,
    /// Declared raw size in bytes.
    pub size: u64,
    /// Shannon entropy in bits per byte.
    pub entropy: f64,
}

/// Bytes that follow the last section payload of a `PE` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverlayInfo {
    /// File offset where the overlay starts.
    pub offset: u64,
    /// Overlay length in bytes.
    pub size: u64,
}

/// Entropy summary of one binary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntropyReport {
    /// File size in bytes.
    pub file_size: u64,
    /// Shannon entropy of the whole file in bits per byte.
    pub file_entropy: f64,
    /// Per-section entropy; empty when sections are unavailable.
    pub sections: Vec<SectionEntropy>,
    /// `PE` overlay, or `None` when there are no trailing bytes.
    pub overlay: Option<OverlayInfo>,
}

/// Summarizes one open session.
pub(crate) fn analyze(session: &BinarySession) -> Result<EntropyReport> {
    let file_size = session.size();
    let bytes = session.read(0, file_size)?;

    let sections = match session.format() {
        BinaryFormat::Pe | BinaryFormat::Elf | BinaryFormat::MachO => {
            let mut sections = Vec::new();
            for section in session.sections()? {
                let start = section.raw_pointer.min(file_size);
                let end = section.raw_pointer.saturating_add(section.raw_size).min(file_size);
                let entropy = if end > start { round(entropy_range(bytes, start, Some(end - start))?) } else { 0.0 };
                sections.push(SectionEntropy {
                    name: section.name,
                    offset: section.raw_pointer,
                    size: section.raw_size,
                    entropy,
                });
            }
            sections
        }
        _ => Vec::new(),
    };

    let overlay = if session.format() == BinaryFormat::Pe {
        sections
            .iter()
            .map(|section| section.offset.saturating_add(section.size))
            .max()
            .and_then(|end| (file_size > end).then_some(OverlayInfo { offset: end, size: file_size - end }))
    }
    else {
        None
    };

    Ok(EntropyReport { file_size, file_entropy: round(entropy_range(bytes, 0, None)?), sections, overlay })
}

/// Rounds a bits-per-byte value to the four decimals the reports print.
fn round(entropy: f64) -> f64 {
    (entropy * 10_000.0).round() / 10_000.0
}
