//! PNG chunk walker with text extraction and trailing-data detection.
//!
//! The signature and every chunk header are decoded statically; `tEXt`, `zTXt`
//! and `iTXt` payloads are surfaced as text, and bytes after `IEND` are reported
//! instead of being silently ignored. Each complete chunk is checked against its
//! stored CRC-32 through the shared `data-checksum` owner, so a mismatching chunk
//! is reported as a fact rather than treated as proof of integrity.

use data_binary_inspect::BinarySession;
use data_checksum::Crc32;
use data_compression::{CodecLimits, Envelope};
use serde::{Deserialize, Serialize};

use crate::{CtfError, Result};

/// The eight-byte PNG signature.
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/// Default cap on listed chunks.
const DEFAULT_CHUNK_LIMIT: usize = 256;

/// Hard cap on listed chunks.
const MAX_CHUNK_LIMIT: usize = 4096;

/// Maximum chunk payload read for text extraction.
const TEXT_READ_LIMIT: u64 = 1024 * 1024;

/// Maximum inflated text bytes.
const TEXT_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

/// Maximum characters recorded per text chunk.
const TEXT_CHAR_LIMIT: usize = 4096;

/// Inputs of one `OpenCtf::png` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PngOptions {
    /// File offset of the PNG signature; defaults to zero.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Cap on listed chunks; clamped to 4096.
    #[serde(default = "default_chunk_limit")]
    pub limit: usize,
}

impl Default for PngOptions {
    fn default() -> Self {
        Self { offset: None, limit: default_chunk_limit() }
    }
}

/// One PNG chunk header, with text when the chunk carries any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PngChunk {
    /// Zero-based chunk index after the signature.
    pub index: usize,
    /// Four-character chunk type.
    pub kind: String,
    /// Declared payload length.
    pub length: u32,
    /// File offset of the length field.
    pub offset: u64,
    /// File offset of the payload.
    pub data_offset: u64,
    /// Keyword of a `tEXt`, `zTXt` or `iTXt` chunk.
    pub keyword: Option<String>,
    /// Decoded text of a `tEXt`, `zTXt` or `iTXt` chunk.
    pub text: Option<String>,
    /// Whether the stored chunk CRC-32 matches the bytes read.
    pub crc_ok: bool,
}

/// Result of one PNG walk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PngReport {
    /// Width from `IHDR`.
    pub width: Option<u32>,
    /// Height from `IHDR`.
    pub height: Option<u32>,
    /// Bit depth from `IHDR`.
    pub bit_depth: Option<u8>,
    /// Color type from `IHDR`.
    pub color_type: Option<u8>,
    /// Interlace method from `IHDR`.
    pub interlace: Option<u8>,
    /// Total chunks seen, before the listing limit.
    pub chunk_count: usize,
    /// Chunks whose stored CRC-32 did not match, across the whole walk.
    pub crc_mismatches: usize,
    /// Listed chunks, cut at the limit.
    pub chunks: Vec<PngChunk>,
    /// Whether the chunk list was cut at the limit.
    pub truncated: bool,
    /// Whether an `IEND` chunk ended the walk.
    pub complete: bool,
    /// File offset where bytes after `IEND` begin.
    pub trailing_offset: Option<u64>,
    /// Bytes present after `IEND`.
    pub trailing_bytes: u64,
}

fn default_chunk_limit() -> usize {
    DEFAULT_CHUNK_LIMIT
}

/// Walks the PNG container starting at the requested offset.
pub fn analyze(session: &BinarySession, options: &PngOptions) -> Result<PngReport> {
    let size = session.size();
    let start = options.offset.unwrap_or(0);
    if start.checked_add(8).is_none_or(|end| end > size) {
        return Err(CtfError::parse("the range is too short to hold a PNG signature"));
    }
    if session.read(start, 8)? != &PNG_SIGNATURE[..] {
        return Err(CtfError::parse("the range does not start with a PNG signature"));
    }
    let limit = options.limit.clamp(1, MAX_CHUNK_LIMIT);
    let mut report = PngReport {
        width: None,
        height: None,
        bit_depth: None,
        color_type: None,
        interlace: None,
        chunk_count: 0,
        crc_mismatches: 0,
        chunks: Vec::new(),
        truncated: false,
        complete: false,
        trailing_offset: None,
        trailing_bytes: 0,
    };
    let mut cursor = start + 8;
    let mut index = 0usize;
    while cursor + 8 <= size {
        let header = session.read(cursor, 8)?;
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let kind = String::from_utf8_lossy(&header[4..8]).into_owned();
        let data_offset = cursor + 8;
        let end = match data_offset.checked_add(u64::from(length)).and_then(|end| end.checked_add(4)) {
            Some(end) if end <= size => end,
            _ => {
                return Err(CtfError::parse(format!(
                    "PNG chunk {index} ({kind}) declares {length} payload bytes past the end of the file"
                )));
            }
        };
        report.chunk_count += 1;
        let crc_ok = chunk_crc_ok(session, &header[4..8], data_offset, length, end - 4)?;
        if !crc_ok {
            report.crc_mismatches += 1;
        }
        let (keyword, text) = extract_text(session, &kind, data_offset, length)?;

        if kind == "IHDR" && length >= 13 {
            let data = session.read(data_offset, 13)?;
            report.width = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            report.height = Some(u32::from_be_bytes([data[4], data[5], data[6], data[7]]));
            report.bit_depth = Some(data[8]);
            report.color_type = Some(data[9]);
            report.interlace = Some(data[12]);
        }
        if report.chunks.len() < limit {
            report
                .chunks
                .push(PngChunk { index, kind: kind.clone(), length, offset: cursor, data_offset, keyword, text, crc_ok });
        }
        else {
            report.truncated = true;
        }
        index += 1;
        cursor = end;
        if kind == "IEND" {
            report.complete = true;
            if end < size {
                report.trailing_offset = Some(end);
                report.trailing_bytes = size - end;
            }
            break;
        }
    }
    Ok(report)
}

/// Compares the stored chunk CRC-32 with the chunk type and payload.
fn chunk_crc_ok(
    session: &BinarySession,
    kind: &[u8],
    data_offset: u64,
    length: u32,
    crc_offset: u64,
) -> Result<bool> {
    let mut crc = Crc32::new();
    crc.update(kind);
    crc.update(session.read(data_offset, u64::from(length))?);
    let stored = session.read(crc_offset, 4)?;
    let stored = u32::from_be_bytes([stored[0], stored[1], stored[2], stored[3]]);
    Ok(stored == crc.value())
}

fn extract_text(session: &BinarySession, kind: &str, offset: u64, length: u32) -> Result<(Option<String>, Option<String>)> {
    if !matches!(kind, "tEXt" | "zTXt" | "iTXt") || length == 0 {
        return Ok((None, None));
    }
    let read = u64::from(length).min(TEXT_READ_LIMIT);
    let data = session.read(offset, read)?;
    let fields = match kind {
        "tEXt" => {
            let Some((keyword, text)) = take_field(data)
            else {
                return Ok((None, None));
            };
            (Some(latin1(keyword)), Some(latin1_limited(text)))
        }
        "zTXt" => {
            let Some((keyword, rest)) = take_field(data)
            else {
                return Ok((None, None));
            };
            let Some((_method, compressed)) = take_field(rest)
            else {
                return Ok((None, None));
            };
            (Some(latin1(keyword)), Some(latin1_limited(&inflate(compressed)?)))
        }
        "iTXt" => {
            let Some((keyword, rest)) = take_field(data)
            else {
                return Ok((None, None));
            };
            let Some((flag, rest)) = take_field(rest)
            else {
                return Ok((None, None));
            };
            let Some((_method, rest)) = take_field(rest)
            else {
                return Ok((None, None));
            };
            let Some((_language, rest)) = take_field(rest)
            else {
                return Ok((None, None));
            };
            let Some((_translated, text)) = take_field(rest)
            else {
                return Ok((None, None));
            };
            let decoded = if flag.first() == Some(&b'1') { inflate(text)? } else { text.to_vec() };
            (Some(latin1(keyword)), Some(latin1_limited(&decoded)))
        }
        _ => (None, None),
    };
    Ok(fields)
}

fn inflate(bytes: &[u8]) -> Result<Vec<u8>> {
    let decoded = Envelope::Zlib.decode(bytes, CodecLimits::new().with_max_output_bytes(TEXT_OUTPUT_LIMIT as u64));
    if decoded.is_complete() {
        Ok(decoded.output)
    }
    else {
        Err(CtfError::parse(format!("the PNG text payload is not a complete zlib stream ({})", decoded.status.code())))
    }
}

fn take_field(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let index = data.iter().position(|&byte| byte == 0)?;
    Some((&data[..index], &data[index + 1..]))
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&byte| byte as char).collect()
}

fn latin1_limited(bytes: &[u8]) -> String {
    bytes.iter().take(TEXT_CHAR_LIMIT).map(|&byte| byte as char).collect()
}
