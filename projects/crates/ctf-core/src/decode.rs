//! Text and byte decoders used by encoding challenges.
//!
//! Base64, base64url, hex and base32 run through `boost.rs/boost-crypto` and
//! the local extension of its encodings; rot13, percent-encoding and HTML
//! entities are decoded here because the upstream crate intentionally exposes
//! no such codecs. `auto` chains the decoders while the output stays printable
//! and shrinks, which covers the usual "base64 of hex of base64" nesting.

use boost_crypto::encoding::{base64_decode, hex_decode};
use data_binary_inspect::BinarySession;
use serde::{Deserialize, Serialize};

use crate::{CtfError, Result};

/// Default number of chained decodes in `auto` mode.
const DEFAULT_DEPTH: usize = 3;

/// Hard cap on chained decodes in `auto` mode.
const MAX_DEPTH: usize = 8;

/// Maximum characters rendered into [`DecodeReport::text`].
const TEXT_PREVIEW_LIMIT: usize = 8192;

/// Maximum bytes rendered into [`DecodeReport::hex`].
const HEX_PREVIEW_LIMIT: usize = 4096;

/// Decoder selected by [`DecodeOptions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecodeCodec {
    /// Chain the decoders while the output stays printable and shrinks.
    #[default]
    Auto,
    /// Standard base64 with or without padding.
    Base64,
    /// URL-safe base64 with or without padding.
    Base64Url,
    /// Hex digits, optionally separated or `0x`-prefixed.
    Hex,
    /// RFC 4648 base32, padding optional.
    Base32,
    /// ROT13 over ASCII letters.
    Rot13,
    /// Percent-encoded bytes; `+` becomes a space.
    Percent,
    /// Named and numeric HTML entities.
    Html,
}

impl DecodeCodec {
    /// Lowercase identifier used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Base64 => "base64",
            Self::Base64Url => "base64url",
            Self::Hex => "hex",
            Self::Base32 => "base32",
            Self::Rot13 => "rot13",
            Self::Percent => "percent",
            Self::Html => "html",
        }
    }

    fn apply(self, input: &[u8]) -> Option<Vec<u8>> {
        let text = std::str::from_utf8(input).ok()?;
        match self {
            Self::Auto => None,
            Self::Base64 => base64_decode(&normalize_base64(text, false)?).ok(),
            Self::Base64Url => base64_decode(&normalize_base64(text, true)?).ok(),
            Self::Hex => hex_decode(&normalize_hex(text)).ok(),
            Self::Base32 => base32_decode(text),
            Self::Rot13 => Some(rot13(text).into_bytes()),
            Self::Percent => percent_decode(text),
            Self::Html => html_decode(text),
        }
    }
}

/// Inputs of one [`crate::OpenCtf::decode`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DecodeOptions {
    /// Decoder to apply; `auto` chains them.
    #[serde(default)]
    pub codec: DecodeCodec,
    /// First byte of the encoded input; defaults to the file start.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Bytes of encoded input; defaults to the rest of the file.
    #[serde(default)]
    pub length: Option<u64>,
    /// Maximum chained decodes in `auto` mode; clamped to 8.
    #[serde(default = "default_depth")]
    pub depth: usize,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self { codec: DecodeCodec::default(), offset: None, length: None, depth: default_depth() }
    }
}

/// One applied decoder with its byte counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodeStep {
    /// Decoder that produced this step.
    pub codec: String,
    /// Input size in bytes.
    pub input_length: usize,
    /// Output size in bytes.
    pub output_length: usize,
}

/// Result of one [`crate::OpenCtf::decode`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodeReport {
    /// Decoders applied, in order.
    pub steps: Vec<DecodeStep>,
    /// Final output size in bytes.
    pub bytes: usize,
    /// Lossy UTF-8 rendering, cut at the preview limit.
    pub text: String,
    /// Lowercase hex of the first bytes, cut at the preview limit.
    pub hex: String,
    /// Whether `text` or `hex` was cut at the preview limit.
    pub truncated: bool,
}

fn default_depth() -> usize {
    DEFAULT_DEPTH
}

/// Decodes one byte range with the selected codec.
pub fn analyze(session: &BinarySession, options: &DecodeOptions) -> Result<DecodeReport> {
    let size = session.size();
    let offset = options.offset.unwrap_or(0);
    if offset > size {
        return Err(CtfError::range("the decode offset is past the end of the file"));
    }
    let available = size - offset;
    let length = options.length.unwrap_or(available).min(available);
    let mut current = session.read(offset, length)?.to_vec();
    let mut steps = Vec::new();
    if options.codec == DecodeCodec::Auto {
        let depth = options.depth.clamp(1, MAX_DEPTH);
        for _ in 0..depth {
            let Some((codec, decoded)) = auto_step(&current)
            else {
                break;
            };
            steps.push(DecodeStep {
                codec: codec.as_str().to_string(),
                input_length: current.len(),
                output_length: decoded.len(),
            });
            current = decoded;
        }
    }
    else {
        let decoded = options
            .codec
            .apply(&current)
            .ok_or_else(|| CtfError::parse(format!("the input is not valid {}", options.codec.as_str())))?;
        steps.push(DecodeStep {
            codec: options.codec.as_str().to_string(),
            input_length: current.len(),
            output_length: decoded.len(),
        });
        current = decoded;
    }
    Ok(report(current, steps))
}

/// Applies the first codec that shrinks the input into printable bytes.
fn auto_step(input: &[u8]) -> Option<(DecodeCodec, Vec<u8>)> {
    for codec in [
        DecodeCodec::Base64,
        DecodeCodec::Base64Url,
        DecodeCodec::Hex,
        DecodeCodec::Base32,
        DecodeCodec::Percent,
        DecodeCodec::Html,
    ] {
        if let Some(decoded) = codec.apply(input)
            && !decoded.is_empty()
            && decoded.len() < input.len()
            && is_probably_text(&decoded)
        {
            return Some((codec, decoded));
        }
    }
    None
}

fn report(bytes: Vec<u8>, steps: Vec<DecodeStep>) -> DecodeReport {
    let text = String::from_utf8_lossy(&bytes);
    let text_truncated = text.chars().count() > TEXT_PREVIEW_LIMIT;
    let rendered: String = if text_truncated { text.chars().take(TEXT_PREVIEW_LIMIT).collect() } else { text.into_owned() };
    let hex_bytes = bytes.len().min(HEX_PREVIEW_LIMIT);
    let mut hex = String::with_capacity(hex_bytes * 2);
    for byte in &bytes[..hex_bytes] {
        hex.push_str(&format!("{byte:02x}"));
    }
    DecodeReport {
        steps,
        bytes: bytes.len(),
        text: rendered,
        hex,
        truncated: text_truncated || bytes.len() > HEX_PREVIEW_LIMIT,
    }
}

/// Strips whitespace and padding, maps URL-safe characters, then pads to four.
fn normalize_base64(text: &str, url_safe: bool) -> Option<String> {
    let mut cleaned = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_whitespace() || ch == '=' {
            continue;
        }
        let mapped = if url_safe {
            match ch {
                '-' => '+',
                '_' => '/',
                other => other,
            }
        }
        else {
            ch
        };
        if mapped.is_ascii_alphanumeric() || mapped == '+' || mapped == '/' {
            cleaned.push(mapped);
        }
        else {
            return None;
        }
    }
    if cleaned.is_empty() || cleaned.len() % 4 == 1 {
        return None;
    }
    while cleaned.len() % 4 != 0 {
        cleaned.push('=');
    }
    Some(cleaned)
}

/// Strips separators and `0x` prefixes before strict hex decoding.
fn normalize_hex(text: &str) -> String {
    let stripped = text.replace("0x", "").replace("0X", "");
    stripped.chars().filter(|ch| !ch.is_whitespace() && !matches!(ch, ',' | ':' | ';' | '-')).collect()
}

/// Decodes RFC 4648 base32, ignoring whitespace and padding.
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut buffer = 0u32;
    let mut bits = 0u32;
    let mut output = Vec::new();
    for ch in text.chars() {
        if ch.is_whitespace() || ch == '=' {
            continue;
        }
        let value = match ch.to_ascii_uppercase() {
            letter @ 'A'..='Z' => letter as u32 - 'A' as u32,
            digit @ '2'..='7' => digit as u32 - '2' as u32 + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if output.is_empty() { None } else { Some(output) }
}

fn rot13(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            'a'..='z' => char::from(b'a' + (ch as u8 - b'a' + 13) % 26),
            'A'..='Z' => char::from(b'A' + (ch as u8 - b'A' + 13) % 26),
            other => other,
        })
        .collect()
}

fn percent_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return None;
                }
                let high = hex_digit(bytes[index + 1])?;
                let low = hex_digit(bytes[index + 2])?;
                output.push(high << 4 | low);
                index += 3;
                changed = true;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
                changed = true;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    if changed { Some(output) } else { None }
}

fn html_decode(text: &str) -> Option<Vec<u8>> {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    let mut changed = false;
    while let Some(index) = rest.find('&') {
        output.push_str(&rest[..index]);
        let tail = &rest[index..];
        let Some(end) = tail.find(';')
        else {
            output.push_str(tail);
            return if changed { Some(output.into_bytes()) } else { None };
        };
        let entity = &tail[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                u32::from_str_radix(&entity[2..], 16).ok().and_then(char::from_u32)
            }
            _ if entity.starts_with('#') => entity[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(ch) => {
                output.push(ch);
                changed = true;
                rest = &tail[end + 1..];
            }
            None => {
                output.push('&');
                rest = &tail[1..];
            }
        }
    }
    output.push_str(rest);
    if changed { Some(output.into_bytes()) } else { None }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_probably_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let printable = bytes.iter().filter(|&&byte| matches!(byte, b'\n' | b'\r' | b'\t' | 0x20..=0x7e)).count();
    printable * 100 >= bytes.len() * 85
}
