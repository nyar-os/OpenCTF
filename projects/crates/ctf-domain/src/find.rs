//! Byte-regex search over the opened bytes.
//!
//! Where [`crate::OpenCtf::search`] matches one fixed pattern, this module
//! evaluates a regular expression against the whole file with the `regex`
//! crate's byte matcher, so a single pass can describe a family of layouts.
//! Plain literal patterns are handed to `data-binary-inspect`'s `find`; patterns
//! that need regex syntax stay on the product matcher because the pinned owner
//! only scans literals. Matches are reported with their file offset, byte length
//! and a bounded printable preview; non-printable bytes collapse to dots.

use data_binary_inspect::{
    BinarySession, SearchMode,
    find::{FindOptions as InspectFindOptions, find as inspect_find},
};
use regex::bytes::{Match, Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::{CtfError, Result};

/// Hit limit used when the caller does not ask for one.
const DEFAULT_LIMIT: usize = 100;
/// Preview length used when the caller does not ask for one.
const DEFAULT_CONTEXT: usize = 80;
/// Hard cap on the number of hits that can be returned.
const MAX_LIMIT: usize = 5_000;
/// Hard cap on the preview length rendered per hit.
const MAX_CONTEXT: usize = 512;

fn default_limit() -> Option<usize> {
    Some(DEFAULT_LIMIT)
}

fn default_context() -> usize {
    DEFAULT_CONTEXT
}

/// Inputs of one [`crate::OpenCtf::find`] call.
///
/// Serialized as JSON with camelCase keys, so `{ "pattern": "marker-[0-9]",
/// "caseInsensitive": true }` is the wire form the addon and the TypeScript
/// client both use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindOptions {
    /// Regular expression evaluated against the raw file bytes.
    pub pattern: String,
    /// Whether ASCII letters match case-insensitively.
    #[serde(default)]
    pub case_insensitive: bool,
    /// Number of leading matches to drop before the limit is applied.
    #[serde(default)]
    pub skip: usize,
    /// Maximum number of hits; defaults to 100 and is capped at 5 000.
    /// `null` requests every hit up to the cap.
    #[serde(default = "default_limit")]
    pub limit: Option<usize>,
    /// Bytes rendered into each hit preview; defaults to 80 and is capped at 512.
    #[serde(default = "default_context")]
    pub context: usize,
}

impl Default for FindOptions {
    fn default() -> Self {
        Self { pattern: String::new(), case_insensitive: false, skip: 0, limit: default_limit(), context: DEFAULT_CONTEXT }
    }
}

/// One regex match with its position and a printable preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindHit {
    /// File offset where the match starts.
    pub offset: u64,
    /// Length of the matched bytes in the file.
    pub length: usize,
    /// Printable rendering of the bytes at the match; non-printable bytes
    /// become dots and the preview is capped at twice the requested context.
    pub preview: String,
}

/// Bounded result of one [`crate::OpenCtf::find`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindReport {
    /// Pattern that was compiled and evaluated.
    pub pattern: String,
    /// Whether the match ran case-insensitively.
    pub case_insensitive: bool,
    /// Number of leading matches that were dropped before the limit.
    pub skip: usize,
    /// Hit limit that was applied.
    pub limit: usize,
    /// Preview length that was applied.
    pub context: usize,
    /// Matches that survived the skip and the limit.
    pub hits: Vec<FindHit>,
    /// Number of matches before the skip and the limit were applied.
    pub total: usize,
    /// Whether the skip or the limit removed matches.
    pub truncated: bool,
}

/// Evaluates `options.pattern` against the whole file and returns the window of
/// matches selected by `skip` and `limit`.
pub fn find(session: &BinarySession, options: &FindOptions) -> Result<FindReport> {
    let bytes = session.read(0, session.size())?;
    let regex = RegexBuilder::new(&options.pattern)
        .case_insensitive(options.case_insensitive)
        .build()
        .map_err(|error| CtfError::parse(format!("invalid pattern: {error}")))?;
    let limit = options.limit.unwrap_or(MAX_LIMIT).min(MAX_LIMIT);
    let context = options.context.min(MAX_CONTEXT);

    let selected = if is_literal(&options.pattern) {
        literal_hits(bytes, &options.pattern, options.case_insensitive, options.skip, limit, context)?
    }
    else {
        None
    };
    let (hits, total, skip) = match selected {
        Some(selected) => selected,
        None => regex_hits(bytes, &regex, options.skip, limit, context),
    };
    let truncated = skip > 0 || total.saturating_sub(skip) > hits.len();

    Ok(FindReport {
        pattern: options.pattern.clone(),
        case_insensitive: options.case_insensitive,
        skip,
        limit,
        context,
        hits,
        total,
        truncated,
    })
}

/// Whether `pattern` is a plain literal the owner's byte scanner can handle.
fn is_literal(pattern: &str) -> bool {
    !pattern.is_empty() && pattern.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-'))
}

/// Scans a plain literal through the shared owner.
///
/// Returns `None` when the owner cannot reproduce the product matcher exactly:
/// overlapping matches, or more matches than the requested window. The caller
/// then falls back to the regex matcher instead of changing the reported totals.
fn literal_hits(
    bytes: &[u8],
    pattern: &str,
    case_insensitive: bool,
    skip: usize,
    limit: usize,
    context: usize,
) -> Result<Option<(Vec<FindHit>, usize, usize)>> {
    let report = inspect_find(
        bytes,
        pattern,
        &InspectFindOptions {
            mode: SearchMode::Ascii,
            case_sensitive: !case_insensitive,
            max_hits: skip.saturating_add(limit),
            max_span: None,
        },
    )?;
    if report.total != report.hits.len() || overlapping(&report.hits) {
        return Ok(None);
    }

    let total = report.total;
    let skipped = skip.min(total);
    let hits = report
        .hits
        .into_iter()
        .skip(skipped)
        .take(limit)
        .map(|hit| {
            let start = hit.offset as usize;
            let end = start.saturating_add(context).min(bytes.len());
            FindHit {
                offset: hit.offset,
                length: hit.length as usize,
                preview: preview(&bytes[start..end], context.saturating_mul(2)),
            }
        })
        .collect();
    Ok(Some((hits, total, skipped)))
}

/// Whether any two adjacent hits overlap, which the literal scan allows but the
/// regex matcher would report once.
fn overlapping(hits: &[data_binary_inspect::find::FindHit]) -> bool {
    hits.windows(2).any(|pair| pair[0].offset + pair[0].length > pair[1].offset)
}

/// Product regex matcher, kept for patterns the literal owner cannot express.
fn regex_hits(bytes: &[u8], regex: &Regex, skip: usize, limit: usize, context: usize) -> (Vec<FindHit>, usize, usize) {
    let mut hits = Vec::new();
    let mut total = 0_usize;
    let mut skipped = 0_usize;
    for matched in regex.find_iter(bytes) {
        total += 1;
        if skipped < skip {
            skipped += 1;
            continue;
        }
        if hits.len() >= limit {
            continue;
        }
        hits.push(hit_of(bytes, &matched, context));
    }
    (hits, total, skipped)
}

/// Renders one regex match with its bounded preview.
fn hit_of(bytes: &[u8], matched: &Match<'_>, context: usize) -> FindHit {
    let start = matched.start();
    let end = start.saturating_add(context).min(bytes.len());
    FindHit {
        offset: start as u64,
        length: matched.end() - start,
        preview: preview(&bytes[start..end], context.saturating_mul(2)),
    }
}

/// Renders `bytes` as printable ASCII, mapping every other byte to a dot, and
/// truncates the rendering to `max_chars` characters.
fn preview(bytes: &[u8], max_chars: usize) -> String {
    bytes
        .iter()
        .map(|&byte| if byte.is_ascii_graphic() || byte == b' ' { char::from(byte) } else { '.' })
        .take(max_chars)
        .collect()
}
