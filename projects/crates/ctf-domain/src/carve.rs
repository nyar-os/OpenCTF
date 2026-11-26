//! Printable-region carving around byte-regex markers.
//!
//! Packers and Electron-style launchers often hide plaintext payloads —
//! injected JavaScript, configuration blobs, scripts — inside an otherwise
//! binary container. `find` locates such a payload but only ever previews a
//! bounded window around the match; this module goes one step further and
//! expands every match to the full printable run that surrounds it, so the
//! whole blob can be listed, previewed and optionally written out for a
//! second tool.
//!
//! Marker selection and region expansion are product policy; plain literal
//! markers are scanned by `data-binary-inspect`'s `find`, and the carved range
//! is sliced through its `dump::window`. The scan stays inside the engine's
//! bounded-report policy: the number of examined matches is capped, duplicates
//! are folded by region start and `truncated` marks a scan the limit stopped
//! early.

use std::{collections::HashSet, path::Path};

use data_binary_inspect::{
    BinarySession, SearchMode,
    dump::window,
    find::{FindHit as InspectFindHit, FindOptions as InspectFindOptions, find as inspect_find},
};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

use crate::{CtfError, Result};

/// Region length used when the caller does not ask for a minimum.
const DEFAULT_MIN_REGION: usize = 200;
/// Right expansion cap used when the caller does not ask for one.
const DEFAULT_MAX_REGION: usize = 262_144;
/// Left expansion cap used when the caller does not ask for one.
const DEFAULT_EXPAND_LEFT: usize = 4_096;
/// Match limit used when the caller does not ask for one.
const DEFAULT_LIMIT: usize = 20;
/// Hard cap on the number of marker matches one carve can examine.
const MAX_LIMIT: usize = 100;
/// Number of bytes rendered into each region preview.
const PREVIEW_BYTES: usize = 120;

/// Marker matches that survived the limit, plus whether more matches exist.
type MarkerSelection = (Vec<(usize, usize)>, bool);

fn default_min_region() -> usize {
    DEFAULT_MIN_REGION
}

fn default_max_region() -> usize {
    DEFAULT_MAX_REGION
}

fn default_expand_left() -> usize {
    DEFAULT_EXPAND_LEFT
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

/// Inputs of one [`crate::OpenCtf::carve`] call.
///
/// Serialized as JSON with camelCase keys, so `{ "marker": "synthetic-blob",
/// "outputDir": "C:\\tmp\\carve" }` is the wire form the addon and the
/// TypeScript client both use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CarveOptions {
    /// Byte regex that marks the regions of interest.
    pub marker: String,
    /// Regions shorter than this many bytes are dropped; defaults to 200.
    #[serde(default = "default_min_region")]
    pub min_region: usize,
    /// Right expansion stops after this many bytes; defaults to 262,144.
    #[serde(default = "default_max_region")]
    pub max_region: usize,
    /// Left expansion stops after this many bytes; defaults to 4,096.
    #[serde(default = "default_expand_left")]
    pub expand_left: usize,
    /// Maximum marker matches to examine; defaults to 20 and is capped at 100.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Directory the carved regions are written to as `carve_<n>.bin`.
    #[serde(default)]
    pub output_dir: Option<String>,
}

impl Default for CarveOptions {
    fn default() -> Self {
        Self {
            marker: String::new(),
            min_region: DEFAULT_MIN_REGION,
            max_region: DEFAULT_MAX_REGION,
            expand_left: DEFAULT_EXPAND_LEFT,
            limit: DEFAULT_LIMIT,
            output_dir: None,
        }
    }
}

/// One printable region anchored on a marker match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CarveRegion {
    /// File offset where the marker match starts.
    pub marker_offset: u64,
    /// File offset where the expanded printable region starts.
    pub region_offset: u64,
    /// Region length in bytes.
    pub region_length: usize,
    /// First [`PREVIEW_BYTES`] printable characters of the region; every other
    /// byte renders as a dot.
    pub preview: String,
    /// Path the region bytes were written to, absent without an output directory.
    pub file: Option<String>,
}

/// Bounded result of one [`crate::OpenCtf::carve`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CarveReport {
    /// Marker regex that was compiled and evaluated.
    pub marker: String,
    /// Minimum region length that was applied.
    pub min_region: usize,
    /// Right expansion cap that was applied.
    pub max_region: usize,
    /// Left expansion cap that was applied.
    pub expand_left: usize,
    /// Match limit that was applied.
    pub limit: usize,
    /// Output directory the regions were written to, when requested.
    pub output_dir: Option<String>,
    /// Regions that survived the length filter and the deduplication.
    pub regions: Vec<CarveRegion>,
    /// Marker matches examined before the limit stopped the scan.
    pub total: usize,
    /// Whether the match limit stopped the scan before the file was exhausted.
    pub truncated: bool,
}

/// Locates every marker match and extracts its printable neighbourhood.
pub fn carve(session: &BinarySession, options: &CarveOptions) -> Result<CarveReport> {
    let bytes = session.read(0, session.size())?;
    let regex = Regex::new(&options.marker).map_err(|error| CtfError::parse(format!("invalid marker: {error}")))?;
    let limit = options.limit.min(MAX_LIMIT);
    let (matches, truncated) = marker_matches(bytes, &regex, &options.marker, limit)?;
    let total = matches.len();

    let mut regions: Vec<CarveRegion> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();
    for (marker_start, marker_end) in matches {
        let floor = marker_start.saturating_sub(options.expand_left);
        let mut start = marker_start;
        while start > floor && start > 0 && printable(bytes[start - 1]) {
            start -= 1;
        }
        let cap = (marker_end + options.max_region).min(bytes.len());
        let mut end = marker_end;
        while end < cap && printable(bytes[end]) {
            end += 1;
        }
        if end - start < options.min_region || !seen.insert(start) {
            continue;
        }

        let region = window(bytes, start as u64, Some((end - start) as u64))?;
        let file = match &options.output_dir {
            Some(dir) => {
                std::fs::create_dir_all(Path::new(dir))?;
                let path = Path::new(dir).join(format!("carve_{}.bin", regions.len()));
                std::fs::write(&path, region)?;
                Some(path.display().to_string())
            }
            None => None,
        };
        regions.push(CarveRegion {
            marker_offset: marker_start as u64,
            region_offset: start as u64,
            region_length: region.len(),
            preview: preview(region),
            file,
        });
    }

    Ok(CarveReport {
        marker: options.marker.clone(),
        min_region: options.min_region,
        max_region: options.max_region,
        expand_left: options.expand_left,
        limit,
        output_dir: options.output_dir.clone(),
        total,
        regions,
        truncated,
    })
}

/// Selects the marker matches the scan may examine.
///
/// A plain literal is scanned by the shared owner. The owner reports every
/// overlapping match, while the product regex matcher reports one match per
/// position, so an overlap falls back to the regex matcher instead of changing
/// the reported totals.
fn marker_matches(bytes: &[u8], regex: &Regex, marker: &str, limit: usize) -> Result<MarkerSelection> {
    if is_literal(marker)
        && let Some(matches) = literal_marker_matches(bytes, marker, limit)?
    {
        return Ok(matches);
    }

    let mut matches = Vec::new();
    for matched in regex.find_iter(bytes) {
        if matches.len() >= limit {
            return Ok((matches, true));
        }
        matches.push((matched.start(), matched.end()));
    }
    Ok((matches, false))
}

/// Scans a plain literal marker through the shared owner.
fn literal_marker_matches(bytes: &[u8], marker: &str, limit: usize) -> Result<Option<MarkerSelection>> {
    let report = inspect_find(
        bytes,
        marker,
        &InspectFindOptions { mode: SearchMode::Ascii, case_sensitive: true, max_hits: limit, max_span: None },
    )?;
    if overlapping(&report.hits) {
        return Ok(None);
    }
    let truncated = report.total > report.hits.len();
    Ok(Some((
        report.hits.into_iter().map(|hit| (hit.offset as usize, (hit.offset + hit.length) as usize)).collect(),
        truncated,
    )))
}

/// Whether `marker` is a plain literal the owner's byte scanner can handle.
fn is_literal(pattern: &str) -> bool {
    !pattern.is_empty() && pattern.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-'))
}

/// Whether any two adjacent hits overlap.
fn overlapping(hits: &[InspectFindHit]) -> bool {
    hits.windows(2).any(|pair| pair[0].offset + pair[0].length > pair[1].offset)
}

/// Printable bytes: printable ASCII plus the three common control bytes.
fn printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte) || matches!(byte, b'\t' | b'\n' | b'\r')
}

/// Renders the first [`PREVIEW_BYTES`] bytes as ASCII, mapping every other
/// byte to a dot so a region never breaks the report layout.
fn preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| if byte.is_ascii_graphic() || byte == b' ' { char::from(byte) } else { '.' })
        .take(PREVIEW_BYTES)
        .collect()
}
