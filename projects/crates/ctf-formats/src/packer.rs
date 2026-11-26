//! Static packer identification.
//!
//! Section names and known ASCII markers are compared against a small table of
//! common protectors. A section-name hit is stronger than a marker hit, and the
//! report never claims that a file is unpacked when nothing matched.

use data_binary_inspect::BinarySession;
use serde::{Deserialize, Serialize};

use crate::Result;

/// Bytes searched for ASCII packer markers.
const SCAN_LIMIT: u64 = 2 * 1024 * 1024;

/// Known markers: packer id and the ASCII bytes it leaves in the image.
const MARKERS: &[(&str, &[u8])] = &[
    ("upx", b"UPX!"),
    ("mpress", b".MPRESS1"),
    ("mpress", b"MPRESS1"),
    ("aspack", b".aspack"),
    ("aspack", b"ASPack"),
    ("themida", b".themida"),
    ("themida", b"WinLicense"),
    ("vmprotect", b".vmp0"),
    ("vmprotect", b"VMProtect"),
    ("enigma", b".enigma"),
    ("petite", b".petite"),
    ("nspack", b".nsp0"),
    ("pecompact", b".pec1"),
    ("fsg", b".FSG!"),
    ("telock", b".tElock"),
    ("perplex", b".perplex"),
];

/// Inputs of one `OpenCtf::packer` call.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PackerOptions {}

/// One packer hypothesis with its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackerMatch {
    /// Packer or protector family.
    pub packer: String,
    /// `identified` for a section-name hit, `candidate` for a marker hit.
    pub confidence: String,
    /// Why this family matched.
    pub evidence: String,
    /// File offset of a marker hit, absent for section-name hits.
    pub offset: Option<u64>,
}

/// Result of one packer identification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackerReport {
    /// Whether any packer signature matched.
    pub packed: bool,
    /// Matches ordered by confidence and name.
    pub matches: Vec<PackerMatch>,
    /// Next steps and negative-evidence notes.
    pub hints: Vec<String>,
}

/// Identifies common packers from section names and image markers.
pub fn analyze(session: &BinarySession, _options: &PackerOptions) -> Result<PackerReport> {
    let mut matches: Vec<PackerMatch> = Vec::new();

    if let Ok(sections) = session.sections() {
        for section in &sections {
            if let Some(packer) = section_packer(&section.name) {
                let evidence = format!("section name `{}`", section.name);
                if !matches.iter().any(|hit| hit.packer == packer) {
                    matches.push(PackerMatch {
                        packer: packer.to_string(),
                        confidence: "identified".to_string(),
                        evidence,
                        offset: None,
                    });
                }
            }
        }
    }

    let size = session.size();
    if size > 0 {
        let head = session.read(0, size.min(SCAN_LIMIT))?;
        for (packer, marker) in MARKERS {
            if matches.iter().any(|hit| hit.packer == *packer) {
                continue;
            }
            if let Some(offset) = find_bytes(head, marker) {
                matches.push(PackerMatch {
                    packer: (*packer).to_string(),
                    confidence: "candidate".to_string(),
                    evidence: format!("marker `{}`", String::from_utf8_lossy(marker)),
                    offset: Some(offset as u64),
                });
            }
        }
    }

    matches.sort_by(|left, right| left.packer.cmp(&right.packer));
    let packed = !matches.is_empty();
    let hints = if packed {
        vec!["dump or statically unpack the mapped image before disassembly and mitigation checks".to_string()]
    }
    else {
        vec!["no known packer signature matched; this does not prove the file is unpacked".to_string()]
    };
    Ok(PackerReport { packed, matches, hints })
}

fn section_packer(name: &str) -> Option<&'static str> {
    let name = name.trim_start_matches('.');
    let upper = name.to_ascii_uppercase();
    match upper.as_str() {
        "UPX0" | "UPX1" | "UPX2" | "UPX3" => Some("upx"),
        "ASPACK" | "ADATA" => Some("aspack"),
        "MPRESS1" | "MPRESS2" => Some("mpress"),
        "THEMIDA" | "WINLICE" => Some("themida"),
        "VMP0" | "VMP1" | "VMP2" => Some("vmprotect"),
        "ENIGMA" | "ENIGMA1" | "ENIGMA2" => Some("enigma"),
        "PETITE" => Some("petite"),
        "NSP0" | "NSP1" | "NSP2" => Some("nspack"),
        "PEC1" | "PEC2" | "PEC" => Some("pecompact"),
        "FSG!" => Some("fsg"),
        "TELOCK" => Some("telock"),
        "PERPLEX" => Some("perplex"),
        _ => None,
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&index| &haystack[index..index + needle.len()] == needle)
}
