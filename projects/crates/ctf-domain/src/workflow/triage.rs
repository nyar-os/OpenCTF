//! Triage: bounded observations that decide what to try next.
//!
//! Triage reads the section table, the entropy summary, a bounded string
//! sample and the packer signatures. Each observation is recorded as evidence
//! with its owner, so the report keeps "the container says" apart from "this
//! heuristic suggests".

use open_ctf_formats::{PackerOptions, PackerReport};

use crate::{Evidence, Result, challenge::OpenCtf};

/// Bounds of one triage pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageOptions {
    /// Minimum printable run length used by the string sample.
    pub min_string_len: usize,
    /// Number of string hits requested from the shared engine.
    pub max_strings: usize,
    /// Number of string hits scanned for a flag-like prefix.
    pub flag_scan: usize,
}

impl Default for TriageOptions {
    fn default() -> Self {
        Self { min_string_len: 4, max_strings: 64, flag_scan: 64 }
    }
}

/// Records the bounded triage observations of one open session.
pub fn triage(session: &OpenCtf, options: &TriageOptions) -> Result<Vec<Evidence>> {
    let mut evidence = Vec::new();

    match session.sections() {
        Ok(sections) => evidence.push(Evidence::fact("info", format!("{} section(s)", sections.len()))),
        Err(error) => evidence.push(Evidence::unsupported("info", error.message().to_string())),
    }

    let entropy = session.entropy()?;
    evidence.push(Evidence::inference("entropy", format!("whole-file entropy {:.4} bits/byte", entropy.file_entropy)));
    if let Some(section) = entropy.sections.iter().max_by(|left, right| left.entropy.total_cmp(&right.entropy)) {
        evidence.push(
            Evidence::inference(
                "entropy",
                format!("section `{}` carries the highest entropy ({:.4})", section.name, section.entropy),
            )
            .at(section.offset),
        );
    }

    let strings = session.strings(Some(options.min_string_len), Some(options.max_strings));
    evidence
        .push(Evidence::fact("strings", format!("{} printable run(s) shown of {} total", strings.hits.len(), strings.total)));
    for hit in strings.hits.iter().take(options.flag_scan) {
        if hit.value.contains("flag{") {
            evidence.push(Evidence::candidate("strings", format!("flag-like run `{}`", hit.value)).at(hit.offset));
        }
    }

    let packer = session.packer(&PackerOptions::default()).unwrap_or_else(|_| PackerReport {
        packed: false,
        matches: Vec::new(),
        hints: vec!["packer identification is unavailable for this container".to_string()],
    });
    for hit in &packer.matches {
        evidence.push(Evidence::candidate("packer", format!("{} {}: {}", hit.packer, hit.confidence, hit.evidence)));
    }

    Ok(evidence)
}
