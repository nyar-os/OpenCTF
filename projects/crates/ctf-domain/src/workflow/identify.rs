//! Identify: open one artifact and record what the container is.
//!
//! Identification never interprets payload bytes. It reads the header through
//! the shared inspection engine, runs the container probe, and records both as
//! evidence so a later triage can tell a detected container from an embedded
//! one.

use std::path::PathBuf;

use open_ctf_formats::ProbeOptions;

use crate::{
    Evidence, Result,
    challenge::{Challenge, OpenCtf, OpenCtfOptions},
    report::ChallengeReport,
};

/// Inputs of one identification pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifyOptions {
    /// Artifact to open.
    pub path: PathBuf,
    /// Maximum number of probe findings recorded.
    pub probe_limit: usize,
}

impl IdentifyOptions {
    /// Builds options for one path with the product default probe bound.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), probe_limit: 8 }
    }
}

/// Opens one artifact and records its container facts plus probe candidates.
pub fn identify(options: &IdentifyOptions) -> Result<ChallengeReport> {
    let session = OpenCtf::new(OpenCtfOptions::new(&options.path))?;
    let challenge = Challenge::of(&session)?;
    let mut evidence = vec![
        Evidence::fact("info", format!("container `{}` on `{}`", challenge.format, challenge.architecture)),
        Evidence::fact("info", format!("{} bytes", challenge.size)),
    ];

    match session.probe(&ProbeOptions { limit: options.probe_limit, ..ProbeOptions::default() }) {
        Ok(report) => {
            for finding in &report.findings {
                evidence.push(
                    Evidence::candidate("probe", format!("{} ({}, {})", finding.format, finding.confidence, finding.reason))
                        .at(finding.offset),
                );
            }
            if report.findings.is_empty() {
                evidence.push(Evidence::inference("probe", "no embedded container signature matched"));
            }
        }
        Err(error) => evidence.push(Evidence::unsupported("probe", error.message().to_string())),
    }

    Ok(ChallengeReport::new(challenge).with_evidence_all(evidence))
}
