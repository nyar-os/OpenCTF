//! Evidence recorded while triaging one challenge.
//!
//! The report separates what was read from the container (facts), what a
//! documented heuristic derived (inferences), what still needs verification
//! (candidates) and what this build refuses to decode (unsupported). Callers
//! branch on [`EvidenceKind`], never on the wording of [`Evidence::statement`].

use serde::{Deserialize, Serialize};

/// How much trust one recorded statement carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    /// Read directly from the container or the shared inspection engine.
    Fact,
    /// Derived by a documented heuristic over facts.
    Inference,
    /// One hypothesis that still needs verification.
    Candidate,
    /// Recognised but not decoded by this build.
    Unsupported,
}

/// One recorded statement with the owner that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Trust level of this statement.
    pub kind: EvidenceKind,
    /// Module or owner that produced it, such as `info`, `probe` or `packer`.
    pub source: String,
    /// Human-readable statement.
    pub statement: String,
    /// File offset the statement refers to, when it has one.
    pub offset: Option<u64>,
}

impl Evidence {
    fn new(kind: EvidenceKind, source: &str, statement: impl Into<String>) -> Self {
        Self { kind, source: source.to_string(), statement: statement.into(), offset: None }
    }

    /// Records a fact read from the container.
    pub fn fact(source: &str, statement: impl Into<String>) -> Self {
        Self::new(EvidenceKind::Fact, source, statement)
    }

    /// Records an inference made by a documented heuristic.
    pub fn inference(source: &str, statement: impl Into<String>) -> Self {
        Self::new(EvidenceKind::Inference, source, statement)
    }

    /// Records a hypothesis that still needs verification.
    pub fn candidate(source: &str, statement: impl Into<String>) -> Self {
        Self::new(EvidenceKind::Candidate, source, statement)
    }

    /// Records a recognised but undecoded capability.
    pub fn unsupported(source: &str, statement: impl Into<String>) -> Self {
        Self::new(EvidenceKind::Unsupported, source, statement)
    }

    /// Attaches the file offset this statement refers to.
    pub fn at(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }
}
