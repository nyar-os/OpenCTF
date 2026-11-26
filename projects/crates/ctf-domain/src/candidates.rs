//! Ranked candidate values produced by the solvers.
//!
//! A solver returns its own report; this module turns those reports into one
//! deduplicated, ranked list so the report can present a single "what to try
//! next" surface. Nothing here re-scores a value: the score and the label come
//! from the solver that produced it.

use open_ctf_solvers::{CaesarReport, XorReport};
use serde::{Deserialize, Serialize};

/// One ranked hypothesis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    /// Solver that produced it, such as `xor` or `caesar`.
    pub source: String,
    /// Short label, such as `key 0x42` or `shift 13`.
    pub label: String,
    /// Plaintext or decoded preview.
    pub value: String,
    /// Solver score; higher ranks first.
    pub score: f64,
}

/// Deduplicated and ranked candidate list.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateSet {
    /// Candidates in the order they were produced.
    pub items: Vec<Candidate>,
}

impl CandidateSet {
    /// Builds an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one candidate.
    pub fn push(&mut self, candidate: Candidate) {
        self.items.push(candidate);
    }

    /// Collects the ranked key guesses of one single-byte XOR crack.
    pub fn from_xor(report: &XorReport) -> Self {
        let items = report
            .guesses
            .iter()
            .map(|guess| Candidate {
                source: "xor".to_string(),
                label: format!("key {}", guess.key_hex),
                value: guess.preview.clone(),
                score: guess.score,
            })
            .collect();
        Self { items }
    }

    /// Collects the ranked shifts of one Caesar crack.
    pub fn from_caesar(report: &CaesarReport) -> Self {
        let items = report
            .candidates
            .iter()
            .map(|candidate| Candidate {
                source: "caesar".to_string(),
                label: format!("shift {}", candidate.shift),
                value: candidate.preview.clone(),
                score: candidate.score,
            })
            .collect();
        Self { items }
    }

    /// Appends every candidate of `other`.
    pub fn merge(&mut self, other: Self) {
        self.items.extend(other.items);
    }

    /// Number of candidates before deduplication.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether no candidate was produced.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Deduplicates by value, keeps the best score and sorts best first.
    ///
    /// Two solvers can produce the same plaintext; the value is the unit a
    /// challenge cares about, so the duplicate with the lower score is dropped
    /// instead of listing the same guess twice.
    pub fn ranked(&self) -> Vec<Candidate> {
        let mut ranked: Vec<Candidate> = Vec::with_capacity(self.items.len());
        for candidate in &self.items {
            match ranked.iter_mut().find(|kept| kept.value == candidate.value) {
                Some(kept) if candidate.score > kept.score => *kept = candidate.clone(),
                Some(_) => {}
                None => ranked.push(candidate.clone()),
            }
        }
        ranked.sort_by(|left, right| right.score.total_cmp(&left.score).then_with(|| left.value.cmp(&right.value)));
        ranked
    }

    /// The best candidate, if any.
    pub fn best(&self) -> Option<Candidate> {
        self.ranked().into_iter().next()
    }
}
