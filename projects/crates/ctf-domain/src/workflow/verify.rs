//! Verify: check candidates against one explicit rule.
//!
//! Verification is a local match, never a claim. A candidate that satisfies the
//! rule is reported as matched with the rule that accepted it; a candidate that
//! does not is still returned so the caller can see that the whole set was
//! checked.

use serde::{Deserialize, Serialize};

use crate::{Candidate, CtfError, Result, candidates::CandidateSet};

/// One explicit verification rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyRule {
    /// Regular expression a candidate value must match.
    pub pattern: String,
}

impl VerifyRule {
    /// Builds a rule from one regular expression.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self { pattern: pattern.into() }
    }

    /// The usual `flag{...}` rule, case-insensitive.
    pub fn flag() -> Self {
        Self::new(r"(?i)flag\{[^}]*\}")
    }
}

/// One verified candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    /// The candidate that was checked.
    pub candidate: Candidate,
    /// Whether the rule matched its value.
    pub matched: bool,
}

/// Checks every ranked candidate against `rule`.
pub fn verify(candidates: &CandidateSet, rule: &VerifyRule) -> Result<Vec<Verdict>> {
    let pattern =
        regex::Regex::new(&rule.pattern).map_err(|error| CtfError::parse(format!("invalid verification pattern: {error}")))?;
    Ok(candidates
        .ranked()
        .into_iter()
        .map(|candidate| Verdict { matched: pattern.is_match(&candidate.value), candidate })
        .collect())
}

/// Returns the best candidate that satisfies `rule`.
pub fn first_match(candidates: &CandidateSet, rule: &VerifyRule) -> Result<Option<Candidate>> {
    Ok(verify(candidates, rule)?.into_iter().find(|verdict| verdict.matched).map(|verdict| verdict.candidate))
}
