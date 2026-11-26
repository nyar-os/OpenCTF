//! Solve: run the solvers over one byte range and rank their hypotheses.
//!
//! Only the CTF-specific solvers run here. Xor and Caesar scoring, ranking and
//! previews come from `open-ctf-solvers`; this module collects their reports
//! into one candidate set without re-scoring a value.

use open_ctf_solvers::{CaesarOptions, XorOptions};

use crate::{Result, candidates::CandidateSet, challenge::OpenCtf};

/// Inputs of one solve pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolveOptions {
    /// First byte of the ciphertext range.
    pub offset: u64,
    /// Ciphertext length; defaults to the rest of the file.
    pub length: Option<u64>,
    /// Guesses requested per solver.
    pub limit: usize,
}

impl Default for SolveOptions {
    fn default() -> Self {
        Self { offset: 0, length: None, limit: 5 }
    }
}

/// Runs the single-byte XOR and Caesar solvers over one range.
pub fn solve(session: &OpenCtf, options: &SolveOptions) -> Result<CandidateSet> {
    let xor =
        session.xor(&XorOptions { offset: Some(options.offset), length: options.length, key: None, limit: options.limit })?;
    let caesar = session.caesar(&CaesarOptions {
        offset: Some(options.offset),
        length: options.length,
        shift: None,
        limit: options.limit,
    })?;

    let mut candidates = CandidateSet::from_xor(&xor);
    candidates.merge(CandidateSet::from_caesar(&caesar));
    Ok(candidates)
}
