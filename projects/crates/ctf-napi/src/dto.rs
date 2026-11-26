//! Private Node-API request and response shapes for ranked candidates.
//!
//! The domain model uses natural `snake_case` Rust field names. This module is
//! the only place where the JavaScript wire spelling lives: the request is
//! deserialized from the caller's `camelCase` object and every domain candidate
//! is mapped onto an explicit item with its own source enum. Nothing here is
//! exported as a JavaScript symbol or re-exported by the SDK; the module is
//! public only so the contract tests in `tests/` can exercise both the success
//! and the rejection paths without an open file handle.

use open_ctf_domain::{Candidate as DomainCandidate, CandidateSet, CtfError, SolveOptions};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

/// Default number of guesses requested per solver.
const DEFAULT_LIMIT: usize = 5;

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

/// Solver that produced one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CandidateSource {
    /// Single-byte XOR key guess.
    Xor,
    /// Caesar shift guess.
    Caesar,
}

/// Inputs of one candidate request, as the JavaScript caller writes them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CandidateRequest {
    /// First byte of the ciphertext range.
    pub offset: u64,
    /// Ciphertext length; `null` or absent means the rest of the file.
    pub length: Option<u64>,
    /// Guesses requested per solver.
    #[serde(default = "default_limit")]
    pub limit: usize,
}

impl Default for CandidateRequest {
    fn default() -> Self {
        Self { offset: 0, length: None, limit: DEFAULT_LIMIT }
    }
}

impl CandidateRequest {
    /// Parses the options object the Node-API parameter carries.
    pub fn parse(raw: &str) -> Result<Self, CtfError> {
        serde_json::from_str(raw).map_err(|error| CtfError::parse(format!("invalid CandidateRequest: {error}")))
    }

    /// Maps this request onto the product solve options.
    pub fn solve_options(&self) -> SolveOptions {
        SolveOptions { offset: self.offset, length: self.length, limit: self.limit }
    }
}

/// One candidate in the Node-API response.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateItem {
    /// Solver that produced the candidate.
    pub source: CandidateSource,
    /// Short label, such as `key 0x42` or `shift 13`.
    pub label: String,
    /// Plaintext or decoded preview.
    pub value: String,
    /// Solver score; higher ranks first.
    pub score: f64,
}

impl TryFrom<&DomainCandidate> for CandidateItem {
    type Error = CtfError;

    fn try_from(candidate: &DomainCandidate) -> Result<Self, Self::Error> {
        let source = match candidate.source.as_str() {
            "xor" => CandidateSource::Xor,
            "caesar" => CandidateSource::Caesar,
            other => return Err(CtfError::unsupported(format!("unsupported candidate source `{other}`"))),
        };
        Ok(Self { source, label: candidate.label.clone(), value: candidate.value.clone(), score: candidate.score })
    }
}

/// Candidate response returned by the Node-API surface.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateResponse {
    /// Candidates in the order they were produced.
    pub items: Vec<CandidateItem>,
}

impl CandidateResponse {
    /// Maps one domain candidate set onto the wire response.
    pub fn from_set(set: &CandidateSet) -> Result<Self, CtfError> {
        let items = set.items.iter().map(CandidateItem::try_from).collect::<Result<Vec<_>, _>>()?;
        Ok(Self { items })
    }
}

/// Serializes one product value as the JavaScript wire object.
///
/// Product, format and solver types keep natural Rust `snake_case` field names.
/// This private binding helper is the single place that restores the frozen
/// `camelCase` key spelling at the Node-API boundary. Object keys are rewritten
/// recursively; array elements, numbers, strings and booleans are untouched, so
/// enum values keep their published spelling. Free-form maps (the JWT header and
/// payload are the only ones) bypass this helper and keep their own keys.
pub(crate) fn to_wire<T: Serialize>(value: &T) -> Result<Value, CtfError> {
    let value = serde_json::to_value(value).map_err(|error| CtfError::parse(error.to_string()))?;
    Ok(camelize(value))
}

/// Parses a JavaScript options object into one natural Rust request type.
///
/// The binding rewrites `camelCase` keys to the `snake_case` spelling the
/// product options use. Values, including enum names and paths, are never
/// rewritten.
pub(crate) fn request<T: DeserializeOwned>(raw: &str) -> Result<T, serde_json::Error> {
    let value: Value = serde_json::from_str(raw)?;
    request_value(value)
}

/// Parses one already-decoded JavaScript options object into a Rust request.
pub(crate) fn request_value<T: DeserializeOwned>(value: Value) -> Result<T, serde_json::Error> {
    serde_json::from_value(snakeize(value))
}

fn camelize(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(map.into_iter().map(|(key, value)| (camel_key(&key), camelize(value))).collect()),
        Value::Array(items) => Value::Array(items.into_iter().map(camelize).collect()),
        other => other,
    }
}

fn camel_key(key: &str) -> String {
    let mut output = String::with_capacity(key.len());
    let mut capitalize = false;
    for character in key.chars() {
        if character == '_' {
            capitalize = true;
        }
        else if capitalize {
            output.extend(character.to_uppercase());
            capitalize = false;
        }
        else {
            output.push(character);
        }
    }
    output
}

fn snakeize(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(map.into_iter().map(|(key, value)| (snake_key(&key), snakeize(value))).collect()),
        Value::Array(items) => Value::Array(items.into_iter().map(snakeize).collect()),
        other => other,
    }
}

fn snake_key(key: &str) -> String {
    let mut output = String::with_capacity(key.len() + 4);
    for character in key.chars() {
        if character.is_ascii_uppercase() {
            output.push('_');
            output.push(character.to_ascii_lowercase());
        }
        else {
            output.push(character);
        }
    }
    output
}

