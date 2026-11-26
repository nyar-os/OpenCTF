//! JSON Web Token decoding.
//!
//! The header and payload are base64url-decoded and parsed as JSON; the
//! signature is only measured and hex-rendered. No signature is verified
//! because a verification key would be required, so the report says so
//! explicitly instead of implying authenticity.

use boost_crypto::encoding::{base64url_decode, hex_encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{CtfError, Result};

/// Decoded contents of one JWT.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtReport {
    /// Decoded header object.
    pub header: Value,
    /// Decoded payload object.
    pub payload: Value,
    /// `alg` declared by the header, or an empty string when absent.
    pub algorithm: String,
    /// Whether the token carries no usable signature.
    pub unsigned: bool,
    /// Signature bytes as lowercase hex; empty when unsigned or undecodable.
    pub signature_hex: String,
    /// Observations that matter for an attack, such as `alg=none`.
    pub warnings: Vec<String>,
}

/// Decodes one compact JWT without verifying its signature.
pub fn decode(token: &str) -> Result<JwtReport> {
    let token = token.trim();
    let token = token.strip_prefix("Bearer ").unwrap_or(token).trim();
    if token.is_empty() {
        return Err(CtfError::parse("the JWT is empty"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return Err(CtfError::parse("a JWT must have two or three dot-separated segments"));
    }
    let header = decode_segment(parts[0], "header")?;
    let payload = decode_segment(parts[1], "payload")?;
    let signature = parts.get(2).copied().unwrap_or("");
    let algorithm = header.get("alg").and_then(Value::as_str).unwrap_or("").to_string();
    let mut warnings = Vec::new();
    if algorithm.eq_ignore_ascii_case("none") {
        warnings.push("the header declares alg=none: the token is not signed".to_string());
    }
    else if algorithm.to_ascii_uppercase().starts_with("HS") {
        warnings.push("an HMAC token can be attacked offline when the secret is weak".to_string());
    }
    if parts.len() == 2 {
        warnings.push("the token has no signature segment".to_string());
    }
    let signature_bytes = if signature.is_empty() {
        Vec::new()
    }
    else {
        match base64url_decode(signature) {
            Ok(bytes) => bytes,
            Err(_) => {
                warnings.push("the signature segment is not valid base64url".to_string());
                Vec::new()
            }
        }
    };
    let unsigned = algorithm.eq_ignore_ascii_case("none") || parts.len() == 2 || signature_bytes.is_empty();
    Ok(JwtReport { header, payload, algorithm, unsigned, signature_hex: hex_encode(&signature_bytes), warnings })
}

fn decode_segment(segment: &str, label: &str) -> Result<Value> {
    let bytes = base64url_decode(segment).map_err(|_| CtfError::parse(format!("the JWT {label} is not valid base64url")))?;
    serde_json::from_slice(&bytes).map_err(|error| CtfError::parse(format!("the JWT {label} is not valid JSON: {error}")))
}
