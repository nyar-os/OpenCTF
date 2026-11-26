//! URL decomposition for web challenges.
//!
//! A URL is split into scheme, authority, path, query and fragment without a
//! network lookup. Query names and values are percent-decoded so an encoded
//! flag or redirect target is readable, and the report warns about embedded
//! credentials and scriptable schemes.

use serde::{Deserialize, Serialize};

use crate::{CtfError, Result, decode::percent_decode};

/// One decoded query parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlParam {
    /// Raw parameter name.
    pub name: String,
    /// Raw parameter value.
    pub value: String,
    /// Percent-decoded name.
    pub decoded_name: String,
    /// Percent-decoded value.
    pub decoded_value: String,
}

/// Result of one URL decomposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlReport {
    /// Lowercase scheme when one is present.
    pub scheme: Option<String>,
    /// User name from the authority.
    pub username: Option<String>,
    /// Password from the authority.
    pub password: Option<String>,
    /// Host name, or the bracketed IPv6 literal without brackets.
    pub host: Option<String>,
    /// Explicit port.
    pub port: Option<u16>,
    /// Path with its leading slash removed.
    pub path: String,
    /// Raw query string.
    pub query: Option<String>,
    /// Decoded query parameters in order.
    pub params: Vec<UrlParam>,
    /// Raw fragment.
    pub fragment: Option<String>,
    /// Percent-decoded form of the whole URL.
    pub decoded: String,
    /// Observations that matter during a challenge.
    pub warnings: Vec<String>,
}

/// Decomposes one URL string; no request is made.
pub fn parse(input: &str) -> Result<UrlReport> {
    let input = input.trim();
    if input.is_empty() {
        return Err(CtfError::parse("the URL is empty"));
    }
    let (rest, fragment) = match input.split_once('#') {
        Some((rest, fragment)) => (rest, Some(fragment.to_string())),
        None => (input, None),
    };
    let (rest, query) = match rest.split_once('?') {
        Some((rest, query)) => (rest, Some(query.to_string())),
        None => (rest, None),
    };
    let (scheme, authority, path) = split_scheme(rest);
    let (username, password, host, port, port_warning) = authority.map_or((None, None, None, None, false), split_authority);

    let mut warnings = Vec::new();
    if password.is_some() {
        warnings.push("the URL embeds credentials in its authority".to_string());
    }
    if port_warning {
        warnings.push("the port in the authority is not a valid u16".to_string());
    }
    if let Some(scheme) = &scheme
        && matches!(scheme.as_str(), "javascript" | "data" | "vbscript")
    {
        warnings.push(format!("the URL uses the scriptable `{scheme}` scheme"));
    }

    let params = query.as_deref().map(parse_query).unwrap_or_default();
    let decoded = percent_decode(input).map_or_else(|| input.to_string(), |bytes| String::from_utf8_lossy(&bytes).into_owned());

    Ok(UrlReport { scheme, username, password, host, port, path, query, params, fragment, decoded, warnings })
}

/// Splits the scheme, authority and path out of the pre-query remainder.
fn split_scheme(rest: &str) -> (Option<String>, Option<&str>, String) {
    if let Some((scheme, after)) = rest.split_once("://") {
        let (authority, path) = split_authority_path(after);
        return (Some(scheme.to_ascii_lowercase()), authority, path);
    }
    if let Some((scheme, after)) = rest.split_once(':') {
        let valid = !scheme.is_empty() && scheme.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'));
        if valid && !after.starts_with("//") {
            return (Some(scheme.to_ascii_lowercase()), None, after.to_string());
        }
    }
    if let Some(after) = rest.strip_prefix("//") {
        let (authority, path) = split_authority_path(after);
        return (None, authority, path);
    }
    (None, None, rest.to_string())
}

fn split_authority_path(after: &str) -> (Option<&str>, String) {
    match after.split_once('/') {
        Some((authority, path)) => (Some(authority), path.to_string()),
        None => (Some(after), String::new()),
    }
}

fn split_authority(authority: &str) -> (Option<String>, Option<String>, Option<String>, Option<u16>, bool) {
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => (Some(userinfo), hostport),
        None => (None, authority),
    };
    let (username, password) = match userinfo {
        Some(userinfo) => match userinfo.split_once(':') {
            Some((name, password)) => (Some(name.to_string()), Some(password.to_string())),
            None => (Some(userinfo.to_string()), None),
        },
        None => (None, None),
    };
    let (host, port_text) = if let Some(stripped) = hostport.strip_prefix('[')
        && let Some((host, tail)) = stripped.split_once(']')
    {
        (host.to_string(), tail.strip_prefix(':'))
    }
    else {
        match hostport.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
                (host.to_string(), Some(port))
            }
            _ => (hostport.to_string(), None),
        }
    };
    let (port, invalid) = match port_text {
        Some(port) => match port.parse::<u16>() {
            Ok(port) => (Some(port), false),
            Err(_) => (None, true),
        },
        None => (None, false),
    };
    let host = if host.is_empty() { None } else { Some(host) };
    (username, password, host, port, invalid)
}

fn parse_query(query: &str) -> Vec<UrlParam> {
    let mut params = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        params.push(UrlParam {
            name: name.to_string(),
            value: value.to_string(),
            decoded_name: decode_part(name),
            decoded_value: decode_part(value),
        });
    }
    params
}

fn decode_part(text: &str) -> String {
    percent_decode(text).map_or_else(|| text.to_string(), |bytes| String::from_utf8_lossy(&bytes).into_owned())
}
