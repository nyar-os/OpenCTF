//! Stable failure surface of the OpenCTF product.
//!
//! Every public operation returns [`Result`], and every failure carries a code
//! that callers can compare instead of parsing prose. The code stays the same
//! when the message is reworded or translated.
//!
//! The format and solver crates surface the upstream inspection error; it is
//! converted losslessly here, so `binary/parse`, `binary/range`,
//! `binary/unsupported` and `binary/io` keep one wire meaning across the
//! product. Product-only codes such as `handle/invalid` are constructed with
//! [`CtfError::new`] and are documented in `documentation/architecture.md`.

use std::fmt;

/// Result of one product operation.
pub type Result<T> = std::result::Result<T, CtfError>;

/// Stable failure with a comparable code and a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtfError {
    code: &'static str,
    message: String,
}

impl CtfError {
    /// Builds a failure from a stable code and a message.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    /// A recognised container could not be decoded.
    pub fn parse(message: impl Into<String>) -> Self {
        Self::new("binary/parse", message)
    }

    /// An offset, length or handle falls outside what the file provides.
    pub fn range(message: impl Into<String>) -> Self {
        Self::new("binary/range", message)
    }

    /// The file or feature is not supported by this build.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new("binary/unsupported", message)
    }

    /// The file could not be read or written.
    pub fn io(message: impl Into<String>) -> Self {
        Self::new("binary/io", message)
    }

    /// The stable code, such as `binary/parse`.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The human-readable message without the code prefix.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CtfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CtfError {}

impl From<data_binary_inspect::InspectError> for CtfError {
    fn from(error: data_binary_inspect::InspectError) -> Self {
        Self::new(error.code(), error.message().to_string())
    }
}

impl From<std::io::Error> for CtfError {
    fn from(error: std::io::Error) -> Self {
        Self::io(error.to_string())
    }
}
