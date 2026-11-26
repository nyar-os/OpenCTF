//! Whole-file, byte-range and multi-algorithm digests.
//!
//! Every digest is computed by `boost.rs/boost-crypto` over bytes already read
//! from the open session; nothing is executed and no external hash tool is
//! invoked. Hex output is lowercase.

use boost_crypto::{
    encoding::hex_encode,
    hash::{md4, md5, sha1, sha224, sha256, sha384, sha512},
};
use data_binary_inspect::BinarySession;
use serde::{Deserialize, Serialize};

use crate::{CtfError, Result};

/// Digest algorithm selected by [`HashOptions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// MD5, 128 bits.
    Md5,
    /// MD4, 128 bits.
    Md4,
    /// SHA-1, 160 bits.
    Sha1,
    /// SHA-224, 224 bits.
    Sha224,
    /// SHA-256, 256 bits.
    #[default]
    Sha256,
    /// SHA-384, 384 bits.
    Sha384,
    /// SHA-512, 512 bits.
    Sha512,
}

impl HashAlgorithm {
    /// Lowercase identifier used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Md4 => "md4",
            Self::Sha1 => "sha1",
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => md5(data).to_vec(),
            Self::Md4 => md4(data).to_vec(),
            Self::Sha1 => sha1(data).to_vec(),
            Self::Sha224 => sha224(data).to_vec(),
            Self::Sha256 => sha256(data).to_vec(),
            Self::Sha384 => sha384(data).to_vec(),
            Self::Sha512 => sha512(data).to_vec(),
        }
    }
}

/// Inputs of one `OpenCtf::hash` call.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HashOptions {
    /// Digest algorithm; defaults to `sha256`.
    #[serde(default)]
    pub algorithm: HashAlgorithm,
    /// First byte to hash; defaults to the file start.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Bytes to hash; defaults to the rest of the file.
    #[serde(default)]
    pub length: Option<u64>,
}

/// Result of one `OpenCtf::hash` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashReport {
    /// Algorithm identifier, lowercase.
    pub algorithm: String,
    /// `file` for the whole file, `range` for an explicit window.
    pub source: String,
    /// First hashed byte when `source` is `range`.
    pub offset: Option<u64>,
    /// Number of hashed bytes.
    pub length: u64,
    /// Lowercase hex digest.
    pub digest: String,
}

/// Hashes the whole file or one byte range with the requested algorithm.
pub fn compute(session: &BinarySession, options: &HashOptions) -> Result<HashReport> {
    let size = session.size();
    let offset = options.offset.unwrap_or(0);
    if offset > size {
        return Err(CtfError::range("the hash offset is past the end of the file"));
    }
    let available = size - offset;
    let length = options.length.unwrap_or(available).min(available);
    let data = session.read(offset, length)?;
    let digest = hex_encode(&options.algorithm.digest(data));
    let whole_file = offset == 0 && length == size;
    Ok(HashReport {
        algorithm: options.algorithm.as_str().to_string(),
        source: if whole_file { "file".to_string() } else { "range".to_string() },
        offset: if whole_file { None } else { Some(offset) },
        length,
        digest,
    })
}
