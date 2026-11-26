//! CTF solver algorithms.
//!
//! Caesar rotations, single-byte XOR cracking, de Bruijn cyclic patterns, text
//! and byte decoders, digests, JWT decoding and URL decomposition. Everything
//! here operates on bytes already read from an open session, or on a string, so
//! the algorithms stay independent from the challenge model and the report
//! assembly in `open-ctf-domain`.
//!
//! The stable failure type is the upstream inspection error re-exported as
//! [`CtfError`]; a solver failure therefore keeps the same wire code as the
//! format owner instead of growing a second convention.

pub mod caesar;
pub mod cyclic;
pub mod decode;
pub mod hash;
pub mod jwt;
pub mod url;
pub mod xor;

pub use caesar::{CaesarCandidate, CaesarOptions, CaesarReport};
pub use cyclic::{CyclicOptions, CyclicReport};
pub use decode::{DecodeCodec, DecodeOptions, DecodeReport, DecodeStep};
pub use hash::{HashAlgorithm, HashOptions, HashReport};
pub use jwt::JwtReport;
pub use url::{UrlParam, UrlReport};
pub use xor::{XorKeyGuess, XorOptions, XorReport};

/// Generates a de Bruijn cyclic pattern and optionally locates a value.
pub use cyclic::run as cyclic;
/// Decodes one compact JWT without verifying its signature.
pub use jwt::decode as decode_jwt;
/// Decomposes one URL string without making a request.
pub use url::parse as parse_url;

pub use data_binary_inspect::{InspectError as CtfError, Result};
