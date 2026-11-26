//! `x86` / `x64` disassembly over the opened bytes.
//!
//! The instruction stream is decoded by `boost.rs/data-binary-x64` behind its
//! `decode` feature; this module keeps the CTF projection: the PE virtual
//! address mapping, the count cap, the syntax switch and the stop-on-invalid
//! rule. Addresses use the `PE` virtual address when one is available and fall
//! back to the file offset for other containers. Other architectures are
//! reported as unsupported instead of being guessed.

use boost_crypto::encoding::hex_encode;
use data_binary_inspect::{Architecture, BinaryFormat, BinarySession};
use data_binary_x64::decode::{Decoder, Syntax};
use serde::{Deserialize, Serialize};

use crate::{CtfError, Result};

/// Instructions returned when the caller does not ask for a count.
const DEFAULT_COUNT: usize = 64;
/// Hard cap on the number of decoded instructions.
const MAX_COUNT: usize = 4096;

/// Assembly syntax of the rendered instruction text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DisassemblySyntax {
    /// Intel (XED) syntax, the default.
    #[default]
    Intel,
    /// Microsoft assembler syntax.
    Masm,
    /// Netwide assembler syntax.
    Nasm,
}

impl DisassemblySyntax {
    /// Stable lower-case name used in reports and on the command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intel => "intel",
            Self::Masm => "masm",
            Self::Nasm => "nasm",
        }
    }

    /// Syntax selector understood by the pinned decoder.
    fn owner(self) -> Syntax {
        match self {
            Self::Intel => Syntax::Intel,
            Self::Masm => Syntax::Masm,
            Self::Nasm => Syntax::Nasm,
        }
    }
}

fn default_count() -> usize {
    DEFAULT_COUNT
}

/// Inputs of one `OpenCtf::disasm` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisassembleOptions {
    /// File offset to start decoding from.
    #[serde(default)]
    pub offset: u64,
    /// Maximum number of instructions to decode; capped at 4096.
    #[serde(default = "default_count")]
    pub count: usize,
    /// Assembly syntax of the rendered text.
    #[serde(default)]
    pub syntax: DisassemblySyntax,
}

impl Default for DisassembleOptions {
    fn default() -> Self {
        Self { offset: 0, count: default_count(), syntax: DisassemblySyntax::default() }
    }
}

impl DisassembleOptions {
    /// Builds options that start at `offset` with the documented defaults.
    pub fn new(offset: u64) -> Self {
        Self { offset, count: default_count(), syntax: DisassemblySyntax::Intel }
    }
}

/// One decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisassemblyInstruction {
    /// Absolute address: the `PE` virtual address when available, otherwise the file offset.
    pub address: u64,
    /// File offset of the first byte.
    pub offset: u64,
    /// Encoded length in bytes.
    pub length: u32,
    /// Encoded bytes as lower-case hex.
    pub bytes: String,
    /// Rendered instruction text.
    pub text: String,
}

/// Result of one disassembly request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisassemblyReport {
    /// `x86` or `x64`.
    pub architecture: String,
    /// Decoder bitness: 32 or 64.
    pub bitness: u32,
    /// File offset decoding started from.
    pub start_offset: u64,
    /// Address assigned to the first decoded instruction.
    pub start_address: u64,
    /// Assembly syntax that was used.
    pub syntax: String,
    /// Decoded instructions.
    pub instructions: Vec<DisassemblyInstruction>,
    /// Whether the count limit stopped decoding before the bytes ran out.
    pub truncated: bool,
}

/// Disassembles one open session.
pub fn analyze(session: &BinarySession, options: &DisassembleOptions) -> Result<DisassemblyReport> {
    let architecture = session.architecture();
    let bitness = match architecture {
        Architecture::X86 => 32,
        Architecture::X64 => 64,
        other => {
            return Err(CtfError::unsupported(format!(
                "disassembly is only available for x86 and x64 images; detected {}",
                other.as_str()
            )));
        }
    };

    let size = session.size();
    if options.offset > size {
        return Err(CtfError::range(format!("offset 0x{:x} is past the end of the file", options.offset)));
    }
    let bytes = session.read(options.offset, size - options.offset)?;
    let start_address = if session.format() == BinaryFormat::Pe {
        session.offset_to_va(options.offset).unwrap_or(options.offset)
    }
    else {
        options.offset
    };

    let limit = options.count.min(MAX_COUNT);
    let syntax = options.syntax.owner();
    let mut decoder = Decoder::new(bitness, bytes, start_address);
    let mut instructions = Vec::new();
    let mut truncated = false;

    while decoder.can_decode() {
        if instructions.len() == limit {
            truncated = true;
            break;
        }
        let relative = decoder.position();
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        let length = instruction.len();
        let end = (relative + length).min(bytes.len());
        instructions.push(DisassemblyInstruction {
            address: instruction.ip(),
            offset: options.offset + relative as u64,
            length: length as u32,
            bytes: hex_encode(&bytes[relative..end]),
            text: instruction.format(syntax).to_string(),
        });
    }

    Ok(DisassemblyReport {
        architecture: architecture.as_str().to_string(),
        bitness,
        start_offset: options.offset,
        start_address,
        syntax: options.syntax.as_str().to_string(),
        instructions,
        truncated,
    })
}
