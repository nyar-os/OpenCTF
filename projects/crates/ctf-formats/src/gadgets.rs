//! Minimal x64 ROP gadget scanning.
//!
//! Only byte patterns whose semantics are fixed on x86-64 are reported:
//! `ret`, `ret imm16`, `pop r64; ret`, `leave; ret`, `syscall`, `sysenter`,
//! `int 0x80`, `jmp rsp` and `call rsp`. No instruction database is consulted,
//! so a hit is a byte-level candidate that a disassembler must still confirm.

// TODO(boost): owner migration -> data-binary-x64; see documentation/duplication.md

use boost_crypto::encoding::hex_encode;
use data_binary_inspect::BinarySession;
use serde::{Deserialize, Serialize};

use crate::Result;

/// Default cap on reported gadgets.
const DEFAULT_HIT_LIMIT: usize = 64;

/// Hard cap on reported gadgets.
const MAX_HIT_LIMIT: usize = 4096;

/// Register names indexed by the low three bits of a `pop r64` opcode.
const POP_REGISTERS: [&str; 8] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];

/// Inputs of one `OpenCtf::gadgets` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GadgetOptions {
    /// First byte to scan; defaults to the start of the executable sections.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Bytes to scan; defaults to the rest of the file.
    #[serde(default)]
    pub length: Option<u64>,
    /// Restrict the scan to executable sections when the container exposes them.
    #[serde(default = "default_executable_only")]
    pub executable_only: bool,
    /// Maximum reported gadgets; clamped to 4096.
    #[serde(default = "default_hit_limit")]
    pub limit: usize,
}

impl Default for GadgetOptions {
    fn default() -> Self {
        Self { offset: None, length: None, executable_only: default_executable_only(), limit: default_hit_limit() }
    }
}

/// One gadget candidate at a file offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GadgetHit {
    /// Absolute file offset of the first gadget byte.
    pub offset: u64,
    /// Virtual address when the container can map the offset.
    pub va: Option<u64>,
    /// Pattern family: `ret`, `ret-imm`, `pop-ret`, `leave-ret`, `syscall`,
    /// `sysenter`, `int80`, `jmp-rsp` or `call-rsp`.
    pub kind: String,
    /// Matched bytes as lowercase hex.
    pub bytes: String,
    /// Human-readable gadget text.
    pub text: String,
}

/// Result of one `OpenCtf::gadgets` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GadgetsReport {
    /// Total bytes examined across the selected ranges.
    pub scanned: u64,
    /// Candidates in file-offset order, cut at the limit.
    pub hits: Vec<GadgetHit>,
    /// Whether the scan stopped at the hit limit.
    pub truncated: bool,
}

fn default_hit_limit() -> usize {
    DEFAULT_HIT_LIMIT
}

fn default_executable_only() -> bool {
    true
}

/// Scans executable sections, or one explicit range, for basic gadgets.
pub fn analyze(session: &BinarySession, options: &GadgetOptions) -> Result<GadgetsReport> {
    let limit = options.limit.clamp(1, MAX_HIT_LIMIT);
    let mut hits = Vec::new();
    let mut scanned = 0u64;
    let mut truncated = false;
    for (start, end) in ranges(session, options) {
        let bytes = session.read(start, end - start)?;
        scanned += bytes.len() as u64;
        for index in 0..bytes.len() {
            let Some((kind, length, text)) = hit_at(bytes, index)
            else {
                continue;
            };
            let offset = start + index as u64;
            hits.push(GadgetHit {
                offset,
                va: session.offset_to_va(offset).ok(),
                kind: kind.to_string(),
                bytes: hex_encode(&bytes[index..index + length]),
                text,
            });
            if hits.len() == limit {
                truncated = index + 1 < bytes.len();
                break;
            }
        }
        if hits.len() == limit {
            break;
        }
    }
    Ok(GadgetsReport { scanned, hits, truncated })
}

/// Resolves the byte ranges to scan, clamped to the requested window.
fn ranges(session: &BinarySession, options: &GadgetOptions) -> Vec<(u64, u64)> {
    let size = session.size();
    let start = options.offset.unwrap_or(0).min(size);
    let end = start.saturating_add(options.length.unwrap_or(size - start)).min(size);
    if end <= start {
        return Vec::new();
    }
    if options.executable_only
        && let Ok(sections) = session.sections()
    {
        let mut ranges = Vec::new();
        for section in sections.iter().filter(|section| section.executable && section.raw_size > 0) {
            let section_start = section.raw_pointer.max(start);
            let section_end = section.raw_pointer.saturating_add(section.raw_size).min(end);
            if section_end > section_start {
                ranges.push((section_start, section_end));
            }
        }
        if !ranges.is_empty() {
            return ranges;
        }
    }
    vec![(start, end)]
}

/// Matches one gadget family at `index`, if any.
fn hit_at(bytes: &[u8], index: usize) -> Option<(&'static str, usize, String)> {
    let byte = bytes[index];
    if let Some(next) = bytes.get(index + 1).copied() {
        match (byte, next) {
            (0x0f, 0x05) => return Some(("syscall", 2, "syscall".to_string())),
            (0x0f, 0x34) => return Some(("sysenter", 2, "sysenter".to_string())),
            (0xcd, 0x80) => return Some(("int80", 2, "int 0x80".to_string())),
            (0xff, 0xe4) => return Some(("jmp-rsp", 2, "jmp rsp".to_string())),
            (0xff, 0xd4) => return Some(("call-rsp", 2, "call rsp".to_string())),
            (0xc9, 0xc3) => return Some(("leave-ret", 2, "leave; ret".to_string())),
            (0x58..=0x5f, 0xc3) => {
                let register = POP_REGISTERS[(byte - 0x58) as usize];
                return Some(("pop-ret", 2, format!("pop {register}; ret")));
            }
            _ => {}
        }
    }
    if byte == 0xc2
        && let (Some(low), Some(high)) = (bytes.get(index + 1).copied(), bytes.get(index + 2).copied())
    {
        let immediate = u16::from_le_bytes([low, high]);
        return Some(("ret-imm", 3, format!("ret 0x{immediate:04x}")));
    }
    if byte == 0xc3 {
        // `leave; ret` and `pop r64; ret` already cover this byte.
        let combined = index > 0 && matches!(bytes[index - 1], 0xc9 | 0x58..=0x5f);
        if !combined {
            return Some(("ret", 1, "ret".to_string()));
        }
    }
    None
}
