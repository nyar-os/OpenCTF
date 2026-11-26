//! Classic `pcap` capture summaries.
//!
//! The global header and per-packet records are decoded statically. Ethernet,
//! raw IPv4/IPv6 and Linux cooked captures are walked far enough to count
//! protocols and endpoints; payloads are never reassembled and `pcapng`
//! sections are rejected instead of guessed.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use data_binary_inspect::BinarySession;
use serde::{Deserialize, Serialize};

use crate::{CtfError, Result};

/// Default cap on scanned packets.
const DEFAULT_PACKET_LIMIT: usize = 100_000;

/// Hard cap on scanned packets.
const MAX_PACKET_LIMIT: usize = 1_000_000;

/// Maximum bytes read from one packet for header decoding.
const PACKET_HEAD_LIMIT: u64 = 160;

/// Maximum bytes accepted in one packet record.
const MAX_PACKET_BYTES: u32 = 16 * 1024 * 1024;

/// Cap on aggregated protocol names.
const MAX_PROTOCOLS: usize = 64;

/// Cap on aggregated endpoints.
const MAX_ENDPOINTS: usize = 32;

/// Inputs of one `OpenCtf::pcap` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PcapOptions {
    /// File offset of the pcap magic; defaults to zero.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Cap on scanned packets; clamped to one million.
    #[serde(default = "default_packet_limit")]
    pub limit: usize,
}

impl Default for PcapOptions {
    fn default() -> Self {
        Self { offset: None, limit: default_packet_limit() }
    }
}

/// One protocol counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcapProtocol {
    /// Protocol label, such as `tcp` or `ethertype-0806`.
    pub name: String,
    /// Packets attributed to this label.
    pub packets: usize,
}

/// One endpoint counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcapEndpoint {
    /// `address:port` seen as a TCP or UDP sender or receiver.
    pub address: String,
    /// Packets involving this endpoint.
    pub packets: usize,
}

/// Result of one pcap summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PcapReport {
    /// Capture format; always `pcap`.
    pub format: String,
    /// Byte order of the record headers.
    pub endianness: String,
    /// Timestamp fraction unit: `us` or `ns`.
    pub timestamp_resolution: String,
    /// Declared `major.minor` version.
    pub version: String,
    /// Declared snapshot length.
    pub snaplen: u32,
    /// Link type number.
    pub link_type: u32,
    /// Link type name.
    pub link_name: String,
    /// Records decoded.
    pub packet_count: usize,
    /// Sum of captured record lengths.
    pub captured_bytes: u64,
    /// Unix timestamp of the first decoded record.
    pub first_timestamp: Option<f64>,
    /// Unix timestamp of the last decoded record.
    pub last_timestamp: Option<f64>,
    /// Protocol counters, highest first.
    pub protocols: Vec<PcapProtocol>,
    /// Endpoint counters, highest first.
    pub endpoints: Vec<PcapEndpoint>,
    /// Whether a limit or a malformed record stopped the walk.
    pub truncated: bool,
}

fn default_packet_limit() -> usize {
    DEFAULT_PACKET_LIMIT
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
            Self::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Self::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        }
    }
}

/// Summarizes one classic pcap capture.
pub fn analyze(session: &BinarySession, options: &PcapOptions) -> Result<PcapReport> {
    let size = session.size();
    let start = options.offset.unwrap_or(0);
    if start.checked_add(24).is_none_or(|end| end > size) {
        return Err(CtfError::parse("the range is too short to hold a pcap header"));
    }
    let magic = session.read(start, 4)?;
    let (endian, resolution) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, "us"),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, "us"),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, "ns"),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, "ns"),
        [0x0a, 0x0d, 0x0d, 0x0a] => {
            return Err(CtfError::parse("pcapng sections are not decoded; only classic pcap is supported"));
        }
        _ => return Err(CtfError::parse("the range does not start with a pcap magic")),
    };
    let header = session.read(start + 4, 20)?;
    let version = format!("{}.{}", endian.u16(&header[0..2]), endian.u16(&header[2..4]));
    let snaplen = endian.u32(&header[12..16]);
    let link_type = endian.u32(&header[16..20]);
    let divisor = if resolution == "us" { 1_000_000.0 } else { 1_000_000_000.0 };
    let limit = options.limit.clamp(1, MAX_PACKET_LIMIT);

    let mut report = PcapReport {
        format: "pcap".to_string(),
        endianness: match endian {
            Endian::Little => "little".to_string(),
            Endian::Big => "big".to_string(),
        },
        timestamp_resolution: resolution.to_string(),
        version,
        snaplen,
        link_type,
        link_name: link_name(link_type).to_string(),
        packet_count: 0,
        captured_bytes: 0,
        first_timestamp: None,
        last_timestamp: None,
        protocols: Vec::new(),
        endpoints: Vec::new(),
        truncated: false,
    };
    let mut protocols: BTreeMap<String, usize> = BTreeMap::new();
    let mut endpoints: BTreeMap<String, usize> = BTreeMap::new();
    let mut cursor = start + 24;
    while cursor + 16 <= size {
        if report.packet_count == limit {
            report.truncated = cursor < size;
            break;
        }
        let record = session.read(cursor, 16)?;
        let seconds = endian.u32(&record[0..4]);
        let fraction = endian.u32(&record[4..8]);
        let captured = endian.u32(&record[8..12]);
        if captured > MAX_PACKET_BYTES {
            report.truncated = true;
            break;
        }
        let data_start = cursor + 16;
        let data_end = match data_start.checked_add(u64::from(captured)) {
            Some(end) if end <= size => end,
            _ => {
                report.truncated = true;
                break;
            }
        };
        let timestamp = f64::from(seconds) + f64::from(fraction) / divisor;
        report.first_timestamp.get_or_insert(timestamp);
        report.last_timestamp = Some(timestamp);
        report.packet_count += 1;
        report.captured_bytes += u64::from(captured);
        let head = session.read(data_start, u64::from(captured).min(PACKET_HEAD_LIMIT))?;
        dissect(link_type, head, &mut protocols, &mut endpoints);
        cursor = data_end;
    }
    if cursor + 16 > size && cursor < size {
        report.truncated = true;
    }
    report.protocols =
        ranked(protocols, MAX_PROTOCOLS).into_iter().map(|(name, packets)| PcapProtocol { name, packets }).collect();
    report.endpoints =
        ranked(endpoints, MAX_ENDPOINTS).into_iter().map(|(address, packets)| PcapEndpoint { address, packets }).collect();
    Ok(report)
}

fn link_name(link_type: u32) -> &'static str {
    match link_type {
        0 => "null",
        1 => "ethernet",
        101 => "raw-ip",
        113 => "linux-sll",
        228 => "ipv4",
        229 => "ipv6",
        _ => "unknown",
    }
}

fn ranked(map: BTreeMap<String, usize>, limit: usize) -> Vec<(String, usize)> {
    let mut entries: Vec<(String, usize)> = map.into_iter().collect();
    entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    entries.truncate(limit);
    entries
}

fn dissect(link_type: u32, data: &[u8], protocols: &mut BTreeMap<String, usize>, endpoints: &mut BTreeMap<String, usize>) {
    match link_type {
        1 => ethernet(data, protocols, endpoints),
        101 | 228 => ipv4(data, protocols, endpoints),
        229 => ipv6(data, protocols, endpoints),
        other => bump(protocols, &format!("linktype-{other}")),
    }
}

fn ethernet(data: &[u8], protocols: &mut BTreeMap<String, usize>, endpoints: &mut BTreeMap<String, usize>) {
    if data.len() < 14 {
        bump(protocols, "truncated-ethernet");
        return;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut payload = &data[14..];
    if ethertype == 0x8100 && payload.len() >= 4 {
        ethertype = u16::from_be_bytes([payload[2], payload[3]]);
        payload = &payload[4..];
    }
    match ethertype {
        0x0800 => ipv4(payload, protocols, endpoints),
        0x86dd => ipv6(payload, protocols, endpoints),
        0x0806 => bump(protocols, "arp"),
        other => bump(protocols, &format!("ethertype-{other:04x}")),
    }
}

fn ipv4(data: &[u8], protocols: &mut BTreeMap<String, usize>, endpoints: &mut BTreeMap<String, usize>) {
    if data.len() < 20 {
        bump(protocols, "truncated-ipv4");
        return;
    }
    let header_length = usize::from(data[0] & 0x0f) * 4;
    if header_length < 20 || data.len() < header_length {
        bump(protocols, "truncated-ipv4");
        return;
    }
    let source = Ipv4Addr::new(data[12], data[13], data[14], data[15]).to_string();
    let destination = Ipv4Addr::new(data[16], data[17], data[18], data[19]).to_string();
    let payload = &data[header_length..];
    match data[9] {
        6 => tcp(payload, &source, &destination, protocols, endpoints),
        17 => udp(payload, &source, &destination, protocols, endpoints),
        1 => bump(protocols, "icmp"),
        other => bump(protocols, &format!("ip-proto-{other}")),
    }
}

fn ipv6(data: &[u8], protocols: &mut BTreeMap<String, usize>, endpoints: &mut BTreeMap<String, usize>) {
    if data.len() < 40 {
        bump(protocols, "truncated-ipv6");
        return;
    }
    let mut source = [0u8; 16];
    source.copy_from_slice(&data[8..24]);
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&data[24..40]);
    let source = format!("[{}]", Ipv6Addr::from(source));
    let destination = format!("[{}]", Ipv6Addr::from(destination));
    let payload = &data[40..];
    match data[6] {
        6 => tcp(payload, &source, &destination, protocols, endpoints),
        17 => udp(payload, &source, &destination, protocols, endpoints),
        58 => bump(protocols, "icmpv6"),
        other => bump(protocols, &format!("ipv6-next-{other}")),
    }
}

fn tcp(
    payload: &[u8],
    source: &str,
    destination: &str,
    protocols: &mut BTreeMap<String, usize>,
    endpoints: &mut BTreeMap<String, usize>,
) {
    bump(protocols, "tcp");
    transport(payload, source, destination, endpoints);
}

fn udp(
    payload: &[u8],
    source: &str,
    destination: &str,
    protocols: &mut BTreeMap<String, usize>,
    endpoints: &mut BTreeMap<String, usize>,
) {
    bump(protocols, "udp");
    transport(payload, source, destination, endpoints);
}

fn transport(payload: &[u8], source: &str, destination: &str, endpoints: &mut BTreeMap<String, usize>) {
    if payload.len() < 4 {
        bump(endpoints, &format!("{source}:?"));
        return;
    }
    let source_port = u16::from_be_bytes([payload[0], payload[1]]);
    let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
    bump(endpoints, &format!("{source}:{source_port}"));
    bump(endpoints, &format!("{destination}:{destination_port}"));
}

fn bump(map: &mut BTreeMap<String, usize>, key: &str) {
    *map.entry(key.to_string()).or_insert(0) += 1;
}
