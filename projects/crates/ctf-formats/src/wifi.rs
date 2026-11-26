//! 802.11 / radiotap / `pcapng` capture projection.
//!
//! Reads a capture container (`pcapng` or classic `pcap`), unwraps the radiotap
//! header when the link type carries one, and walks the 802.11 MAC header far
//! enough to answer the questions a wireless CTF asks first: which frame types
//! are present, which SSIDs and BSSIDs appear, on which channel, and whether the
//! beacon advertises an encrypted network. Frame bodies are never reassembled
//! and nothing is decrypted, so this projection stays a fact reader.
//!
//! Live 802.11 capture needs a monitor-mode adapter and driver;
//! [`capture_support`] reports that requirement instead of pretending a passive
//! file read is a live radio. On top of the frame facts, [`analyze_handshakes`]
//! extracts the `EAPOL` four-way handshake and verifies candidate WPA2
//! passphrases with PBKDF2-HMAC-SHA1 and the M2 MIC. Nothing is decrypted: the
//! PSK check recomputes the MIC from a candidate and compares it.

use std::collections::BTreeMap;

use boost_crypto::{kdf::pbkdf2_hmac_sha1, mac::hmac_sha1};
use data_binary_inspect::BinarySession;
use serde::{Deserialize, Serialize};

use crate::{CtfError, Result};

/// Default cap on decoded frames.
const DEFAULT_FRAME_LIMIT: usize = 200_000;

/// Hard cap on decoded frames.
const MAX_FRAME_LIMIT: usize = 2_000_000;

/// Maximum bytes accepted in one captured frame.
const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

/// Maximum distinct BSSIDs kept in the report.
const MAX_SSIDS: usize = 128;

/// Maximum bytes of one frame read for header, IE and EAPOL decoding.
const FRAME_READ_LIMIT: usize = 4096;

/// Default frame cap for one handshake projection.
const DEFAULT_HANDSHAKE_LIMIT: usize = 200_000;

/// Hard cap on candidate passphrases checked in one call.
const MAX_PASSPHRASES: usize = 256;

/// Maximum distinct handshakes kept in the report.
const MAX_HANDSHAKES: usize = 128;

/// Link type for an Ethernet capture (managed-mode frames after 802.3 conversion).
const LINK_ETHERNET: u32 = 1;

/// Link type for a raw 802.11 capture (no radiotap).
const LINK_80211: u32 = 105;

/// Link type for an 802.11 capture with a radiotap preamble.
const LINK_RADIOTAP: u32 = 127;

/// Inputs of one `wifi` projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WifiOptions {
    /// File offset of the capture magic; defaults to zero.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Cap on decoded frames; clamped to two million.
    #[serde(default = "default_frame_limit")]
    pub limit: usize,
}

impl Default for WifiOptions {
    fn default() -> Self {
        Self { offset: None, limit: default_frame_limit() }
    }
}

/// Whether this build can open a live radio instead of reading a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSupport {
    /// Whether a live 802.11 capture is available on this host.
    pub live: bool,
    /// Why live capture is or is not available.
    pub reason: String,
}

/// One BSSID and what its beacons advertise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiSsid {
    /// BSSID of the access point, colon-separated lower-case hex.
    pub bssid: String,
    /// Advertised SSID; empty when the beacon broadcasts none.
    pub ssid: String,
    /// Primary channel, from the DS parameter set or the radiotap channel.
    pub channel: Option<u16>,
    /// Band inferred from the channel or radiotap frequency.
    pub band: String,
    /// Encryption advertised by the beacon (`OPEN`, `WEP`, `WPA`, `WPA2/WPA3`).
    pub security: String,
    /// Beacon or probe-response frames attributed to this BSSID.
    pub frames: usize,
}

/// One decoded frame-type counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiFrameType {
    /// Frame label, such as `beacon`, `probe-req` or `data`.
    pub label: String,
    /// Frames attributed to this label.
    pub count: usize,
}

/// Result of one `wifi` projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WifiReport {
    /// Capture container; `pcapng` or `pcap`.
    pub format: String,
    /// Link layer; `radiotap`, `802.11` or `linktype-<n>`.
    pub link: String,
    /// Frames decoded.
    pub frames: usize,
    /// Sum of captured frame lengths.
    pub bytes: u64,
    /// Unix timestamp of the first decoded frame.
    pub first_timestamp: Option<f64>,
    /// Unix timestamp of the last decoded frame.
    pub last_timestamp: Option<f64>,
    /// Frame-type counters, highest first.
    pub frame_types: Vec<WifiFrameType>,
    /// Access points seen, most active first.
    pub ssids: Vec<WifiSsid>,
    /// Whether a limit or a malformed block stopped the walk.
    pub truncated: bool,
    /// Live-capture support on this host.
    pub capture: CaptureSupport,
}

fn default_frame_limit() -> usize {
    DEFAULT_FRAME_LIMIT
}

/// Reports whether this build can capture 802.11 live instead of reading a file.
pub fn capture_support() -> CaptureSupport {
    CaptureSupport {
        live: false,
        reason: "live 802.11 capture needs a monitor-mode adapter and driver; this build reads capture files and never opens a radio"
            .to_string(),
    }
}

/// Inputs of one `wifi-handshake` projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EapolOptions {
    /// File offset of the capture magic; defaults to zero.
    pub offset: Option<u64>,
    /// Cap on decoded frames; clamped to two million.
    pub limit: usize,
    /// SSID used for PMK derivation; inferred from beacons when absent.
    pub ssid: Option<String>,
    /// Candidate passphrases tested against each complete handshake; capped at 256.
    pub passphrases: Vec<String>,
}

impl Default for EapolOptions {
    fn default() -> Self {
        Self { offset: None, limit: DEFAULT_HANDSHAKE_LIMIT, ssid: None, passphrases: Vec::new() }
    }
}

/// One EAPOL-Key message observed while walking a capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EapolMessage {
    /// Four-way message number: 1, 2, 3 or 4.
    pub number: u8,
    /// Whether the access point sent this message.
    pub from_ap: bool,
    /// Replay counter carried by the message.
    pub replay: u64,
    /// Key descriptor version: 1 (TKIP), 2 (CCMP) or 3 (AES-CMAC).
    pub key_version: u8,
    /// Install bit; set on message 3.
    pub install: bool,
    /// Secure bit; set on message 4.
    pub secure: bool,
    /// Nonce carried by the message, lower-case hex.
    pub nonce: String,
}

/// One four-way handshake grouped by access point and station.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EapolHandshake {
    /// BSSID of the access point, colon-separated lower-case hex.
    pub bssid: String,
    /// MAC address of the station, colon-separated lower-case hex.
    pub station: String,
    /// SSID used for the PSK check; from the options, a beacon or `null`.
    pub ssid: Option<String>,
    /// Messages observed for this pair, in capture order.
    pub messages: Vec<EapolMessage>,
    /// Whether both message 1 and message 2 were seen.
    pub complete: bool,
    /// Access-point nonce, lower-case hex.
    pub anonce: Option<String>,
    /// Station nonce, lower-case hex.
    pub snonce: Option<String>,
    /// Whether a candidate reproduced the message 2 MIC.
    pub mic_verified: bool,
    /// Matched passphrase, only present when [`Self::mic_verified`] is true.
    pub passphrase: Option<String>,
    /// Candidate passphrases tested for this handshake.
    pub checked: usize,
}

/// Result of one `wifi-handshake` projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EapolReport {
    /// Capture container; `pcapng` or `pcap`.
    pub format: String,
    /// Link layer; `ethernet`, `radiotap`, `802.11` or `linktype-<n>`.
    pub link: String,
    /// Frames decoded.
    pub frames: usize,
    /// EAPOL-Key frames decoded, including group-key messages.
    pub eapol_frames: usize,
    /// Handshakes found, in first-seen order.
    pub handshakes: Vec<EapolHandshake>,
    /// Candidate passphrases tested across every handshake.
    pub passphrases_checked: usize,
    /// Whether a limit or a malformed block stopped the walk.
    pub truncated: bool,
    /// Live-capture support on this host.
    pub capture: CaptureSupport,
}

/// Extracts four-way handshakes and tests candidate WPA2 passphrases.
///
/// The PMK is `PBKDF2-HMAC-SHA1(passphrase, SSID, 4096)`, the PTK is the
/// 512-bit PRF over both MAC addresses and both nonces, and the check recomputes
/// the message 2 MIC with the KCK. Only key descriptor version 2 (CCMP) is
/// verified; message frames are never decrypted or reassembled.
pub fn analyze_handshakes(session: &BinarySession, options: &EapolOptions) -> Result<EapolReport> {
    let size = session.size();
    let start = options.offset.unwrap_or(0);
    if start.checked_add(4).is_none_or(|end| end > size) {
        return Err(CtfError::parse("the range is too short to hold a capture header"));
    }
    let limit = options.limit.clamp(1, MAX_FRAME_LIMIT);
    let mut scan = HandshakeScan::new();
    let walk = walk_capture(session, start, size, limit, &mut |link_type, frame, _total, _timestamp| {
        scan.ingest(link_type, frame);
    })?;
    if !matches!(walk.link_type, LINK_ETHERNET | LINK_80211 | LINK_RADIOTAP) {
        return Err(CtfError::parse(
            "the capture link type is not Wi-Fi or Ethernet; wifi-handshake expects ethernet (1), 802.11 (105) or radiotap (127)",
        ));
    }
    Ok(scan.finish(walk, options.ssid.as_deref(), &options.passphrases))
}

struct EapolPart {
    number: u8,
    from_ap: bool,
    replay: u64,
    key_version: u8,
    install: bool,
    secure: bool,
    nonce: [u8; 32],
}

struct Pending {
    parts: Vec<EapolPart>,
    anonce: Option<[u8; 32]>,
    snonce: Option<[u8; 32]>,
    m2_zeroed: Option<Vec<u8>>,
    m2_mic: Option<[u8; 16]>,
    m2_version: Option<u8>,
}

impl Pending {
    fn new() -> Self {
        Self { parts: Vec::new(), anonce: None, snonce: None, m2_zeroed: None, m2_mic: None, m2_version: None }
    }
}

struct HandshakeScan {
    order: Vec<([u8; 6], [u8; 6])>,
    map: BTreeMap<([u8; 6], [u8; 6]), Pending>,
    ssids: BTreeMap<[u8; 6], String>,
    eapol_frames: usize,
}

impl HandshakeScan {
    fn new() -> Self {
        Self { order: Vec::new(), map: BTreeMap::new(), ssids: BTreeMap::new(), eapol_frames: 0 }
    }

    fn ingest(&mut self, link_type: u32, frame: &[u8]) {
        let body = match link_type {
            LINK_RADIOTAP => match parse_radiotap(frame) {
                Some((offset, _)) if offset <= frame.len() => &frame[offset..],
                _ => return,
            },
            LINK_80211 | LINK_ETHERNET => frame,
            _ => return,
        };
        if link_type != LINK_ETHERNET
            && let Some((bssid, ssid)) = management_ssid(body)
        {
            self.ssids.entry(bssid).or_insert(ssid);
        }
        let parsed = if link_type == LINK_ETHERNET { eapol_from_ethernet(body) } else { eapol_from_80211(body) };
        let Some((eapol, sender, receiver)) = parsed else { return };
        let Some(key) = parse_eapol_key(eapol) else { return };
        self.eapol_frames += 1;
        let Some(number) = classify_eapol(key.key_info, &key.nonce) else { return };
        let from_ap = key.key_info & 0x0080 != 0;
        let ap = if from_ap { sender } else { receiver };
        let station = if from_ap { receiver } else { sender };
        let pair = (ap, station);
        if !self.map.contains_key(&pair) {
            if self.map.len() >= MAX_HANDSHAKES {
                return;
            }
            self.order.push(pair);
            self.map.insert(pair, Pending::new());
        }
        let Some(pending) = self.map.get_mut(&pair) else { return };
        let version = (key.key_info & 0x0007) as u8;
        pending.parts.push(EapolPart {
            number,
            from_ap,
            replay: key.replay,
            key_version: version,
            install: key.key_info & 0x0040 != 0,
            secure: key.key_info & 0x0200 != 0,
            nonce: key.nonce,
        });
        match number {
            1 | 3 => {
                if pending.anonce.is_none() {
                    pending.anonce = Some(key.nonce);
                }
            }
            2 => {
                if pending.snonce.is_none() {
                    pending.snonce = Some(key.nonce);
                }
                if pending.m2_mic.is_none() {
                    let mut zeroed = eapol[..key.pdu_len].to_vec();
                    zeroed[81..97].fill(0);
                    pending.m2_zeroed = Some(zeroed);
                    pending.m2_mic = Some(key.mic);
                    pending.m2_version = Some(version);
                }
            }
            _ => {}
        }
    }

    fn finish(self, walk: Walk, override_ssid: Option<&str>, passphrases: &[String]) -> EapolReport {
        let mut handshakes = Vec::new();
        let mut checked_total = 0usize;
        for pair in &self.order {
            let Some(pending) = self.map.get(pair) else { continue };
            let ssid = override_ssid.map(str::to_string).or_else(|| self.ssids.get(&pair.0).cloned());
            let mut verified = false;
            let mut passphrase = None;
            let mut checked = 0usize;
            if let (Some(ssid_text), Some(anonce), Some(snonce), Some(zeroed), Some(mic), Some(version)) = (
                ssid.as_deref(),
                pending.anonce.as_ref(),
                pending.snonce.as_ref(),
                pending.m2_zeroed.as_deref(),
                pending.m2_mic.as_ref(),
                pending.m2_version,
            ) && version == 2
            {
                for candidate in passphrases.iter().take(MAX_PASSPHRASES) {
                    checked += 1;
                    if verify_psk(ssid_text, candidate, &pair.0, &pair.1, anonce, snonce, zeroed, mic) {
                        verified = true;
                        passphrase = Some(candidate.clone());
                        break;
                    }
                }
            }
            checked_total += checked;
            let mut messages = Vec::with_capacity(pending.parts.len());
            for part in &pending.parts {
                messages.push(EapolMessage {
                    number: part.number,
                    from_ap: part.from_ap,
                    replay: part.replay,
                    key_version: part.key_version,
                    install: part.install,
                    secure: part.secure,
                    nonce: hex(&part.nonce),
                });
            }
            handshakes.push(EapolHandshake {
                bssid: format_mac(&pair.0),
                station: format_mac(&pair.1),
                ssid,
                messages,
                complete: pending.parts.iter().any(|part| part.number == 1) && pending.parts.iter().any(|part| part.number == 2),
                anonce: pending.anonce.map(|nonce| hex(&nonce)),
                snonce: pending.snonce.map(|nonce| hex(&nonce)),
                mic_verified: verified,
                passphrase,
                checked,
            });
        }
        EapolReport {
            format: walk.format,
            link: capture_link(walk.link_type),
            frames: walk.frames,
            eapol_frames: self.eapol_frames,
            handshakes,
            passphrases_checked: checked_total,
            truncated: walk.truncated,
            capture: capture_support(),
        }
    }
}

struct EapolKey {
    key_info: u16,
    replay: u64,
    nonce: [u8; 32],
    mic: [u8; 16],
    pdu_len: usize,
}

fn parse_eapol_key(frame: &[u8]) -> Option<EapolKey> {
    if frame.len() < 4 || frame[1] != 3 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([frame[2], frame[3]]));
    let pdu_len = 4usize.checked_add(length)?;
    if pdu_len < 97 || pdu_len > frame.len() {
        return None;
    }
    let key_info = u16::from_be_bytes([frame[5], frame[6]]);
    let replay = u64::from_be_bytes(frame[9..17].try_into().ok()?);
    let nonce: [u8; 32] = frame[17..49].try_into().ok()?;
    let mic: [u8; 16] = frame[81..97].try_into().ok()?;
    Some(EapolKey { key_info, replay, nonce, mic, pdu_len })
}

fn classify_eapol(key_info: u16, nonce: &[u8; 32]) -> Option<u8> {
    if key_info & 0x0008 == 0 {
        return None;
    }
    let ack = key_info & 0x0080 != 0;
    let mic = key_info & 0x0100 != 0;
    if ack && !mic {
        Some(1)
    } else if ack {
        Some(3)
    } else if mic && nonce.iter().all(|byte| *byte == 0) {
        Some(4)
    } else if mic {
        Some(2)
    } else {
        None
    }
}

fn eapol_from_ethernet(frame: &[u8]) -> Option<(&[u8], [u8; 6], [u8; 6])> {
    if frame.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 12usize;
    if ethertype == 0x8100 && frame.len() >= 18 {
        ethertype = u16::from_be_bytes([frame[16], frame[17]]);
        offset = 16;
    }
    if ethertype != 0x888e || frame.len() <= offset + 2 {
        return None;
    }
    let destination: [u8; 6] = frame[0..6].try_into().ok()?;
    let source: [u8; 6] = frame[6..12].try_into().ok()?;
    Some((&frame[offset + 2..], source, destination))
}

fn eapol_from_80211(frame: &[u8]) -> Option<(&[u8], [u8; 6], [u8; 6])> {
    if frame.len() < 24 + 8 {
        return None;
    }
    let control = u16::from_le_bytes([frame[0], frame[1]]);
    if (control >> 2) & 0x3 != 2 || control & 0x4000 != 0 {
        return None;
    }
    let subtype = ((control >> 4) & 0xf) as u8;
    let mut header = 24usize;
    if control & 0x0100 != 0 && control & 0x0200 != 0 {
        header += 6;
    }
    if subtype & 0x8 != 0 {
        header += 2;
    }
    if frame.len() < header + 8 {
        return None;
    }
    let payload = &frame[header..];
    if payload[0] != 0xaa || payload[1] != 0xaa || payload[2] != 0x03 {
        return None;
    }
    if payload[3] != 0 || payload[4] != 0 || payload[5] != 0 {
        return None;
    }
    if u16::from_be_bytes([payload[6], payload[7]]) != 0x888e {
        return None;
    }
    let destination: [u8; 6] = frame[4..10].try_into().ok()?;
    let source: [u8; 6] = frame[10..16].try_into().ok()?;
    Some((&payload[8..], source, destination))
}

fn management_ssid(frame: &[u8]) -> Option<([u8; 6], String)> {
    if frame.len() < 24 {
        return None;
    }
    let control = u16::from_le_bytes([frame[0], frame[1]]);
    if (control >> 2) & 0x3 != 0 {
        return None;
    }
    let subtype = ((control >> 4) & 0xf) as u8;
    if subtype != 5 && subtype != 8 {
        return None;
    }
    let info = parse_management(frame)?;
    match (info.bssid, info.ssid) {
        (Some(bssid), Some(ssid)) if !ssid.is_empty() => Some((bssid, ssid)),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_psk(
    ssid: &str,
    passphrase: &str,
    ap: &[u8; 6],
    station: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    eapol: &[u8],
    mic: &[u8; 16],
) -> bool {
    let mut pmk = [0u8; 32];
    if pbkdf2_hmac_sha1(passphrase.as_bytes(), ssid.as_bytes(), 4096, &mut pmk).is_err() {
        return false;
    }
    let context = ptk_context(ap, station, anonce, snonce);
    let Some(ptk) = prf512(&pmk, b"Pairwise key expansion", &context) else {
        return false;
    };
    let Ok(digest) = hmac_sha1(&ptk[..16], eapol) else {
        return false;
    };
    digest[..16] == *mic
}

fn ptk_context(ap: &[u8; 6], station: &[u8; 6], anonce: &[u8; 32], snonce: &[u8; 32]) -> [u8; 76] {
    let mut context = [0u8; 76];
    let (first_mac, second_mac) = if *ap <= *station { (ap, station) } else { (station, ap) };
    let (first_nonce, second_nonce) = if *anonce <= *snonce { (anonce, snonce) } else { (snonce, anonce) };
    context[0..6].copy_from_slice(first_mac);
    context[6..12].copy_from_slice(second_mac);
    context[12..44].copy_from_slice(first_nonce);
    context[44..76].copy_from_slice(second_nonce);
    context
}

fn prf512(pmk: &[u8; 32], label: &[u8], context: &[u8]) -> Option<[u8; 64]> {
    let mut output = [0u8; 64];
    for counter in 1u8..=4 {
        let mut input = Vec::with_capacity(label.len() + context.len() + 2);
        input.extend_from_slice(label);
        input.push(0);
        input.extend_from_slice(context);
        input.push(counter);
        let digest = hmac_sha1(pmk, &input).ok()?;
        let start = usize::from(counter - 1) * 20;
        let take = (64 - start).min(20);
        output[start..start + take].copy_from_slice(&digest[..take]);
    }
    Some(output)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn capture_link(link_type: u32) -> String {
    match link_type {
        LINK_ETHERNET => "ethernet".to_string(),
        LINK_80211 => "802.11".to_string(),
        LINK_RADIOTAP => "radiotap".to_string(),
        other => format!("linktype-{other}"),
    }
}

/// Summarizes one 802.11 capture.
pub fn analyze(session: &BinarySession, options: &WifiOptions) -> Result<WifiReport> {
    let size = session.size();
    let start = options.offset.unwrap_or(0);
    if start.checked_add(4).is_none_or(|end| end > size) {
        return Err(CtfError::parse("the range is too short to hold a capture header"));
    }
    let limit = options.limit.clamp(1, MAX_FRAME_LIMIT);
    let mut acc = Accumulator::new();
    let walk = walk_capture(session, start, size, limit, &mut |link_type, frame, _total, _timestamp| {
        acc.ingest(link_type, frame);
    })?;
    if walk.link_type != LINK_80211 && walk.link_type != LINK_RADIOTAP {
        return Err(CtfError::parse(
            "the capture link type is not 802.11; wifi expects radiotap (127) or raw 802.11 (105)",
        ));
    }
    Ok(acc.finish(walk))
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

struct SsidAcc {
    ssid: String,
    channel: Option<u16>,
    band: String,
    security: String,
    frames: usize,
}

struct Accumulator {
    types: BTreeMap<String, usize>,
    ssids: BTreeMap<[u8; 6], SsidAcc>,
}

impl Accumulator {
    fn new() -> Self {
        Self { types: BTreeMap::new(), ssids: BTreeMap::new() }
    }

    fn ingest(&mut self, link_type: u32, frame: &[u8]) {
        if link_type != LINK_80211 && link_type != LINK_RADIOTAP {
            bump(&mut self.types, &format!("link-{link_type}"));
            return;
        }
        let (body, frequency) = if link_type == LINK_RADIOTAP {
            match parse_radiotap(frame) {
                Some((offset, frequency)) if offset <= frame.len() => (&frame[offset..], frequency),
                _ => {
                    bump(&mut self.types, "radiotap-malformed");
                    return;
                }
            }
        } else {
            (frame, None)
        };
        if body.len() < 2 {
            bump(&mut self.types, "truncated");
            return;
        }
        let control = u16::from_le_bytes([body[0], body[1]]);
        let frame_type = ((control >> 2) & 0x3) as u8;
        let subtype = ((control >> 4) & 0xf) as u8;
        bump(&mut self.types, &frame_label(frame_type, subtype));
        if frame_type != 0 {
            return;
        }
        let Some(info) = parse_management(body) else { return };
        let Some(bssid) = info.bssid else { return };
        let Some(ssid) = info.ssid.clone() else { return };
        if ssid.is_empty() {
            return;
        }
        let channel = info.channel.or_else(|| frequency.and_then(channel_from_frequency));
        let band = band_for(frequency, channel);
        let entry = self
            .ssids
            .entry(bssid)
            .or_insert_with(|| SsidAcc { ssid: ssid.clone(), channel, band, security: info.security.clone(), frames: 0 });
        entry.frames += 1;
        if entry.channel.is_none() {
            entry.channel = channel;
        }
    }

    fn finish(self, walk: Walk) -> WifiReport {
        let mut frame_types: Vec<WifiFrameType> =
            self.types.into_iter().map(|(label, count)| WifiFrameType { label, count }).collect();
        frame_types.sort_by(|left, right| right.count.cmp(&left.count).then_with(|| left.label.cmp(&right.label)));
        let mut ssids: Vec<WifiSsid> = self
            .ssids
            .into_iter()
            .map(|(bssid, acc)| WifiSsid {
                bssid: format_mac(&bssid),
                ssid: acc.ssid,
                channel: acc.channel,
                band: acc.band,
                security: acc.security,
                frames: acc.frames,
            })
            .collect();
        ssids.sort_by(|left, right| right.frames.cmp(&left.frames).then_with(|| left.bssid.cmp(&right.bssid)));
        ssids.truncate(MAX_SSIDS);
        WifiReport {
            format: walk.format,
            link: link_name(walk.link_type),
            frames: walk.frames,
            bytes: walk.bytes,
            first_timestamp: walk.first_timestamp,
            last_timestamp: walk.last_timestamp,
            frame_types,
            ssids,
            truncated: walk.truncated,
            capture: capture_support(),
        }
    }
}

/// Facts shared by every capture walk.
struct Walk {
    format: String,
    link_type: u32,
    frames: usize,
    bytes: u64,
    first_timestamp: Option<f64>,
    last_timestamp: Option<f64>,
    truncated: bool,
}

type Visit<'a> = &'a mut dyn FnMut(u32, &[u8], u64, f64);

fn walk_capture(session: &BinarySession, start: u64, size: u64, limit: usize, visit: Visit<'_>) -> Result<Walk> {
    let magic = session.read(start, 4)?;
    let mut walk = Walk {
        format: String::new(),
        link_type: 0,
        frames: 0,
        bytes: 0,
        first_timestamp: None,
        last_timestamp: None,
        truncated: false,
    };
    match [magic[0], magic[1], magic[2], magic[3]] {
        [0x0a, 0x0d, 0x0d, 0x0a] => walk_pcapng(session, start, size, limit, &mut walk, visit)?,
        [0xd4, 0xc3, 0xb2, 0xa1] => {
            walk_pcap(session, start, size, Endian::Little, 1_000_000.0, limit, &mut walk, visit)?;
        }
        [0xa1, 0xb2, 0xc3, 0xd4] => {
            walk_pcap(session, start, size, Endian::Big, 1_000_000.0, limit, &mut walk, visit)?;
        }
        [0x4d, 0x3c, 0xb2, 0xa1] => {
            walk_pcap(session, start, size, Endian::Little, 1_000_000_000.0, limit, &mut walk, visit)?;
        }
        [0xa1, 0xb2, 0x3c, 0x4d] => {
            walk_pcap(session, start, size, Endian::Big, 1_000_000_000.0, limit, &mut walk, visit)?;
        }
        _ => return Err(CtfError::parse("the range does not start with a pcap or pcapng header")),
    }
    Ok(walk)
}

fn record(walk: &mut Walk, link_type: u32, frame: &[u8], total: u64, timestamp: f64, visit: Visit<'_>) {
    walk.frames += 1;
    walk.bytes += total;
    walk.first_timestamp.get_or_insert(timestamp);
    walk.last_timestamp = Some(timestamp);
    visit(link_type, frame, total, timestamp);
}

#[allow(clippy::too_many_arguments)]
fn walk_pcap(
    session: &BinarySession,
    start: u64,
    size: u64,
    endian: Endian,
    divisor: f64,
    limit: usize,
    walk: &mut Walk,
    visit: Visit<'_>,
) -> Result<()> {
    let header = session.read(start + 4, 20)?;
    let link_type = endian.u32(&header[16..20]);
    walk.format = "pcap".to_string();
    walk.link_type = link_type;
    let mut cursor = start + 24;
    while cursor + 16 <= size {
        if walk.frames >= limit {
            walk.truncated = cursor < size;
            break;
        }
        let header_bytes = session.read(cursor, 16)?;
        let seconds = endian.u32(&header_bytes[0..4]);
        let fraction = endian.u32(&header_bytes[4..8]);
        let captured = endian.u32(&header_bytes[8..12]);
        if captured > MAX_FRAME_BYTES {
            walk.truncated = true;
            break;
        }
        let data_start = cursor + 16;
        let data_end = match data_start.checked_add(u64::from(captured)) {
            Some(end) if end <= size => end,
            _ => {
                walk.truncated = true;
                break;
            }
        };
        let head = session.read(data_start, u64::from(captured).min(FRAME_READ_LIMIT as u64))?;
        let timestamp = f64::from(seconds) + f64::from(fraction) / divisor;
        record(walk, link_type, head, u64::from(captured), timestamp, visit);
        cursor = data_end;
    }
    if cursor + 16 > size && cursor < size {
        walk.truncated = true;
    }
    Ok(())
}

fn walk_pcapng(session: &BinarySession, start: u64, size: u64, limit: usize, walk: &mut Walk, visit: Visit<'_>) -> Result<()> {
    walk.format = "pcapng".to_string();
    let mut cursor = start;
    let mut endian: Option<Endian> = None;
    let mut interfaces: Vec<u32> = Vec::new();
    while cursor + 12 <= size {
        if walk.frames >= limit {
            walk.truncated = cursor < size;
            break;
        }
        let magic = session.read(cursor, 4)?;
        if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
            let bom = session.read(cursor + 8, 4)?;
            endian = match [bom[0], bom[1], bom[2], bom[3]] {
                [0x4d, 0x3c, 0x2b, 0x1a] => Some(Endian::Little),
                [0x1a, 0x2b, 0x3c, 0x4d] => Some(Endian::Big),
                _ => return Err(CtfError::parse("the pcapng byte-order magic is unknown")),
            };
            interfaces.clear();
        }
        let Some(order) = endian else {
            return Err(CtfError::parse("a pcapng packet block appears before the section header"));
        };
        let head = session.read(cursor, 8)?;
        let block_type = order.u32(&head[0..4]);
        let total = u64::from(order.u32(&head[4..8]));
        if total < 12 || total % 4 != 0 {
            walk.truncated = true;
            break;
        }
        let block_end = match cursor.checked_add(total) {
            Some(end) if end <= size => end,
            _ => {
                walk.truncated = true;
                break;
            }
        };
        match block_type {
            0x0a0d_0d0a => {}
            1 => {
                let body = session.read(cursor + 8, total - 12)?;
                if body.len() < 8 {
                    walk.truncated = true;
                    break;
                }
                let link_type = u32::from(order.u16(&body[0..2]));
                if interfaces.is_empty() {
                    walk.link_type = link_type;
                }
                interfaces.push(link_type);
            }
            6 => {
                let body = session.read(cursor + 8, total - 12)?;
                if body.len() < 20 {
                    walk.truncated = true;
                    break;
                }
                let interface_id = order.u32(&body[0..4]) as usize;
                let seconds = u64::from(order.u32(&body[4..8]));
                let sub = u64::from(order.u32(&body[8..12]));
                let captured = order.u32(&body[12..16]);
                if captured > MAX_FRAME_BYTES {
                    walk.truncated = true;
                    break;
                }
                let data_end = 20usize + captured as usize;
                if data_end > body.len() {
                    walk.truncated = true;
                    break;
                }
                let link_type = interfaces.get(interface_id).copied().unwrap_or(u32::MAX);
                let timestamp = ((seconds << 32) | sub) as f64 / 1_000_000.0;
                let frame = &body[20..data_end];
                let head = &frame[..frame.len().min(FRAME_READ_LIMIT)];
                record(walk, link_type, head, u64::from(captured), timestamp, visit);
            }
            3 => {
                let body = session.read(cursor + 8, total - 12)?;
                if body.len() < 4 {
                    walk.truncated = true;
                    break;
                }
                let original = order.u32(&body[0..4]) as usize;
                let data = &body[4..];
                let take = original.min(data.len());
                let sample = &data[..take];
                let head = &sample[..sample.len().min(FRAME_READ_LIMIT)];
                let link_type = interfaces.first().copied().unwrap_or(u32::MAX);
                record(walk, link_type, head, u64::from(original as u32), 0.0, visit);
            }
            _ => {}
        }
        cursor = block_end;
    }
    if cursor + 12 > size && cursor < size {
        walk.truncated = true;
    }
    Ok(())
}

/// Decodes a radiotap preamble and returns the payload offset plus any channel
/// frequency. Unknown higher fields stop the field walk rather than guessing.
fn parse_radiotap(data: &[u8]) -> Option<(usize, Option<u16>)> {
    if data.len() < 8 || data[0] != 0 {
        return None;
    }
    let length = usize::from(u16::from_le_bytes([data[2], data[3]]));
    if length < 8 || length > data.len() {
        return None;
    }
    let mut offset = 4usize;
    let mut present: Vec<u32> = Vec::new();
    loop {
        if offset + 4 > length {
            return None;
        }
        let bits = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        present.push(bits);
        offset += 4;
        if bits & 0x8000_0000 == 0 {
            break;
        }
        if present.len() >= 8 {
            return None;
        }
    }
    let mut cursor = offset;
    let mut frequency: Option<u16> = None;
    'fields: for (index, bits) in present.iter().enumerate() {
        for bit in 0..32u32 {
            if bits & (1u32 << bit) == 0 {
                continue;
            }
            let id = index as u32 * 32 + bit;
            let (size, align) = match id {
                0 => (8usize, 8usize),
                1 | 2 | 5 | 6 | 10 | 11 | 12 | 13 => (1, 1),
                3 | 4 | 7 | 8 | 9 | 14 => (2, 2),
                _ => break 'fields,
            };
            cursor = align_up(cursor, align);
            if cursor + size > length {
                break 'fields;
            }
            if id == 3 {
                frequency = Some(u16::from_le_bytes([data[cursor], data[cursor + 1]]));
            }
            cursor += size;
        }
    }
    Some((length, frequency))
}

struct MgmtInfo {
    bssid: Option<[u8; 6]>,
    ssid: Option<String>,
    channel: Option<u16>,
    security: String,
}

/// Decodes a management frame far enough to read the BSSID and its IEs.
fn parse_management(body: &[u8]) -> Option<MgmtInfo> {
    if body.len() < 24 {
        return None;
    }
    let control = u16::from_le_bytes([body[0], body[1]]);
    let subtype = ((control >> 4) & 0xf) as u8;
    let bssid = match subtype {
        5 | 8 => Some([body[16], body[17], body[18], body[19], body[20], body[21]]),
        _ => None,
    };
    let (ie_start, privacy) = match subtype {
        5 | 8 => {
            if body.len() < 24 + 12 {
                return None;
            }
            let capability = u16::from_le_bytes([body[24 + 10], body[24 + 11]]);
            (24 + 12, capability & 0x0010 != 0)
        }
        4 => (24, false),
        _ => (body.len(), false),
    };
    let mut info = MgmtInfo { bssid, ssid: None, channel: None, security: String::new() };
    let mut rsn = false;
    let mut wpa = false;
    let mut index = ie_start;
    while index + 2 <= body.len() {
        let id = body[index];
        let length = usize::from(body[index + 1]);
        let start = index + 2;
        let end = start + length;
        if end > body.len() {
            break;
        }
        let value = &body[start..end];
        match id {
            0 => info.ssid = Some(String::from_utf8_lossy(value).to_string()),
            3 => {
                if length >= 1 {
                    info.channel = Some(u16::from(value[0]));
                }
            }
            48 => rsn = true,
            221 if value.len() >= 4 && value[0] == 0x00 && value[1] == 0x50 && value[2] == 0xf2 && value[3] == 0x01 => {
                wpa = true;
            }
            _ => {}
        }
        index = end;
    }
    info.security = security_label(rsn, wpa, privacy);
    Some(info)
}

fn frame_label(frame_type: u8, subtype: u8) -> String {
    match (frame_type, subtype) {
        (0, 0) => "assoc-req",
        (0, 1) => "assoc-resp",
        (0, 2) => "reassoc-req",
        (0, 3) => "reassoc-resp",
        (0, 4) => "probe-req",
        (0, 5) => "probe-resp",
        (0, 8) => "beacon",
        (0, 10) => "disassoc",
        (0, 11) => "auth",
        (0, 12) => "deauth",
        (0, 13) => "action",
        (1, _) => "control",
        (2, _) => "data",
        (3, _) => "extension",
        _ => "management",
    }
    .to_string()
}

fn security_label(rsn: bool, wpa: bool, privacy: bool) -> String {
    if rsn && wpa {
        "WPA/WPA2 (RSN+WPA)".to_string()
    } else if rsn {
        "WPA2/WPA3 (RSN)".to_string()
    } else if wpa {
        "WPA".to_string()
    } else if privacy {
        "WEP".to_string()
    } else {
        "OPEN".to_string()
    }
}

fn channel_from_frequency(frequency: u16) -> Option<u16> {
    match frequency {
        2412..=2472 => Some((frequency - 2407) / 5),
        2484 => Some(14),
        5160..=5885 => Some((frequency - 5000) / 5),
        5955..=7115 => Some((frequency - 5950) / 5),
        _ => None,
    }
}

fn band_for(frequency: Option<u16>, channel: Option<u16>) -> String {
    if let Some(value) = frequency {
        return match value {
            2400..=2500 => "2.4 GHz",
            4900..=5924 => "5 GHz",
            5925..=7125 => "6 GHz",
            _ => "unknown",
        }
        .to_string();
    }
    match channel {
        Some(1..=14) => "2.4 GHz".to_string(),
        Some(32..=177) => "5 GHz".to_string(),
        _ => "unknown".to_string(),
    }
}

fn link_name(link_type: u32) -> String {
    match link_type {
        LINK_80211 => "802.11".to_string(),
        LINK_RADIOTAP => "radiotap".to_string(),
        other => format!("linktype-{other}"),
    }
}

fn format_mac(address: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", address[0], address[1], address[2], address[3], address[4], address[5])
}

fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 { value } else { (value + align - 1) & !(align - 1) }
}

fn bump(map: &mut BTreeMap<String, usize>, key: &str) {
    *map.entry(key.to_string()).or_insert(0) += 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmk_matches_the_ieee_vector() {
        let mut pmk = [0u8; 32];
        pbkdf2_hmac_sha1(b"password", b"IEEE", 4096, &mut pmk).expect("pbkdf2");
        assert_eq!(hex(&pmk), "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e");
    }
}
