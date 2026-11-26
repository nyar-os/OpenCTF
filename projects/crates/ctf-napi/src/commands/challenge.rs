//! Challenge projections: what the artifact is, not what a solver guesses.
//!
//! Container probing, packer identification, PNG chunks and pcap captures are
//! reported here because they classify the challenge. Each function forwards one
//! options JSON to `open-ctf-domain` and returns the serialized report.

use open_ctf_domain::{CtfError, EapolOptions, PackerOptions, PcapOptions, PngOptions, ProbeOptions, WifiOptions};
use serde_json::Value;
use wae::{CallContext, JsValue, Result};

use crate::{
    error::{encoded, failure, handle, respond, text},
    registry::with_engine,
};

fn probe_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<ProbeOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid ProbeOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.probe(&options)?))
}

fn packer_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<PackerOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid PackerOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.packer(&options)?))
}

fn png_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<PngOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid PngOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.png(&options)?))
}

fn pcap_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<PcapOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid PcapOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.pcap(&options)?))
}

fn wifi_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<WifiOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid WifiOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.wifi(&options)?))
}

fn wifi_handshake_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<EapolOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid EapolOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.wifi_handshake(&options)?))
}

pub(crate) fn binary_probe(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match probe_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_packer(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match packer_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_png(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match png_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_pcap(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match pcap_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_wifi(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match wifi_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_wifi_handshake(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match wifi_handshake_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}
