//! Challenge projections: what the artifact is, not what a solver guesses.
//!
//! Container probing, packer identification, PNG chunks and pcap captures are
//! reported here because they classify the challenge. Each function forwards one
//! options JSON to `open-ctf-domain` and returns the serialized report.

use open_ctf_domain::{CtfError, PackerOptions, PcapOptions, PngOptions, ProbeOptions};
use serde_json::Value;
use wae::{CallContext, JsValue, Result};

use crate::{
    error::{encoded, failure, handle, respond, text},
    registry::with_engine,
};

fn probe_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<ProbeOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid ProbeOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.probe(&options)?))
}

fn packer_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<PackerOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid PackerOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.packer(&options)?))
}

fn png_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<PngOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid PngOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.png(&options)?))
}

fn pcap_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<PcapOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid PcapOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.pcap(&options)?))
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
