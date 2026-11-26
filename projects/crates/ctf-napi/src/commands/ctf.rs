//! CTF-oriented operations behind the exported Node-API entry points.
//!
//! Each function forwards one options JSON to `open-ctf-core` and returns the
//! serialized report; JWT decoding is standalone because it needs no file
//! handle.

use open_ctf_core::{CtfError, DecodeOptions, GadgetOptions, HashOptions, ProbeOptions, XorOptions, decode_jwt};
use serde_json::Value;
use wae::{CallContext, JsValue, Result};

use crate::{
    args::{encoded, failure, handle, respond, text},
    registry::with_engine,
};

fn probe_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<ProbeOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid ProbeOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.probe(&options)?))
}

fn hash_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<HashOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid HashOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.hash(&options)?))
}

fn decode_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<DecodeOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid DecodeOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.decode(&options)?))
}

fn xor_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<XorOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid XorOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.xor(&options)?))
}

fn gadgets_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = serde_json::from_str::<GadgetOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid GadgetOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.gadgets(&options)?))
}

pub(crate) fn jwt_report(token: &str) -> std::result::Result<Value, CtfError> {
    encoded(&decode_jwt(token)?)
}

pub(crate) fn binary_probe(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match probe_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_hash(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match hash_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_decode(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match decode_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_xor(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match xor_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn binary_gadgets(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match gadgets_report(handle, &options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn jwt_decode(ctx: CallContext) -> Result<JsValue> {
    let token = text(&ctx, 0)?;
    match jwt_report(&token) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}
