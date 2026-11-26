//! Solver operations: one options JSON in, one serialized report out.
//!
//! Caesar, XOR, digests, decoders, gadgets, JWT, URL and cyclic patterns are
//! forwarded to `open-ctf-domain`; JWT, URL and cyclic need no file handle.

use open_ctf_domain::{
    CaesarOptions, CtfError, CyclicOptions, DecodeOptions, GadgetOptions, HashOptions, XorOptions, cyclic, decode_jwt,
    parse_url,
};
use serde_json::Value;
use wae::{CallContext, JsValue, Result};

use crate::{
    error::{encoded, failure, handle, respond, text},
    registry::with_engine,
};

fn hash_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<HashOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid HashOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.hash(&options)?))
}

fn decode_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<DecodeOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid DecodeOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.decode(&options)?))
}

fn xor_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<XorOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid XorOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.xor(&options)?))
}

fn gadgets_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<GadgetOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid GadgetOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.gadgets(&options)?))
}

fn caesar_report(handle: u64, options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<CaesarOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid CaesarOptions: {error}")))?;
    with_engine(handle, |engine| encoded(&engine.caesar(&options)?))
}

pub(crate) fn jwt_report(token: &str) -> std::result::Result<Value, CtfError> {
    let report = decode_jwt(token)?;
    // The header and payload are caller data: their keys are never rewritten.
    Ok(serde_json::json!({
        "header": report.header,
        "payload": report.payload,
        "algorithm": report.algorithm,
        "unsigned": report.unsigned,
        "signatureHex": report.signature_hex,
        "warnings": report.warnings,
    }))
}

pub(crate) fn url_report(input: &str) -> std::result::Result<Value, CtfError> {
    encoded(&parse_url(input)?)
}

pub(crate) fn cyclic_report(options_json: &str) -> std::result::Result<Value, CtfError> {
    let options = crate::dto::request::<CyclicOptions>(options_json)
        .map_err(|error| CtfError::parse(format!("invalid CyclicOptions: {error}")))?;
    encoded(&cyclic(&options)?)
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

pub(crate) fn binary_caesar(ctx: CallContext) -> Result<JsValue> {
    let handle = handle(&ctx, 0)?;
    let options = text(&ctx, 1)?;
    match caesar_report(handle, &options) {
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

pub(crate) fn url_parse(ctx: CallContext) -> Result<JsValue> {
    let input = text(&ctx, 0)?;
    match url_report(&input) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}

pub(crate) fn cyclic_run(ctx: CallContext) -> Result<JsValue> {
    let options = text(&ctx, 0)?;
    match cyclic_report(&options) {
        Ok(value) => respond(&ctx, &value),
        Err(error) => Err(failure(error)),
    }
}
