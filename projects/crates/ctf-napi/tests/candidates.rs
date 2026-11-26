//! Node-API candidate DTO contract: request defaults, response key names,
//! source enum values and the rejection path for an unknown solver.

use open_ctf_domain::{Candidate, CandidateSet};
use open_ctf_napi::dto::{CandidateRequest, CandidateResponse, CandidateSource};

fn candidate(source: &str, label: &str, value: &str, score: f64) -> Candidate {
    Candidate { source: source.to_string(), label: label.to_string(), value: value.to_string(), score }
}

#[test]
fn request_defaults_and_explicit_fields_keep_the_js_names() {
    let empty = CandidateRequest::parse("{}").expect("empty request");
    assert_eq!(empty.offset, 0);
    assert_eq!(empty.length, None);
    assert_eq!(empty.limit, 5);

    let explicit = CandidateRequest::parse(r#"{"offset":16,"length":null,"limit":2}"#).expect("explicit request");
    assert_eq!(explicit.offset, 16);
    assert_eq!(explicit.length, None);
    assert_eq!(explicit.limit, 2);

    let ranged = CandidateRequest::parse(r#"{"offset":4,"length":8}"#).expect("ranged request");
    assert_eq!(ranged.length, Some(8));
    assert_eq!(ranged.limit, 5, "an omitted limit keeps the documented default");
}

#[test]
fn response_maps_every_item_and_freezes_the_keys_and_enum_values() {
    let mut set = CandidateSet::new();
    set.push(candidate("xor", "key 0x42", "CTF{xor}", 2.5));
    set.push(candidate("caesar", "shift 13", "CTF{caesar}", 1.25));

    let response = CandidateResponse::from_set(&set).expect("map candidates");
    let value = serde_json::to_value(&response).expect("serialize response");

    let items = value["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["source"], "xor");
    assert_eq!(items[0]["label"], "key 0x42");
    assert_eq!(items[0]["value"], "CTF{xor}");
    assert_eq!(items[0]["score"], 2.5);
    assert_eq!(items[1]["source"], "caesar");

    let mut keys: Vec<&str> = items[0].as_object().expect("item object").keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["label", "score", "source", "value"]);
    assert_eq!(value.as_object().expect("response object").keys().map(String::as_str).collect::<Vec<_>>(), vec!["items"]);
}

#[test]
fn unknown_solver_sources_are_rejected_with_the_stable_code() {
    let mut set = CandidateSet::new();
    set.push(candidate("rot13", "shift 13", "unexpected", 1.0));

    let error = CandidateResponse::from_set(&set).expect_err("unknown source must not map");
    assert_eq!(error.code(), "binary/unsupported");
}

#[test]
fn source_enum_serializes_as_the_published_lowercase_values() {
    assert_eq!(serde_json::to_value(CandidateSource::Xor).expect("xor"), "xor");
    assert_eq!(serde_json::to_value(CandidateSource::Caesar).expect("caesar"), "caesar");
}
