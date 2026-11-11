// Copyright 2026 Bad Monkey, Inc.
// Author: Al Baker
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The wire encoding vectors of SPEC annex I (`tests/wire-encoding-vectors.json`, a byte-identical
//! copy of the core repository's `tools/wire-encoding/vectors.json`): every vector goes through
//! this crate's reader for its carrier, and the reader's verdict must equal the vector's.
//!
//! - `frame`: the frame decoder ([`decode_frame_detailed`], the item rules, `ver`, the record
//!   rules of `WireCodec.Signed` and `Envelope`, the canonical-bytes check, the signature) and the
//!   body of its kind ([`decode_body`]); a body that does not decode makes the frame undecodable.
//! - `space-delta`: the delta decoder ([`decode_delta`]) and then the record and claim rules: the
//!   record signature, the state signature for its issuer, and the claim's signature.
//! - `signed-peer-ad`: the stored-ad path of the `peers` stream ([`verify_signed_peer_ad`]).
//! - `document`: the strict document decoder ([`cbor::decode`], S1 to S12).
//! - `pref`: a persistent-tree ref as its record schema reads it ([`schema::decode`], `PRef` with
//!   rule R1 on `attrs`). This peer reads no persistent trees, but every `pref` vector is judged
//!   by the record rules alone, so the decoder decides each.
//! - `beacon-document`: the beacon reader ([`BeaconDocument::parse`], [`verify_document`]); an
//!   accepted signed document must name the vector's signer.
//!
//! `accept` means the reader takes the carrier; `refuse-undecodable` (and `refuse` for a beacon
//! document) means it drops it, counts it as undecodable, and strikes nobody.

mod common;

use agentspaces_wire::ads::verify_signed_peer_ad;
use agentspaces_wire::beacon::{BeaconDocument, verify_document};
use agentspaces_wire::bodies::decode_body;
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::envelope::{Auth, decode_frame_detailed};
use agentspaces_wire::records::{
    decode_delta, verify_claim_signature, verify_record, verify_state_signature,
};
use agentspaces_wire::schema;
use std::collections::BTreeMap;
use std::sync::OnceLock;

fn vectors() -> &'static serde_json::Value {
    static V: OnceLock<serde_json::Value> = OnceLock::new();
    V.get_or_init(|| {
        serde_json::from_str(include_str!("wire-encoding-vectors.json"))
            .expect("wire-encoding-vectors.json parses")
    })
}

/// What the reader of a carrier did with it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Accept,
    Refuse,
}

/// A frame: decoded, verified under the key it carries, and its body decoded for its kind.
fn frame(bytes: &[u8]) -> Verdict {
    let Some((env, auth)) = decode_frame_detailed(bytes, None, None) else {
        return Verdict::Refuse;
    };
    let kind = env.get("kind").and_then(Value::as_str).unwrap_or_default();
    let body = env
        .get("body")
        .and_then(Value::as_bytes)
        .unwrap_or_default();
    if auth == Auth::Signed && decode_body(kind, body).is_some() {
        Verdict::Accept
    } else {
        Verdict::Refuse
    }
}

/// A space delta: decoded, then its state's record and transition and its claim verified.
fn space_delta(bytes: &[u8]) -> Verdict {
    let Some(delta) = decode_delta(bytes) else {
        return Verdict::Refuse;
    };
    if let Some((_, signed)) = &delta.claim
        && !verify_claim_signature(&Value::Map(signed.clone()))
    {
        return Verdict::Refuse;
    }
    if let Some(state) = &delta.state
        && !state_verifies(state)
    {
        return Verdict::Refuse;
    }
    Verdict::Accept
}

/// Whether a state's record and its transition verify for the record's issuer (no vector holds
/// a completion, whose party is a claim holder).
fn state_verifies(state: &Map) -> bool {
    let Some(record) = state.get("record").and_then(Value::as_map) else {
        return false;
    };
    let key = state
        .get("issuerPublicKey")
        .and_then(Value::as_bytes)
        .unwrap_or_default();
    let issuer = record
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let attested = state
        .get("agentCertificate")
        .is_some_and(|certificate| !certificate.is_null());
    verify_record(record, key, state.get("agentCertificate"), 0)
        && verify_state_signature(state, issuer, key, attested, 0)
}

/// A beacon document: parsed and its signature verified; an accepted signed document must name
/// `signer`.
fn beacon(bytes: &[u8], signer: Option<&str>) -> Verdict {
    let Ok(doc) = BeaconDocument::parse(bytes) else {
        return Verdict::Refuse;
    };
    match verify_document(&doc, None) {
        Ok(verified) if verified.as_deref() == signer => Verdict::Accept,
        _ => Verdict::Refuse,
    }
}

#[test]
fn every_annex_i_vector_gets_its_verdict() {
    let meta = &vectors()["meta"];
    assert!(
        meta["verdicts"]
            .as_str()
            .is_some_and(|v| v.contains("refuse-undecodable"))
    );
    let list = vectors()["vectors"].as_array().expect("a vector list");
    assert_eq!(list.len(), 205, "annex I.2 lists 205 vectors");
    let mut tally: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut disagreements = Vec::new();
    for vector in list {
        let id = vector["id"].as_str().expect("an id");
        let carrier = vector["carrier"].as_str().expect("a carrier");
        let expected = match vector["verdict"].as_str().expect("a verdict") {
            "accept" => Verdict::Accept,
            "refuse" | "refuse-undecodable" => Verdict::Refuse,
            other => panic!("{id}: unknown verdict {other}"),
        };
        let bytes = hex::decode(vector["hex"].as_str().expect("hex")).expect("hex decodes");
        let got = match carrier {
            "frame" => frame(&bytes),
            "space-delta" => space_delta(&bytes),
            "signed-peer-ad" => match verify_signed_peer_ad(&bytes) {
                Some(_) => Verdict::Accept,
                None => Verdict::Refuse,
            },
            "document" => match cbor::decode(&bytes) {
                Ok(_) => Verdict::Accept,
                Err(_) => Verdict::Refuse,
            },
            "pref" => match schema::decode(&bytes, "PRef") {
                Some(_) => Verdict::Accept,
                None => Verdict::Refuse,
            },
            "beacon-document" => beacon(&bytes, vector["signer"].as_str()),
            other => panic!("{id}: unknown carrier {other}"),
        };
        let entry = tally.entry(carrier).or_default();
        entry.1 += 1;
        if got == expected {
            entry.0 += 1;
        } else {
            disagreements.push(format!(
                "{id} ({carrier}, {}): expected {expected:?}, got {got:?}: {}",
                vector["rule"].as_str().unwrap_or_default(),
                vector["why"].as_str().unwrap_or_default()
            ));
        }
    }
    let agree: usize = tally.values().map(|(agree, _)| agree).sum();
    for (carrier, (agree, total)) in &tally {
        println!("{carrier}: {agree} of {total} agree");
    }
    println!("annex I: {agree} of {} vectors agree", list.len());
    assert!(
        disagreements.is_empty(),
        "{} disagreements:\n{}",
        disagreements.len(),
        disagreements.join("\n")
    );
}

#[test]
fn every_accepted_cbor_carrier_re_encodes_to_its_bytes() {
    // Rule F3: an accepted carrier is exactly the encoding of what it decodes to.
    for vector in vectors()["vectors"].as_array().expect("a vector list") {
        let carrier = vector["carrier"].as_str().expect("a carrier");
        if vector["verdict"] != "accept" || carrier == "beacon-document" || carrier == "document" {
            continue;
        }
        let bytes = hex::decode(vector["hex"].as_str().expect("hex")).expect("hex decodes");
        assert!(schema::load_canonical(&bytes).is_some(), "{}", vector["id"]);
    }
}

#[test]
fn the_inputs_v0_1_31_made_refusals_are_refused() {
    // SPEC §15, v0.1.31: four inputs that earlier text accepted.
    for input in [
        "7f6361626363646566ff",
        "c24180",
        "c341ff",
        "c4823a7fffffff01",
    ] {
        let bytes = hex::decode(input).expect("hex");
        assert!(cbor::decode(&bytes).is_err(), "{input}");
    }
}
