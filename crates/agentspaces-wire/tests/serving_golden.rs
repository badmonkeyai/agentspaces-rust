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

//! The serving half of anti-entropy against the golden vectors Java produced: the state hash and
//! the claim hash a `ReplicatedSpace` digest names (`space_state_hash`, `space_claim_hash`), so
//! a Rust listening peer and a Java member agree on what each lacks, and the digest and delta
//! shapes built from them.

mod common;

use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::serving::{
    claim_hash, claim_line, digest_lines, names_line, space_digest, state_hash, state_line,
    sync_delta,
};
use common::{hex, s};

/// The decoded map of a golden CBOR vector.
fn map_of(name: &str) -> Map {
    cbor::decode(&hex(name))
        .ok()
        .and_then(Value::into_map)
        .unwrap_or_else(|| panic!("{name} is a CBOR map"))
}

#[test]
fn the_state_hash_is_java_s() {
    let delta = map_of("delta_cbor");
    let state = delta
        .get("state")
        .and_then(Value::as_map)
        .expect("the delta carries a state");
    assert_eq!(state_hash(state), s("space_state_hash"));
    assert_eq!(
        state_line("e1", state),
        format!("e:e1={}", s("space_state_hash"))
    );
}

#[test]
fn the_claim_hash_is_java_s() {
    let delta = map_of("claim_delta_cbor");
    let signed = delta
        .get("claim")
        .and_then(Value::as_map)
        .expect("the delta carries a signed claim");
    let claim = signed
        .get("claim")
        .and_then(Value::as_map)
        .expect("a signed claim holds its claim");
    assert_eq!(claim_hash(claim), s("space_claim_hash"));
    assert_eq!(
        claim_line("e1", signed),
        format!("c:e1={}", s("space_claim_hash"))
    );
}

#[test]
fn a_digest_names_what_its_delta_then_leaves_out() {
    let delta = map_of("delta_cbor");
    let state = delta.get("state").and_then(Value::as_map).expect("state");
    let claim_delta = map_of("claim_delta_cbor");
    let signed = claim_delta
        .get("claim")
        .and_then(Value::as_map)
        .expect("claim");
    let digest = space_digest([("e1", state)].into_iter(), [("e1", signed)].into_iter());
    let text = String::from_utf8(digest.clone()).expect("a digest is text");
    assert_eq!(
        text,
        format!(
            "c:e1={}\ne:e1={}\n",
            s("space_claim_hash"),
            s("space_state_hash")
        )
    );
    let lines = digest_lines(&digest);
    assert!(names_line(&lines, &state_line("e1", state)));
    assert!(names_line(&lines, &claim_line("e1", signed)));
    assert!(!names_line(&lines, &state_line("e2", state)));
    // The sync delta of what an empty digest lacks reads back as Java's `SyncDelta`.
    let bytes = sync_delta(&[state], &[("e1", signed)]);
    let decoded = agentspaces_wire::records::decode_sync_delta(&bytes).expect("a sync delta");
    assert_eq!(decoded.states.len(), 1);
    assert_eq!(decoded.claims.len(), 1);
}
