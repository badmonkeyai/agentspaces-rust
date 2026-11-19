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

//! The order and the budget of a fetch's answer (SPEC annex I.6, *The fetch* and *The budget*):
//! every present state before every tombstone and claims alone last, newest first by stamp, equal
//! stamps by the ids' UTF-8 bytes; a state travels with its entry's claim as one item; the answer
//! stops before the item that would pass the budget, and always carries its first item, however
//! large.

use agentspaces_wire::audit::{Offer, bounded_delta, offer_order};
use agentspaces_wire::cbor::{self, Map, Value};

fn state(id: &str, stamp: &str, pad: usize) -> Map {
    let mut record = Map::new();
    record.insert("entryId", id);
    record.insert("pad", "x".repeat(pad));
    let mut state = Map::new();
    state.insert("record", record);
    state.insert("leaseStamp", stamp);
    state
}

fn claim(id: &str, stamp: &str) -> Map {
    let mut inner = Map::new();
    inner.insert("entryId", id);
    inner.insert("stamp", stamp);
    let mut signed = Map::new();
    signed.insert("claim", inner);
    signed
}

/// The entry ids of a delta's states, in order, and its claims' keys.
fn carried(delta: &[u8]) -> (Vec<String>, Vec<String>) {
    let map = cbor::decode(delta).unwrap().into_map().unwrap();
    let states = map
        .get("states")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|state| {
            let record = state.get("record").unwrap();
            record
                .get("entryId")
                .and_then(Value::as_str)
                .unwrap()
                .to_owned()
        })
        .collect();
    let claims = map
        .get("claims")
        .and_then(Value::as_map)
        .unwrap()
        .keys()
        .map(|key| key.as_str().unwrap().to_owned())
        .collect();
    (states, claims)
}

#[test]
fn present_states_then_tombstones_then_claims_alone_newest_first() {
    let a = state("a", "1000:0:z", 0);
    let b = state("b", "3000:0:z", 0);
    let c = state("c", "2000:0:z", 0);
    let gone = state("gone", "9000:0:z", 0);
    let lone = claim("lone", "9999:0:z");
    let tie_b = state("tie-b", "2000:0:z", 0);
    let offers = vec![
        Offer {
            entry_id: "lone",
            state: None,
            present: false,
            claim: Some(&lone),
        },
        Offer {
            entry_id: "gone",
            state: Some(&gone),
            present: false,
            claim: None,
        },
        Offer {
            entry_id: "a",
            state: Some(&a),
            present: true,
            claim: None,
        },
        Offer {
            entry_id: "tie-b",
            state: Some(&tie_b),
            present: true,
            claim: None,
        },
        Offer {
            entry_id: "b",
            state: Some(&b),
            present: true,
            claim: None,
        },
        Offer {
            entry_id: "c",
            state: Some(&c),
            present: true,
            claim: None,
        },
    ];
    let mut sorted = offers.clone();
    sorted.sort_by(offer_order);
    let order: Vec<&str> = sorted.iter().map(|offer| offer.entry_id).collect();
    // A replacement's new revision (present) goes before the old one's cancel (a tombstone),
    // so a budget that splits them never leaves a reader seeing neither.
    assert_eq!(order, ["b", "c", "tie-b", "a", "gone", "lone"]);
    let (delta, left) = bounded_delta(offers, 1 << 20, true);
    assert_eq!(left, 0);
    let (states, claims) = carried(&delta.unwrap());
    assert_eq!(states, ["b", "c", "tie-b", "a", "gone"]);
    assert_eq!(claims, ["lone"]);
}

#[test]
fn a_state_and_its_claim_are_one_item() {
    let held = state("held", "5000:0:z", 0);
    let held_claim = claim("held", "5001:0:z");
    let other = state("other", "4000:0:z", 2100);
    let offers = vec![
        Offer {
            entry_id: "held",
            state: Some(&held),
            present: false,
            claim: Some(&held_claim),
        },
        Offer {
            entry_id: "other",
            state: Some(&other),
            present: true,
            claim: None,
        },
    ];
    // Room for the present state alone: the tombstone and its claim are left out together.
    let (delta, left) = bounded_delta(offers, 2200, true);
    assert_eq!(left, 1);
    let (states, claims) = carried(&delta.unwrap());
    assert_eq!(states, ["other"]);
    assert!(
        claims.is_empty(),
        "a claim never travels ahead of its entry's state"
    );
}

#[test]
fn the_first_item_always_travels_and_the_rest_waits() {
    let big = state("big", "9000:0:z", 70_000);
    let small = state("small", "1000:0:z", 10);
    let offers = vec![
        Offer {
            entry_id: "big",
            state: Some(&big),
            present: true,
            claim: None,
        },
        Offer {
            entry_id: "small",
            state: Some(&small),
            present: true,
            claim: None,
        },
    ];
    let (delta, left) = bounded_delta(offers.clone(), 4096, true);
    let (states, _) = carried(&delta.unwrap());
    assert_eq!(
        states,
        ["big"],
        "a state larger than the budget still travels alone"
    );
    assert_eq!(left, 1);
    // Not first in its answer: nothing fits, and everything is counted as left out.
    let (delta, left) = bounded_delta(offers, 4096, false);
    assert!(delta.is_none());
    assert_eq!(left, 2);
    let none: Vec<Offer<'_>> = Vec::new();
    assert_eq!(bounded_delta(none, 10, true), (None, 0));
    assert!(matches!(Value::from("x"), Value::Text(_)));
}
