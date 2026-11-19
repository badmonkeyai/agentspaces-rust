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

//! The computed cases of SPEC annex I.7 and I.9 (v0.1.35): `renew_clamp_cases` (§7.2's
//! `max(current, now + extension)`), `lapse_horizon_cases` (§7.3's horizons with the drift floor),
//! and `horizon_mode_cases` (the horizons under the legacy and the per-entry rule, one millisecond
//! before each horizon and at it). Each row is rebuilt from this crate's functions and compared
//! with the vector's row as a whole, every field and value exactly; the horizon cases are judged
//! over real state maps too, as the sweep and the door judge them.

mod common;

use agentspaces_wire::cbor::{Map, Value};
use agentspaces_wire::cbor_map;
use agentspaces_wire::horizon::{
    self, Rule, Standing, collectable, collectable_here, horizon, renewed_expiry,
};
use serde_json::{Value as Json, json};

fn rows(name: &str) -> &'static Vec<Json> {
    common::golden()[name]
        .as_array()
        .unwrap_or_else(|| panic!("{name} is a list"))
}

fn int(row: &Json, field: &str) -> i64 {
    row[field]
        .as_i64()
        .unwrap_or_else(|| panic!("{field} in {row}"))
}

fn text<'a>(row: &'a Json, field: &str) -> &'a str {
    row[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} in {row}"))
}

/// A state map of `standing` whose write lease expires at `expiry`, written by one node.
fn state_of(standing: Standing, expiry: i64) -> Map {
    let dot = cbor_map! { "replica" => "z6MkWriter", "counter" => 1 };
    let withdrawn = matches!(standing, Standing::Withdrawn | Standing::WithdrawnCompleted);
    let completed = matches!(standing, Standing::Completed | Standing::WithdrawnCompleted);
    let value = cbor_map! {
        "adds" => Value::Array(vec![dot.clone()]),
        "removes" => Value::Array(if withdrawn { vec![dot] } else { Vec::new() }),
        "leaseStamp" => "1799999000000:0:z6MkWriter",
        "leaseValue" => cbor_map! {
            "holder" => "z6MkWriter/rust",
            "expiresAtMillis" => expiry,
            "kind" => "WRITE",
        },
        "completed" => completed,
    };
    match value {
        Value::Map(map) => map,
        _ => unreachable!("a map"),
    }
}

#[test]
fn renew_clamp_cases_match_byte_for_byte() {
    let cases = rows("renew_clamp_cases");
    assert_eq!(cases.len(), 5, "annex I.7 names five renewals");
    let mut shorter = 0;
    for row in cases {
        let (current, now, extension) =
            (int(row, "current"), int(row, "now"), int(row, "extension"));
        let expiry = renewed_expiry(current, now, extension);
        let rebuilt = json!({
            "current": current, "now": now, "extension": extension, "expiry": expiry,
        });
        assert_eq!(&rebuilt, row);
        assert!(expiry >= current, "a renewal never shortens: {row}");
        if now + extension < current {
            shorter += 1;
        }
    }
    assert!(
        shorter >= 2,
        "the cases renew for less than the lease has left, zero included"
    );
}

#[test]
fn lapse_horizon_cases_match_byte_for_byte() {
    let cases = rows("lapse_horizon_cases");
    assert_eq!(cases.len(), 12, "annex I.7 names twelve horizons");
    for row in cases {
        let standing = Standing::parse(text(row, "state")).expect("a known state");
        let (expiry, max_lease) = (int(row, "expiry"), int(row, "max_lease"));
        let at = horizon(expiry, standing, max_lease, Rule::Legacy).expect("no overflow");
        let rebuilt = json!({
            "state": standing.as_str(), "expiry": expiry, "max_lease": max_lease, "horizon": at,
        });
        assert_eq!(&rebuilt, row);
        // The same horizon judged over a state, by the sweep's predicate.
        let state = state_of(standing, expiry);
        assert_eq!(Standing::of(&state), standing);
        assert!(
            !collectable(&state, at - 1, max_lease, Rule::Legacy),
            "{row}"
        );
        assert!(collectable(&state, at, max_lease, Rule::Legacy), "{row}");
        match standing {
            Standing::Present => assert!(at - expiry <= horizon::LAPSED_GRACE_MILLIS),
            Standing::Withdrawn => assert!(at - expiry >= horizon::WITHDRAWN_DRIFT_FLOOR_MILLIS),
            _ => {}
        }
    }
}

#[test]
fn horizon_mode_cases_match_byte_for_byte() {
    let cases = rows("horizon_mode_cases");
    assert_eq!(cases.len(), 64, "annex I.9 names 64 rows");
    for row in cases {
        let standing = Standing::parse(text(row, "state")).expect("a known state");
        let rule = Rule::parse(text(row, "mode")).expect("a known rule");
        let (expiry, max_lease, now) = (int(row, "expiry"), int(row, "max_lease"), int(row, "now"));
        let at = horizon(expiry, standing, max_lease, rule).expect("no overflow");
        let state = state_of(standing, expiry);
        let collects = collectable(&state, now, max_lease, rule);
        let rebuilt = json!({
            "state": standing.as_str(),
            "mode": rule.as_str(),
            "expiry": expiry,
            "max_lease": max_lease,
            "horizon": at,
            "now": now,
            "collectable": collects,
        });
        assert_eq!(&rebuilt, row);
        // A replica that vouches for the writer collects by the row; under the per-entry rule
        // one that does not keeps a withdrawal to the later of the two horizons.
        assert_eq!(
            collectable_here(&state, now, max_lease, rule, true),
            collects,
            "{row}"
        );
        if rule == Rule::PerEntry && standing == Standing::Withdrawn {
            let legacy = horizon(expiry, standing, max_lease, Rule::Legacy).expect("no overflow");
            assert_eq!(
                collectable_here(&state, now, max_lease, rule, false),
                now >= legacy.max(at),
                "{row}"
            );
        }
    }
}

#[test]
fn every_state_rule_and_lease_appears_twice() {
    let cases = rows("horizon_mode_cases");
    let mut seen = std::collections::BTreeMap::new();
    for row in cases {
        let key = (
            text(row, "state").to_owned(),
            text(row, "mode").to_owned(),
            int(row, "max_lease"),
        );
        *seen.entry(key).or_insert(0) += 1;
        let at = int(row, "horizon");
        let now = int(row, "now");
        assert!(now == at || now == at - 1, "{row}");
    }
    assert_eq!(seen.len(), 32);
    assert!(seen.values().all(|count| *count == 2));
}
