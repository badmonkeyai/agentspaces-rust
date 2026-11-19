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

//! The conformance check of `audit-vectors.json` (SPEC annex I.6, I.8): this crate's trie,
//! partner answers, and asker fold every set and every descent, and every row agrees with the
//! vector generator's. The `audit_conformance` example writes the same rows for the
//! conformance harness's table.

mod audit_fold;

use std::sync::OnceLock;

fn vectors() -> &'static serde_json::Value {
    static V: OnceLock<serde_json::Value> = OnceLock::new();
    V.get_or_init(|| {
        serde_json::from_str(include_str!("audit-vectors.json")).expect("audit-vectors.json parses")
    })
}

#[test]
fn every_set_and_descent_agrees_with_the_vectors() {
    let doc = vectors();
    let rows = audit_fold::rows(doc);
    let sets = doc["sets"].as_array().unwrap();
    let descents = doc["descents"].as_array().unwrap();
    assert_eq!(sets.len(), 32);
    assert_eq!(descents.len(), 9);
    let nodes: usize = sets
        .iter()
        .map(|set| set["nodes"].as_array().unwrap().len())
        .sum();
    let exchanges: usize = descents
        .iter()
        .map(|descent| descent["exchanges"].as_array().unwrap().len())
        .sum();
    // Three rows per set and one per node; two per descent and two per exchange.
    assert_eq!(
        rows.len(),
        3 * sets.len() + nodes + 2 * descents.len() + 2 * exchanges
    );
    assert_eq!(rows.len(), 1255, "the harness's table counts 1255 rows");
    let bad: Vec<(&String, &String)> = rows
        .iter()
        .filter(|(_, verdict)| *verdict != "agree")
        .collect();
    assert!(
        bad.is_empty(),
        "{} rows disagree: {:?}",
        bad.len(),
        &bad[..bad.len().min(10)]
    );
}

#[test]
fn the_parameters_are_the_crates_own() {
    use agentspaces_wire::{audit, trie};
    let parameters = &vectors()["parameters"];
    assert_eq!(parameters["fanout"], trie::FANOUT);
    assert_eq!(parameters["leaf_max"], trie::LEAF_MAX);
    assert_eq!(parameters["fingerprint_bytes"], trie::FINGERPRINT_BYTES);
    assert_eq!(parameters["child_bytes"], trie::CHILD_BYTES);
    assert_eq!(
        parameters["inner_preimage_bytes"],
        trie::INNER_PREIMAGE_BYTES
    );
    assert_eq!(parameters["path_max"], audit::PATH_MAX);
    assert_eq!(parameters["tree_nodes_max"], audit::TREE_NODES_MAX);
    assert_eq!(parameters["ids_max"], audit::IDS_MAX);
    assert_eq!(parameters["budget_default"], audit::BUDGET_DEFAULT);
    let empty: String = trie::EMPTY_STREAM_HASH
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(parameters["empty_stream_hash"], empty.as_str());
}
