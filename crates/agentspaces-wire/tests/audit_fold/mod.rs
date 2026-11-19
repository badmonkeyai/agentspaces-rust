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

//! The Rust fold of `audit-vectors.json` (SPEC annex I.6): every set's audited lines, count,
//! stream hash and listed nodes, and every descent's exchanges, bodies and fetched ids, computed
//! by this crate's trie, partner answers, and asker, and judged against the vectors row by row.
//! The rows are named as the conformance harness names them (`set:<name>:lines`,
//! `descent:<name>:exchange:<k>:bodies`, ...), so the harness's table reads this fold's output
//! beside Java's and the independent Python fold's.
//!
//! Shared by `tests/audit_vectors.rs` and the `audit_conformance` example.
#![allow(dead_code)]

use std::collections::BTreeMap;

use agentspaces_wire::audit::{self, DigestBody, TreeForm, TreeNode};
use agentspaces_wire::reconcile::{Asker, RootVerdict, Sessions};
use agentspaces_wire::trie::{AuditTrie, Path, SlotSource};
use serde_json::{Value as Json, json};

/// The stream every descent's bodies name.
pub const STREAM: &str = "space:tasks";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn path_of(hex_path: &str) -> Path {
    let nibbles: Vec<u8> = hex_path
        .chars()
        .map(|c| c.to_digit(16).expect("a hex nibble") as u8)
        .collect();
    Path::from_nibbles(&nibbles).expect("a path")
}

/// The trie of a vector set's slots.
pub fn trie_of(set: &Json) -> AuditTrie {
    let slots = set["slots"].as_array().expect("slots");
    let mut trie = AuditTrie::new();
    for slot in slots {
        let acks: Vec<String> = slot["acks"]
            .as_array()
            .expect("acks")
            .iter()
            .map(|ack| ack.as_str().expect("an ack line").to_owned())
            .collect();
        let source = SlotSource {
            id: slot["id"].as_str().expect("an id"),
            state: slot["state"].as_str(),
            claim: slot["claim"].as_str(),
            dropped: slot["dropped"].as_str(),
            lapsed: slot["lapsed"].as_bool().expect("lapsed"),
            acks: &acks,
        };
        trie.put(source.id, source.lines());
    }
    trie
}

fn node_json(node: &TreeNode) -> Json {
    let path: String = node
        .path
        .iter()
        .map(|n| char::from_digit(u32::from(*n), 16).expect("a nibble"))
        .collect();
    match &node.form {
        TreeForm::Count(count) => json!({"path": path, "count": count}),
        TreeForm::Nodes(nodes) => json!({"path": path, "nodes": hex(nodes)}),
        TreeForm::Lines(lines) => json!({"path": path, "lines": lines}),
    }
}

fn tree_body(nodes: &[TreeNode], budget: Option<i64>) -> String {
    hex(&DigestBody {
        tree: Some(vec![(STREAM.to_owned(), nodes.to_vec())]),
        budget,
        ..DigestBody::default()
    }
    .encode())
}

/// One exchange of a descent, as the vectors write it.
struct Exchange {
    requests: Vec<Json>,
    answers: Vec<Json>,
    request_body: String,
    answer_body: String,
}

/// The descent of annex I.6 between two sets, run through the crate's own partner (sessions and
/// answers) and asker: its exchanges and the sorted ids the asker fetches.
fn descent(
    asker_trie: &mut AuditTrie,
    partner_trie: &mut AuditTrie,
    budget: i64,
) -> (Vec<Exchange>, Vec<String>) {
    let mut exchanges = Vec::new();
    let mut ids: Vec<String> = Vec::new();
    let asker_hash = asker_trie.stream_hash();
    if asker_hash == partner_trie.stream_hash() {
        return (exchanges, ids);
    }
    let mut sessions = Sessions::default();
    let mut asker = Asker::new();
    asker.opening("partner", 0);
    let opening = DigestBody {
        hashes: Some(vec![(STREAM.to_owned(), asker_hash.to_vec())]),
        ..DigestBody::default()
    };
    let root = audit::answer_root(partner_trie);
    if matches!(root.form, TreeForm::Nodes(_)) {
        assert_eq!(
            sessions.open_root("asker", STREAM, 0),
            RootVerdict::Answer { capped: false }
        );
    }
    exchanges.push(Exchange {
        requests: Vec::new(),
        answers: vec![node_json(&root)],
        request_body: hex(&opening.encode()),
        answer_body: tree_body(std::slice::from_ref(&root), None),
    });
    let mut step = asker.on_answers("partner", STREAM, &[root], asker_trie, 0);
    loop {
        ids.extend(step.ids.iter().cloned());
        if step.requests.is_empty() {
            break;
        }
        assert!(
            sessions.request("asker", STREAM, 0).is_ok(),
            "a session is open"
        );
        let (answers, repeated) =
            audit::answer_requests(partner_trie, STREAM, &step.requests, Some(budget));
        assert!(!repeated);
        exchanges.push(Exchange {
            requests: step.requests.iter().map(node_json).collect(),
            answers: answers.iter().map(node_json).collect(),
            request_body: tree_body(&step.requests, Some(budget)),
            answer_body: tree_body(&answers, None),
        });
        step = asker.on_answers("partner", STREAM, &answers, asker_trie, 0);
        assert!(step.refusals.is_empty(), "{:?}", step.refusals);
    }
    ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    ids.dedup();
    (exchanges, ids)
}

/// Every row of the vectors, `"agree"` or `"disagree: <what>"`.
pub fn rows(doc: &Json) -> BTreeMap<String, String> {
    let mut rows = BTreeMap::new();
    let mut judge = |row: String, ok: bool, what: String| {
        rows.insert(
            row,
            if ok {
                "agree".to_owned()
            } else {
                format!("disagree: {what}")
            },
        );
    };
    let budget = doc["parameters"]["budget_default"]
        .as_i64()
        .expect("a budget");
    let mut sets: BTreeMap<String, AuditTrie> = BTreeMap::new();
    for set in doc["sets"].as_array().expect("sets") {
        let name = set["name"].as_str().expect("a name");
        let mut trie = trie_of(set);
        let lines: Vec<Json> = trie.lines().into_iter().map(Json::from).collect();
        judge(
            format!("set:{name}:lines"),
            Json::from(lines) == set["lines"],
            "audited lines".into(),
        );
        judge(
            format!("set:{name}:count"),
            Some(trie.count()) == set["count"].as_u64(),
            format!("count {}", trie.count()),
        );
        let stream = hex(&trie.stream_hash());
        judge(
            format!("set:{name}:stream"),
            Some(stream.as_str()) == set["stream_hash"].as_str(),
            stream.clone(),
        );
        for node in set["nodes"].as_array().expect("nodes") {
            let path = node["path"].as_str().expect("a path");
            let mine = trie.node(&path_of(path));
            let fingerprint = mine.fingerprint.map(|fp| hex(&fp));
            let ok = Some(mine.kind.as_str()) == node["kind"].as_str()
                && Some(mine.count) == node["count"].as_u64()
                && fingerprint.as_deref() == node["fingerprint"].as_str()
                && Some(hex(&mine.preimage).as_str()) == node["preimage"].as_str();
            let label = if path.is_empty() { "." } else { path };
            judge(
                format!("set:{name}:node:{label}"),
                ok,
                format!(
                    "{} {} {}",
                    mine.kind.as_str(),
                    mine.count,
                    fingerprint.unwrap_or("-".into())
                ),
            );
        }
        sets.insert(name.to_owned(), trie);
    }
    for vector in doc["descents"].as_array().expect("descents") {
        let name = vector["name"].as_str().expect("a name");
        let mut asker = sets[vector["asker"].as_str().expect("an asker")].clone();
        let mut partner = sets[vector["partner"].as_str().expect("a partner")].clone();
        let (exchanges, ids) = descent(&mut asker, &mut partner, budget);
        let theirs = vector["exchanges"].as_array().expect("exchanges");
        judge(
            format!("descent:{name}:exchanges"),
            exchanges.len() == theirs.len(),
            format!("{} exchanges", exchanges.len()),
        );
        for (k, (mine, theirs)) in exchanges.iter().zip(theirs).enumerate() {
            let same = Json::from(mine.requests.clone()) == theirs["requests"]
                && Json::from(mine.answers.clone()) == theirs["answers"];
            judge(
                format!("descent:{name}:exchange:{k}"),
                same,
                "nodes differ".into(),
            );
            let bodies = Some(mine.request_body.as_str()) == theirs["request_body_cbor"].as_str()
                && Some(mine.answer_body.as_str()) == theirs["answer_body_cbor"].as_str();
            judge(
                format!("descent:{name}:exchange:{k}:bodies"),
                bodies,
                "body bytes differ".into(),
            );
        }
        let ids_json: Vec<Json> = ids.iter().map(|id| Json::from(id.as_str())).collect();
        judge(
            format!("descent:{name}:ids"),
            Json::from(ids_json) == vector["ids"],
            format!("ids {:?}", &ids[..ids.len().min(5)]),
        );
    }
    rows
}
