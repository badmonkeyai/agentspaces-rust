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

//! The golden vectors of SPEC annex I.6 (`DIGEST{tree, ids, budget}`, `TreeNode`,
//! `PULL_RESP.remainder`) and of annex I.7 (the probe bodies of §5.2 with `hashes` and `have`),
//! byte for byte both ways: each carrier to accept decodes, re-encodes to the bytes Java wrote,
//! and is rebuilt from its parts (the audit's answers from the trie itself); each carrier to
//! refuse is refused for its own form rule, by the named reader and by every reader of its frame
//! kind, although its bytes are otherwise well formed.

mod common;

use agentspaces_wire::audit::{
    self, BUDGET_DEFAULT, DigestBody, FormError, PullRespBody, TreeForm, TreeNode,
};
use agentspaces_wire::bodies::{
    KIND_ACK, KIND_DIGEST, KIND_PING, KIND_PULL_RESP, ack_body, decode_body, parse_ack,
    parse_digest, parse_ping, parse_pull_resp, pull_resp_body,
};
use agentspaces_wire::cbor::{self, Map, Value};
use agentspaces_wire::envelope::decode_frame;
use agentspaces_wire::schema;
use agentspaces_wire::trie::{AuditTrie, NodeKind, Path, SlotSource};
use common::hex;

const STREAM: &str = "space:tasks";

fn digest(name: &str) -> DigestBody {
    audit::parse_digest(&hex(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn tree_of(body: &DigestBody) -> &[TreeNode] {
    let tree = body.tree.as_ref().expect("a tree");
    assert_eq!(tree.len(), 1);
    assert_eq!(tree[0].0, STREAM);
    &tree[0].1
}

fn body_of_frame(name: &str) -> Vec<u8> {
    let env = decode_frame(&hex(name)).expect("the Java frame verifies");
    env.get("body").and_then(Value::as_bytes).unwrap().to_vec()
}

// ------------------------------------------------------------------------- carriers to accept

#[test]
fn a_request_of_two_nodes_under_a_budget_round_trips() {
    let body = digest("digest_tree_request_body_cbor");
    assert_eq!(body.digests, None);
    assert_eq!(body.budget, Some(BUDGET_DEFAULT));
    assert!(body.carries_audit());
    let nodes = tree_of(&body);
    assert_eq!(nodes.len(), 2);
    let rebuilt = DigestBody {
        tree: Some(vec![(
            STREAM.to_owned(),
            vec![
                TreeNode::request(&Path::from_nibbles(&[0x0a]).unwrap(), 12),
                TreeNode::request(&Path::from_nibbles(&[0x0a, 0x03]).unwrap(), 40),
            ],
        )]),
        budget: Some(BUDGET_DEFAULT),
        ..DigestBody::default()
    };
    assert_eq!(rebuilt, body);
    assert_eq!(rebuilt.encode(), hex("digest_tree_request_body_cbor"));
    // The general reader takes it too, and its digests read as none.
    assert_eq!(
        parse_digest(&hex("digest_tree_request_body_cbor")),
        Some(Map::new())
    );
}

#[test]
fn the_root_of_e00_to_e32_answers_with_its_nodes() {
    let ids: Vec<String> = (0..33).map(|i| format!("e{i:02}")).collect();
    let mut trie = AuditTrie::from_sources(ids.iter().map(|id| SlotSource {
        id,
        state: Some("0"),
        ..SlotSource::default()
    }));
    let root = audit::answer_root(&mut trie);
    assert!(matches!(&root.form, TreeForm::Nodes(nodes) if nodes.len() == 384));
    let rebuilt = DigestBody {
        tree: Some(vec![(STREAM.to_owned(), vec![root])]),
        ..DigestBody::default()
    };
    assert_eq!(rebuilt.encode(), hex("digest_tree_nodes_body_cbor"));
    assert_eq!(digest("digest_tree_nodes_body_cbor"), rebuilt);
}

#[test]
fn a_leaf_of_lines_and_an_empty_node_answer_as_lines() {
    let mut trie = AuditTrie::new();
    trie.put("a", vec!["e:a=1".into(), "c:a=2".into()]);
    let requests = [
        TreeNode::request(&Path::from_nibbles(&[0x0c]).unwrap(), 0),
        TreeNode::request(&Path::from_nibbles(&[0x05]).unwrap(), 0),
    ];
    let (answers, repeated) = audit::answer_requests(&mut trie, STREAM, &requests, None);
    assert!(!repeated);
    assert_eq!(answers[0].form, TreeForm::Lines("c:a=2\ne:a=1".into()));
    assert_eq!(answers[1].form, TreeForm::Lines(String::new()));
    let rebuilt = DigestBody {
        tree: Some(vec![(STREAM.to_owned(), answers)]),
        ..DigestBody::default()
    };
    assert_eq!(rebuilt.encode(), hex("digest_tree_lines_body_cbor"));
    assert_eq!(digest("digest_tree_lines_body_cbor"), rebuilt);
}

#[test]
fn a_fetch_of_two_ids_and_its_signed_frame_round_trip() {
    let body = digest("digest_ids_body_cbor");
    let rebuilt = DigestBody {
        ids: Some(vec![(
            STREAM.to_owned(),
            vec![
                "11111111-2222-3333-4444-555555555555".to_owned(),
                "entry-150".to_owned(),
            ],
        )]),
        budget: Some(65_536),
        ..DigestBody::default()
    };
    assert_eq!(body, rebuilt);
    assert_eq!(rebuilt.encode(), hex("digest_ids_body_cbor"));
    let framed = body_of_frame("digest_ids_frame_cbor");
    assert_eq!(framed, hex("digest_ids_body_cbor"));
    assert!(decode_body(KIND_DIGEST, &framed).is_some());
}

#[test]
fn a_budgeted_get_space_round_trips() {
    let body = digest("digest_get_space_budget_body_cbor");
    let rebuilt = DigestBody {
        digests: Some(vec![(STREAM.to_owned(), Vec::new())]),
        budget: Some(BUDGET_DEFAULT),
        ..DigestBody::default()
    };
    assert_eq!(body, rebuilt);
    assert_eq!(rebuilt.encode(), hex("digest_get_space_budget_body_cbor"));
    let digests = parse_digest(&hex("digest_get_space_budget_body_cbor")).unwrap();
    assert_eq!(digests.get(STREAM).and_then(Value::as_bytes), Some(&[][..]));
}

#[test]
fn a_pull_resp_with_and_without_a_remainder_round_trips() {
    let plain = audit::parse_pull_resp(&hex("pull_resp_body_cbor")).unwrap();
    assert_eq!(plain.remainder, None);
    assert_eq!(plain.deltas.len(), 1);
    assert_eq!(plain.encode(), hex("pull_resp_body_cbor"));
    let mut deltas = Map::new();
    deltas.insert(STREAM, plain.deltas[0].1.clone());
    assert_eq!(pull_resp_body(&deltas), hex("pull_resp_body_cbor"));
    // The delta is a sync delta of one state, as every member answers it.
    let sync = schema::decode_map(&plain.deltas[0].1, "SpaceWire.SyncDelta").expect("a sync delta");
    assert_eq!(
        sync.get("states")
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(1)
    );

    let budgeted = audit::parse_pull_resp(&hex("pull_resp_remainder_body_cbor")).unwrap();
    assert_eq!(budgeted.remainder, Some(vec![(STREAM.to_owned(), 3)]));
    assert_eq!(budgeted.remainder_of(STREAM), 3);
    let rebuilt = PullRespBody {
        deltas: plain.deltas.clone(),
        remainder: Some(vec![(STREAM.to_owned(), 3)]),
    };
    assert_eq!(rebuilt.encode(), hex("pull_resp_remainder_body_cbor"));
    // The general reader reads the deltas of both.
    assert!(parse_pull_resp(&hex("pull_resp_remainder_body_cbor")).is_some());
    assert!(decode_body(KIND_PULL_RESP, &hex("pull_resp_remainder_body_cbor")).is_some());
}

// ------------------------------------------------------------------------- carriers to refuse

#[test]
fn each_malformed_carrier_is_refused_for_its_own_rule() {
    let digests = [
        ("adv_digest_tree_path_nibble_body", FormError::PathNibble),
        ("adv_digest_tree_path_long_body", FormError::PathLong),
        ("adv_digest_tree_nodes_length_body", FormError::NodesLength),
        ("adv_digest_tree_nodes_few_body", FormError::NodesFew),
        ("adv_digest_tree_two_forms_body", FormError::TwoForms),
        ("adv_digest_tree_no_form_body", FormError::NoForm),
        ("adv_digest_tree_lines_order_body", FormError::LinesOrder),
        (
            "adv_digest_tree_lines_empty_line_body",
            FormError::LinesEmptyLine,
        ),
        ("adv_digest_ids_twice_body", FormError::IdsTwice),
        ("adv_digest_budget_zero_body", FormError::BudgetNotPositive),
    ];
    for (name, rule) in digests {
        let bytes = hex(name);
        // Otherwise well formed: one canonical item, refused for the form rule alone.
        assert!(
            schema::load_canonical(&bytes).is_some(),
            "{name} is canonical"
        );
        assert_eq!(audit::parse_digest(&bytes), Err(rule), "{name}");
        assert_eq!(decode_body(KIND_DIGEST, &bytes), None, "{name}");
        assert_eq!(parse_digest(&bytes), None, "{name}");
    }
    let name = "adv_pull_resp_remainder_negative_body";
    let bytes = hex(name);
    assert!(schema::load_canonical(&bytes).is_some());
    assert_eq!(
        audit::parse_pull_resp(&bytes),
        Err(FormError::RemainderNegative)
    );
    assert_eq!(decode_body(KIND_PULL_RESP, &bytes), None);
    assert_eq!(parse_pull_resp(&bytes), None);
    // Each reason has its own name.
    let names: std::collections::HashSet<&str> = [
        FormError::PathNibble,
        FormError::PathLong,
        FormError::NodesLength,
        FormError::NodesFew,
        FormError::TwoForms,
        FormError::NoForm,
        FormError::LinesOrder,
        FormError::LinesEmptyLine,
        FormError::IdsTwice,
        FormError::BudgetNotPositive,
        FormError::RemainderNegative,
        FormError::Undecodable,
    ]
    .iter()
    .map(|rule| rule.as_str())
    .collect();
    assert_eq!(names.len(), 12);
}

#[test]
fn the_bounds_of_a_body_are_refused_past_them() {
    let node = TreeNode::request(&Path::ROOT, 1);
    let mut body = DigestBody {
        tree: Some(vec![(STREAM.to_owned(), vec![node; 256])]),
        ..DigestBody::default()
    };
    assert!(audit::parse_digest(&body.encode()).is_ok());
    if let Some(tree) = body.tree.as_mut() {
        tree[0].1.push(TreeNode::request(&Path::ROOT, 1));
    }
    assert_eq!(
        audit::parse_digest(&body.encode()),
        Err(FormError::TreeTooMany)
    );
    let ids: Vec<String> = (0..4096).map(|i| format!("entry-{i}")).collect();
    let mut fetch = DigestBody {
        ids: Some(vec![(STREAM.to_owned(), ids)]),
        ..DigestBody::default()
    };
    assert!(audit::parse_digest(&fetch.encode()).is_ok());
    if let Some(ids) = fetch.ids.as_mut() {
        ids[0].1.push("entry-4096".into());
    }
    assert_eq!(
        audit::parse_digest(&fetch.encode()),
        Err(FormError::IdsTooMany)
    );
    // A negative count, a negative budget, an empty child with a fingerprint: each refused.
    let mut negative = Map::new();
    negative.insert("path", Vec::<u8>::new());
    negative.insert("count", -1);
    assert_eq!(
        audit::tree_node_form(&negative),
        Err(FormError::CountNegative)
    );
    let mut budget = Map::new();
    budget.insert("digests", Value::Null);
    budget.insert("budget", -5);
    assert_eq!(
        audit::parse_digest(&cbor::encode(&Value::Map(budget))),
        Err(FormError::BudgetNotPositive)
    );
    let mut nodes = vec![0u8; 384];
    nodes[23] = 40;
    nodes[24] = 1;
    assert_eq!(audit::check_nodes(&nodes), Err(FormError::NodesEmptyChild));
    // A sketch is read and ignored; an unknown field is refused under P1.
    let sketch = DigestBody {
        sketch: Some(vec![(STREAM.to_owned(), vec![1, 2, 3])]),
        ..DigestBody::default()
    };
    assert!(audit::parse_digest(&sketch.encode()).is_ok());
    let mut unknown = Map::new();
    unknown.insert("digests", Value::Null);
    unknown.insert("extra", 1);
    assert_eq!(
        audit::parse_digest(&cbor::encode(&Value::Map(unknown))),
        Err(FormError::Undecodable)
    );
}

#[test]
fn a_body_of_v0_1_34_is_unchanged_byte_for_byte() {
    let mut digests = Map::new();
    digests.insert(STREAM, b"e:a=1\n".to_vec());
    let old = agentspaces_wire::bodies::digest_body(&digests);
    let new = DigestBody {
        digests: Some(vec![(STREAM.to_owned(), b"e:a=1\n".to_vec())]),
        ..DigestBody::default()
    };
    assert_eq!(new.encode(), old);
    assert!(!new.carries_audit());
    assert_eq!(
        audit::answer_root(&mut AuditTrie::new()).form,
        TreeForm::Lines(String::new())
    );
    assert_eq!(AuditTrie::new().node(&Path::ROOT).kind, NodeKind::Empty);
}

// ------------------------------------------------------------------------- probe bodies (I.7)

#[test]
fn the_probe_bodies_with_hashes_and_have_round_trip() {
    for (name, kind) in [
        ("ping_hashes_have_body_cbor", KIND_PING),
        ("ping_hashes_body_cbor", KIND_PING),
        ("ping_have_body_cbor", KIND_PING),
        ("ping_hashes_twenty_streams_body_cbor", KIND_PING),
        ("ack_body_cbor", KIND_ACK),
        ("ack_hashes_have_body_cbor", KIND_ACK),
        ("ack_hashes_body_cbor", KIND_ACK),
        ("ack_have_body_cbor", KIND_ACK),
    ] {
        let bytes = hex(name);
        let body = decode_body(kind, &bytes).unwrap_or_else(|| panic!("{name} decodes"));
        assert_eq!(cbor::encode(&Value::Map(body.clone())), bytes, "{name}");
        assert!(!body.contains_key("root"), "{name} carries no root");
        let nonce = if kind == KIND_PING {
            parse_ping(&bytes)
        } else {
            parse_ack(&bytes)
        };
        assert_eq!(nonce, Some(42), "{name}");
        if let Some(hashes) = body.get("hashes").and_then(Value::as_map) {
            assert!(
                hashes
                    .values()
                    .all(|hash| hash.as_bytes().is_some_and(|h| h.len() == 32))
            );
        }
    }
    assert_eq!(ack_body(42), hex("ack_body_cbor"));
    let twenty = decode_body(KIND_PING, &hex("ping_hashes_twenty_streams_body_cbor")).unwrap();
    assert_eq!(
        twenty.get("hashes").and_then(Value::as_map).map(Map::len),
        Some(20)
    );
    let both = decode_body(KIND_PING, &hex("ping_hashes_have_body_cbor")).unwrap();
    assert!(both.contains_key("hashes") && both.contains_key("have"));
    let framed = body_of_frame("ping_hashes_have_frame_cbor");
    assert_eq!(framed, hex("ping_hashes_have_body_cbor"));
}
